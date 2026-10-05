#include "net/proxy.hpp"

#include "ghostline/audit.hpp"
#include "ghostline/capture.hpp"
#include "ghostline/operator_state.hpp"
#include "ghostline/plugin.hpp"

#include <arpa/inet.h>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <deque>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sstream>
#include <string>
#include <stdexcept>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <unordered_map>
#include <vector>

namespace {

std::uint64_t now_ns() {
    using namespace std::chrono;
    return duration_cast<nanoseconds>(steady_clock::now().time_since_epoch()).count();
}

std::string last_err() {
    return std::strerror(errno);
}

bool has_flag(const FlowContext& flow, FlowFlag flag) {
    for (std::vector<FlowFlag>::const_iterator it = flow.flags.begin(); it != flow.flags.end(); ++it) {
        if (*it == flag) return true;
    }
    return false;
}

void add_flag(FlowContext& flow, FlowFlag flag) {
    if (!has_flag(flow, flag)) flow.flags.push_back(flag);
}

std::string direction_name(Direction direction) {
    return direction == Direction::ClientToServer ? "c2s" : "s2c";
}

struct PeerState {
    int fd = -1;
    bool connecting = false;
    bool read_open = true;
    bool write_open = true;
    bool shutdown_when_drained = false;
    bool plugin_logged = false;
    std::string plugin_name;
    ByteVec pending;
    ByteVec trace_tail;
    bool trace_logged = false;
    std::deque<ByteVec> outq;
};

struct FlowState {
    FlowContext context;
    PeerState client;
    PeerState upstream;
    bool closed = false;
};

struct FdContext {
    std::uint32_t flow_id = 0;
    bool is_client = true;
};

int set_nonblocking(int fd) {
    const int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

void close_quiet(int fd) {
    if (fd >= 0) ::close(fd);
}

int create_listen_socket(const std::string& host, std::uint16_t port) {
    addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    addrinfo* result = nullptr;
    char port_buf[16];
    std::snprintf(port_buf, sizeof(port_buf), "%u", static_cast<unsigned>(port));
    const int rc = getaddrinfo(host.c_str(), port_buf, &hints, &result);
    if (rc != 0) return -1;

    int listen_fd = -1;
    for (addrinfo* p = result; p; p = p->ai_next) {
        const int fd = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;

        const int yes = 1;
        ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

        if (::bind(fd, p->ai_addr, p->ai_addrlen) == 0 && ::listen(fd, 128) == 0) {
            listen_fd = fd;
            break;
        }
        close_quiet(fd);
    }

    freeaddrinfo(result);

    if (listen_fd >= 0 && set_nonblocking(listen_fd) != 0) {
        close_quiet(listen_fd);
        return -1;
    }
    return listen_fd;
}

int connect_upstream(const std::string& host, std::uint16_t port, bool& in_progress) {
    in_progress = false;

    addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    addrinfo* result = nullptr;
    char port_buf[16];
    std::snprintf(port_buf, sizeof(port_buf), "%u", static_cast<unsigned>(port));
    const int rc = getaddrinfo(host.c_str(), port_buf, &hints, &result);
    if (rc != 0) return -1;

    int connected_fd = -1;
    for (addrinfo* p = result; p; p = p->ai_next) {
        const int fd = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;
        if (set_nonblocking(fd) != 0) {
            close_quiet(fd);
            continue;
        }

        const int status = ::connect(fd, p->ai_addr, p->ai_addrlen);
        if (status == 0) {
            connected_fd = fd;
            break;
        }
        if (status < 0 && errno == EINPROGRESS) {
            connected_fd = fd;
            in_progress = true;
            break;
        }
        close_quiet(fd);
    }

    freeaddrinfo(result);
    return connected_fd;
}

std::size_t find_subsequence(const ByteVec& haystack, const ByteVec& needle, std::size_t offset) {
    if (needle.empty()) return std::string::npos;
    if (haystack.size() < needle.size() || offset > haystack.size() - needle.size()) return std::string::npos;
    for (std::size_t i = offset; i + needle.size() <= haystack.size(); ++i) {
        if (std::equal(needle.begin(), needle.end(), haystack.begin() + static_cast<long>(i))) {
            return i;
        }
    }
    return std::string::npos;
}

ByteVec decode_hex_bytes(const std::string& input, const std::string& label) {
    ByteVec output;
    std::string compact;
    for (const char ch : input) {
        if (!std::isspace(static_cast<unsigned char>(ch))) compact.push_back(ch);
    }
    if (compact.empty()) return output;
    if (compact.size() % 2 != 0) {
        throw std::runtime_error(label + " must have an even number of characters");
    }
    for (std::size_t index = 0; index < compact.size(); index += 2) {
        const std::string octet = compact.substr(index, 2);
        std::size_t consumed = 0;
        const unsigned long value = std::stoul(octet, &consumed, 16);
        if (consumed != 2 || value > 255) throw std::runtime_error(label + " contains invalid hexadecimal bytes");
        output.push_back(static_cast<byte>(value));
    }
    return output;
}

bool trace_matches(PeerState& peer, const ByteVec& signature, const ByteVec& bytes) {
    if (signature.empty() || peer.trace_logged) return false;
    ByteVec window;
    window.reserve(peer.trace_tail.size() + bytes.size());
    window.insert(window.end(), peer.trace_tail.begin(), peer.trace_tail.end());
    window.insert(window.end(), bytes.begin(), bytes.end());
    const bool matched = find_subsequence(window, signature, 0) != std::string::npos;
    const std::size_t keep = signature.size() > 1 ? std::min(signature.size() - 1, window.size()) : 0;
    peer.trace_tail.assign(window.end() - static_cast<long>(keep), window.end());
    if (matched) peer.trace_logged = true;
    return matched;
}

void enqueue_bytes(std::deque<ByteVec>& outq, const ByteVec& bytes) {
    if (!bytes.empty()) outq.push_back(bytes);
}

void record_detection(AuditTrail& audit, const FlowState& flow, Direction direction, const ProtocolPlugin& plugin, const ByteVec& sample) {
    AuditEvent event;
    event.event_id = "event-" + std::to_string(flow.context.flow_id) + "-" + direction_name(direction) + "-" + std::to_string(flow.context.event_sequence) + "-detect";
    event.flow_id = flow.context.flow_id;
    event.direction = direction;
    event.plugin_name = plugin.name();
    event.event_type = "plugin-detect";
    event.message = "Matched plugin " + plugin.audit_label();
    event.original_bytes = sample;
    event.flags = flow.context.flags;
    event.workflow_stage = WorkflowStage::Triggered;
    event.sequence = flow.context.event_sequence;
    event.timestamp_ns = now_ns();
    audit.record_event(event);
}

void record_protocol_event(AuditTrail& audit,
                           const FlowContext& flow,
                           Direction direction,
                           const std::string& plugin_name,
                           const std::string& event_type,
                           const std::string& message,
                           const ByteVec& original_bytes,
                           const ByteVec& modified_bytes) {
    AuditEvent event;
    event.event_id = "event-" + std::to_string(flow.flow_id) + "-" + direction_name(direction) + "-" + std::to_string(flow.event_sequence) + "-" + event_type;
    event.flow_id = flow.flow_id;
    event.direction = direction;
    event.plugin_name = plugin_name;
    event.event_type = event_type;
    event.message = message;
    event.workflow_stage = event_type == "framed-packet" ? WorkflowStage::Framed : WorkflowStage::Observe;
    event.original_bytes = original_bytes;
    event.modified_bytes = modified_bytes;
    event.flags = flow.flags;
    event.sequence = flow.event_sequence;
    event.timestamp_ns = now_ns();
    audit.record_event(event);
}

void flush_prefix(ByteVec& pending, std::size_t prefix_len, std::deque<ByteVec>& outq) {
    if (prefix_len == 0) return;
    ByteVec prefix(pending.begin(), pending.begin() + static_cast<long>(prefix_len));
    enqueue_bytes(outq, prefix);
    pending.erase(pending.begin(), pending.begin() + static_cast<long>(prefix_len));
}

bool flush_outq(PeerState& peer) {
    while (!peer.outq.empty()) {
        ByteVec& chunk = peer.outq.front();
        if (chunk.empty()) {
            peer.outq.pop_front();
            continue;
        }

        const ssize_t sent = ::send(peer.fd, chunk.data(), chunk.size(), 0);
        if (sent > 0) {
            chunk.erase(chunk.begin(), chunk.begin() + sent);
            if (chunk.empty()) {
                peer.outq.pop_front();
                continue;
            }
            return true;
        }

        if (sent < 0 && (errno == EWOULDBLOCK || errno == EAGAIN)) {
            return true;
        }
        return false;
    }
    return true;
}

void maybe_shutdown_write(PeerState& peer) {
    if (peer.shutdown_when_drained && peer.outq.empty() && peer.write_open) {
        ::shutdown(peer.fd, SHUT_WR);
        peer.write_open = false;
    }
}

void create_action_item(AuditTrail& audit,
                        const FlowContext& flow,
                        Direction direction,
                        const Candidate& candidate,
                        const CandidateDecision& decision) {
    ActionItem item;
    item.action_id = "action-" + std::to_string(flow.flow_id) + "-" + std::to_string(flow.event_sequence);
    item.trigger_id = candidate.trigger_id;
    item.candidate_id = candidate.candidate_id;
    item.flow_id = flow.flow_id;
    item.plugin_name = candidate.plugin_name;
    item.direction = direction;
    item.title = decision.action_title;
    item.detail = decision.action_detail;
    item.validation_label = decision.validation_label;
    item.fallback_reason = decision.fallback_reason;
    item.original_hex = bytes_to_hex_string(candidate.original_bytes);
    item.modified_hex = bytes_to_hex_string(candidate.modified_bytes);
    item.workflow_stage = WorkflowStage::ActionCreated;
    item.created_at_ns = now_ns();
    audit.save_action_item(item);
}

std::string next_trigger_id(FlowContext& flow, Direction direction, const std::string& plugin_name) {
    ++flow.trigger_sequence;
    return "trigger-" + std::to_string(flow.flow_id) + "-" + direction_name(direction) + "-" + plugin_name + "-" + std::to_string(flow.trigger_sequence);
}

std::string next_candidate_id(FlowContext& flow, Direction direction, const std::string& plugin_name) {
    ++flow.candidate_sequence;
    return "candidate-" + std::to_string(flow.flow_id) + "-" + direction_name(direction) + "-" + plugin_name + "-" + std::to_string(flow.candidate_sequence);
}

void set_observe_only(FlowState& flow, Direction direction, AuditTrail& audit, const std::string& reason) {
    if (!flow.context.observe_only) {
        flow.context.observe_only = true;
        flow.context.observe_reason = reason;
        add_flag(flow.context, FlowFlag::ObserveOnly);
        audit.record_observe_transition(flow.context, direction, reason);
    }
}

void process_pending(FlowState& flow,
                     PeerState& src,
                     PeerState& dst,
                     Direction direction,
                     const ProxyConfig& cfg,
                     const PluginRegistry& registry,
                     AuditTrail& audit) {
    while (!src.pending.empty()) {
        ++flow.context.event_sequence;
        if (flow.context.observe_only) {
            enqueue_bytes(dst.outq, src.pending);
            src.pending.clear();
            return;
        }

        const ProtocolPlugin* plugin = registry.match(flow.context, direction, cfg.upstream_port, src.pending);
        if (plugin == nullptr) {
            enqueue_bytes(dst.outq, src.pending);
            src.pending.clear();
            return;
        }

        flow.context.active_plugin = plugin->name();
        if (!src.plugin_logged || src.plugin_name != plugin->name()) {
            src.plugin_logged = true;
            src.plugin_name = plugin->name();
            record_detection(audit, flow, direction, *plugin, src.pending);
        }

        if (plugin->uses_protocol_framing()) {
            FramingResult framed = plugin->frame(flow.context, direction, src.pending);
            if (framed.disposition == FramingDisposition::NeedMoreBytes) {
                if (src.pending.size() > cfg.max_plugin_buffer_bytes) {
                    set_observe_only(flow, direction, audit, "plugin buffer ceiling reached before framing completed");
                    record_protocol_event(audit,
                                          flow.context,
                                          direction,
                                          plugin->name(),
                                          "framing-buffer-ceiling",
                                          "released original bytes after plugin buffering ceiling was exceeded",
                                          src.pending,
                                          ByteVec());
                    enqueue_bytes(dst.outq, src.pending);
                    src.pending.clear();
                }
                return;
            }

            if (framed.disposition == FramingDisposition::FramingFailed) {
                set_observe_only(flow, direction, audit, framed.detail.empty() ? "protocol framing failed" : framed.detail);
                record_protocol_event(audit,
                                      flow.context,
                                      direction,
                                      plugin->name(),
                                      "framing-failed",
                                      framed.detail,
                                      src.pending,
                                      ByteVec());
                enqueue_bytes(dst.outq, src.pending);
                src.pending.clear();
                return;
            }

            if (framed.disposition == FramingDisposition::PassThrough) {
                record_protocol_event(audit,
                                      flow.context,
                                      direction,
                                      plugin->name(),
                                      "framing-pass-through",
                                      framed.detail,
                                      src.pending,
                                      ByteVec());
                enqueue_bytes(dst.outq, src.pending);
                src.pending.clear();
                return;
            }

            if (framed.disposition == FramingDisposition::FramedPacket) {
                flow.context.last_packet_type = framed.packet_type;
                record_protocol_event(audit,
                                      flow.context,
                                      direction,
                                      plugin->name(),
                                      "framed-packet",
                                      framed.detail + " packet=" + framed.packet_type,
                                      framed.frame_bytes,
                                      ByteVec());

                Candidate candidate = plugin->build_candidate(flow.context, direction, framed.frame_bytes, &framed);
                candidate.trigger_id = next_trigger_id(flow.context, direction, plugin->name());
                candidate.candidate_id = next_candidate_id(flow.context, direction, plugin->name());
                candidate.workflow_stage = WorkflowStage::CandidateBuilt;
                CandidateDecision decision = plugin->decide(flow.context, direction, candidate);
                decision.trigger_id = candidate.trigger_id;
                decision.candidate_id = candidate.candidate_id;
                decision.workflow_stage = WorkflowStage::CandidateReviewed;

                if (candidate.allow_size_mutated) add_flag(flow.context, FlowFlag::AllowSizeMutated);
                if (candidate.pid_drift_risk) add_flag(flow.context, FlowFlag::PidDriftRisk);
                if (decision.observe_only) {
                    set_observe_only(flow, direction, audit, decision.fallback_reason);
                }

                audit.record_candidate(flow.context, direction, candidate, decision);
                record_protocol_event(audit,
                                      flow.context,
                                      direction,
                                      plugin->name(),
                                      decision.release == CandidateRelease::ReleaseModified ? "candidate-release-modified" : "candidate-release-original",
                                      decision.validation_detail.empty() ? decision.validation_label : decision.validation_detail,
                                      candidate.original_bytes,
                                      decision.release == CandidateRelease::ReleaseModified ? candidate.modified_bytes : ByteVec());
                if (decision.create_action_item) {
                    create_action_item(audit, flow.context, direction, candidate, decision);
                }

                enqueue_bytes(dst.outq,
                              decision.release == CandidateRelease::ReleaseModified
                                  ? candidate.modified_bytes
                                  : candidate.original_bytes);
                src.pending.erase(src.pending.begin(), src.pending.begin() + static_cast<long>(framed.consumed_bytes));
                continue;
            }
        }

        WindowRule rule;
        if (!plugin->configure_window(flow.context, direction, rule) || rule.start_marker.empty() || rule.end_marker.empty()) {
            enqueue_bytes(dst.outq, src.pending);
            src.pending.clear();
            return;
        }

        const std::size_t start_pos = find_subsequence(src.pending, rule.start_marker, 0);
        if (start_pos == std::string::npos) {
            const std::size_t keep = rule.start_marker.empty() ? 0 : rule.start_marker.size() - 1;
            if (src.pending.size() <= keep) return;
            flush_prefix(src.pending, src.pending.size() - keep, dst.outq);
            return;
        }

        if (start_pos > 0) {
            flush_prefix(src.pending, start_pos, dst.outq);
            continue;
        }

        const std::size_t end_search_offset = rule.start_marker.size();
        const std::size_t end_pos = find_subsequence(src.pending, rule.end_marker, end_search_offset);
        if (end_pos == std::string::npos) {
            if (src.pending.size() > cfg.max_inspect_bytes) {
                enqueue_bytes(dst.outq, src.pending);
                src.pending.clear();
            }
            return;
        }

        const std::size_t window_len = end_pos + rule.end_marker.size();
        ByteVec window(src.pending.begin(), src.pending.begin() + static_cast<long>(window_len));
        Candidate candidate = plugin->build_candidate(flow.context, direction, window);
        candidate.trigger_id = next_trigger_id(flow.context, direction, plugin->name());
        candidate.candidate_id = next_candidate_id(flow.context, direction, plugin->name());
        candidate.workflow_stage = WorkflowStage::CandidateBuilt;
        CandidateDecision decision = plugin->decide(flow.context, direction, candidate);
        decision.trigger_id = candidate.trigger_id;
        decision.candidate_id = candidate.candidate_id;
        decision.workflow_stage = WorkflowStage::CandidateReviewed;

        if (candidate.allow_size_mutated) add_flag(flow.context, FlowFlag::AllowSizeMutated);
        if (candidate.pid_drift_risk) add_flag(flow.context, FlowFlag::PidDriftRisk);
        if (decision.observe_only) {
            set_observe_only(flow, direction, audit, decision.fallback_reason);
        }

        audit.record_candidate(flow.context, direction, candidate, decision);
        if (decision.create_action_item) {
            create_action_item(audit, flow.context, direction, candidate, decision);
        }

        enqueue_bytes(dst.outq,
                      decision.release == CandidateRelease::ReleaseModified
                          ? candidate.modified_bytes
                          : candidate.original_bytes);

        src.pending.erase(src.pending.begin(), src.pending.begin() + static_cast<long>(window_len));
    }
}

void flush_pending_on_read_close(FlowState& flow,
                                 PeerState& src,
                                 PeerState& dst,
                                 Direction direction,
                                 AuditTrail& audit) {
    if (src.pending.empty()) return;

    ++flow.context.event_sequence;
    record_protocol_event(audit,
                          flow.context,
                          direction,
                          flow.context.active_plugin.empty() ? "transport-core" : flow.context.active_plugin,
                          "read-close-flush-original",
                          "released pending original bytes on read-close",
                          src.pending,
                          ByteVec());
    enqueue_bytes(dst.outq, src.pending);
    src.pending.clear();
}

void close_flow(std::unordered_map<std::uint32_t, FlowState>& flows,
                std::unordered_map<int, FdContext>& fd_contexts,
                std::uint32_t flow_id) {
    std::unordered_map<std::uint32_t, FlowState>::iterator it = flows.find(flow_id);
    if (it == flows.end()) return;

    close_quiet(it->second.client.fd);
    close_quiet(it->second.upstream.fd);
    fd_contexts.erase(it->second.client.fd);
    fd_contexts.erase(it->second.upstream.fd);
    flows.erase(it);
}

bool flow_finished(const FlowState& flow) {
    const bool client_done = !flow.client.read_open && flow.client.outq.empty() && !flow.client.write_open;
    const bool upstream_done = !flow.upstream.read_open && flow.upstream.outq.empty() && !flow.upstream.write_open;
    return client_done && upstream_done;
}

MutationConfig make_mutation_config(const ProxyConfig& cfg) {
    MutationConfig config;

    config.start_marker = decode_hex_bytes(cfg.start_marker_hex, "marker hex");
    config.end_marker = decode_hex_bytes(cfg.end_marker_hex, "marker hex");
    config.replacement_text = cfg.replacement_text;
    config.raw_find_text = cfg.raw_find_text;
    config.allow_size_mutation = cfg.allow_size_mutation;
    config.rewrite_u32_prefix = cfg.rewrite_u32_prefix;
    config.raw_live_mode = cfg.raw_live_mode;
    config.raw_chunk_bytes = cfg.raw_chunk_bytes;
    config.mutate_client_to_server = cfg.mutate_client_to_server;
    config.mutate_server_to_client = cfg.mutate_server_to_client;
    config.raw_review_threshold_bytes = cfg.raw_review_threshold_bytes;
    config.mqtt_review_threshold_bytes = cfg.mqtt_review_threshold_bytes;
    config.byte_window_review_threshold_bytes = cfg.byte_window_review_threshold_bytes;
    return config;
}

} // namespace

int run_transport_core(const ProxyConfig& cfg) {
    if (!cfg.trace_text.empty() && !cfg.trace_hex.empty()) {
        std::fprintf(stderr, "Configure one trace signature: --trace-text or --trace-hex\n");
        return 2;
    }
    ByteVec trace_signature(cfg.trace_text.begin(), cfg.trace_text.end());
    try {
        if (!cfg.trace_hex.empty()) trace_signature = decode_hex_bytes(cfg.trace_hex, "trace hex");
    } catch (const std::exception& error) {
        std::fprintf(stderr, "Invalid trace signature: %s\n", error.what());
        return 2;
    }
    if (cfg.cut_on_trace && trace_signature.empty()) {
        std::fprintf(stderr, "--cut-on-trace requires --trace-text or --trace-hex\n");
        return 2;
    }

    const int listen_fd = create_listen_socket(cfg.listen_host, cfg.listen_port);
    if (listen_fd < 0) {
        std::fprintf(stderr, "Failed to create listen socket on %s:%u\n", cfg.listen_host.c_str(), static_cast<unsigned>(cfg.listen_port));
        return 1;
    }

    PluginRegistry registry(make_mutation_config(cfg));
    AuditTrail audit(cfg.audit_log_path,
                     cfg.action_log_path,
                     cfg.audit_json_path,
                     cfg.action_json_path,
                     cfg.review_queue_dir);

    CaptureConfig capture_config;
    capture_config.stream_path = cfg.capture_path;
    capture_config.pcap_path = cfg.capture_pcap_path;
    capture_config.max_bytes = cfg.capture_max_bytes;
    capture_config.snaplen = cfg.capture_snaplen;
    capture_config.print_hex = cfg.capture_hex;
    capture_config.expect_mqtt_connack = cfg.expect_mqtt_connack;
    MicroCapture capture(capture_config);

    std::unordered_map<std::uint32_t, FlowState> flows;
    std::unordered_map<int, FdContext> fd_contexts;
    std::uint32_t next_flow_id = 1;

    std::vector<byte> read_buffer(cfg.max_chunk);

    while (true) {
        std::vector<pollfd> pollfds;
        pollfds.reserve(1 + flows.size() * 2);
        pollfd listen_pfd;
        listen_pfd.fd = listen_fd;
        listen_pfd.events = POLLIN;
        listen_pfd.revents = 0;
        pollfds.push_back(listen_pfd);

        for (std::unordered_map<std::uint32_t, FlowState>::iterator it = flows.begin(); it != flows.end(); ++it) {
            FlowState& flow = it->second;

            pollfd client_pfd;
            client_pfd.fd = flow.client.fd;
            client_pfd.events = 0;
            if (flow.client.read_open) client_pfd.events |= POLLIN;
            if (flow.client.connecting || !flow.client.outq.empty()) client_pfd.events |= POLLOUT;
            client_pfd.revents = 0;
            pollfds.push_back(client_pfd);

            pollfd upstream_pfd;
            upstream_pfd.fd = flow.upstream.fd;
            upstream_pfd.events = 0;
            if (flow.upstream.read_open && !flow.upstream.connecting) upstream_pfd.events |= POLLIN;
            if (flow.upstream.connecting || !flow.upstream.outq.empty()) upstream_pfd.events |= POLLOUT;
            upstream_pfd.revents = 0;
            pollfds.push_back(upstream_pfd);
        }

        const int ready = ::poll(pollfds.data(), pollfds.size(), -1);
        if (ready < 0) {
            if (errno == EINTR) continue;
            std::fprintf(stderr, "poll failed: %s\n", last_err().c_str());
            break;
        }

        for (std::size_t i = 0; i < pollfds.size(); ++i) {
            const pollfd& pfd = pollfds[i];
            if (pfd.revents == 0) continue;

            if (pfd.fd == listen_fd) {
                while (true) {
                    sockaddr_storage address;
                    socklen_t address_len = sizeof(address);
                    const int client_fd = ::accept(listen_fd, reinterpret_cast<sockaddr*>(&address), &address_len);
                    if (client_fd < 0) {
                        if (errno == EWOULDBLOCK || errno == EAGAIN) break;
                        std::fprintf(stderr, "accept failed: %s\n", last_err().c_str());
                        break;
                    }

                    if (set_nonblocking(client_fd) != 0) {
                        close_quiet(client_fd);
                        continue;
                    }

                    bool connecting = false;
                    const int upstream_fd = connect_upstream(cfg.upstream_host, cfg.upstream_port, connecting);
                    if (upstream_fd < 0) {
                        close_quiet(client_fd);
                        continue;
                    }

                    FlowState flow;
                    flow.context.flow_id = next_flow_id++;
                    flow.context.preferred_plugin = cfg.protocol_hint;
                    flow.context.observe_only = cfg.observe_only;
                    if (cfg.observe_only) {
                        flow.context.observe_reason = "operator forced observe-only mode";
                        flow.context.flags.push_back(FlowFlag::ObserveOnly);
                    }
                    flow.client.fd = client_fd;
                    flow.upstream.fd = upstream_fd;
                    flow.upstream.connecting = connecting;

                    fd_contexts[client_fd] = FdContext{flow.context.flow_id, true};
                    fd_contexts[upstream_fd] = FdContext{flow.context.flow_id, false};
                    flows[flow.context.flow_id] = flow;
                }
                continue;
            }

            std::unordered_map<int, FdContext>::iterator ctx_it = fd_contexts.find(pfd.fd);
            if (ctx_it == fd_contexts.end()) continue;

            std::unordered_map<std::uint32_t, FlowState>::iterator flow_it = flows.find(ctx_it->second.flow_id);
            if (flow_it == flows.end()) continue;

            FlowState& flow = flow_it->second;
            const std::uint32_t active_flow_id = flow.context.flow_id;
            PeerState& src = ctx_it->second.is_client ? flow.client : flow.upstream;
            PeerState& dst = ctx_it->second.is_client ? flow.upstream : flow.client;
            const Direction direction = ctx_it->second.is_client ? Direction::ClientToServer : Direction::ServerToClient;

            if (pfd.revents & (POLLERR | POLLNVAL)) {
                close_flow(flows, fd_contexts, flow.context.flow_id);
                continue;
            }

            if ((pfd.revents & POLLOUT) && src.connecting) {
                int so_error = 0;
                socklen_t len = sizeof(so_error);
                if (getsockopt(src.fd, SOL_SOCKET, SO_ERROR, &so_error, &len) != 0 || so_error != 0) {
                    close_flow(flows, fd_contexts, flow.context.flow_id);
                    continue;
                }
                src.connecting = false;
            }

            if ((pfd.revents & POLLIN) && src.read_open) {
                bool cut_flow = false;
                while (true) {
                    const ssize_t received = ::recv(src.fd, read_buffer.data(), read_buffer.size(), 0);
                    if (received > 0) {
                        const ByteVec captured(
                            read_buffer.begin(), read_buffer.begin() + received);
                        capture.record(flow.context.flow_id, direction, "tcp",
                                       cfg.protocol_hint, captured);
                        const bool trace_direction_enabled = direction == Direction::ClientToServer
                            ? cfg.trace_client_to_server : cfg.trace_server_to_client;
                        if (trace_direction_enabled && trace_matches(src, trace_signature, captured)) {
                            ++flow.context.event_sequence;
                            record_protocol_event(audit,
                                                  flow.context,
                                                  direction,
                                                  "trace-guard",
                                                  cfg.cut_on_trace ? "containment-stream-cut" : "trace-match",
                                                  cfg.cut_on_trace
                                                      ? "classified byte trace matched; both flow directions closed"
                                                      : "classified byte trace matched; observation continued",
                                                  captured,
                                                  ByteVec());
                            if (cfg.cut_on_trace) {
                                close_flow(flows, fd_contexts, active_flow_id);
                                cut_flow = true;
                                break;
                            }
                        }
                        src.pending.insert(src.pending.end(), read_buffer.begin(), read_buffer.begin() + received);
                        process_pending(flow, src, dst, direction, cfg, registry, audit);
                        continue;
                    }

                    if (received == 0) {
                        flush_pending_on_read_close(flow, src, dst, direction, audit);
                        src.read_open = false;
                        dst.shutdown_when_drained = true;
                        break;
                    }

                    if (errno == EWOULDBLOCK || errno == EAGAIN) break;
                    close_flow(flows, fd_contexts, flow.context.flow_id);
                    break;
                }
                if (cut_flow) continue;
            }

            if ((pfd.revents & POLLOUT) && !src.outq.empty()) {
                if (!flush_outq(src)) {
                    close_flow(flows, fd_contexts, flow.context.flow_id);
                    continue;
                }
            }

            maybe_shutdown_write(src);
        }

        std::vector<std::uint32_t> finished;
        for (std::unordered_map<std::uint32_t, FlowState>::iterator it = flows.begin(); it != flows.end(); ++it) {
            maybe_shutdown_write(it->second.client);
            maybe_shutdown_write(it->second.upstream);
            if (flow_finished(it->second)) finished.push_back(it->first);
        }
        for (std::size_t i = 0; i < finished.size(); ++i) {
            close_flow(flows, fd_contexts, finished[i]);
        }
    }

    close_quiet(listen_fd);
    return 1;
}
