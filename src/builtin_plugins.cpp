#include "ghostline/plugin.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <memory>
#include <sstream>

namespace {

bool starts_with(const ByteVec& bytes, const char* literal) {
    const std::size_t size = std::strlen(literal);
    if (bytes.size() < size) return false;
    for (std::size_t i = 0; i < size; ++i) {
        if (bytes[i] != static_cast<byte>(literal[i])) return false;
    }
    return true;
}

bool is_printable_payload(const ByteVec& payload) {
    for (ByteVec::const_iterator it = payload.begin(); it != payload.end(); ++it) {
        if (*it == '\n' || *it == '\r' || *it == '\t') continue;
        if (!std::isprint(static_cast<unsigned char>(*it))) return false;
    }
    return true;
}

std::string mutation_note(const Candidate& candidate) {
    std::ostringstream out;
    out << "trigger=" << candidate.trigger_label
        << " packet=" << candidate.packet_type
        << " size-delta=" << candidate.size_delta;
    return out.str();
}

bool direction_is_mutable(const MutationConfig& config, Direction direction) {
    return direction == Direction::ClientToServer ? config.mutate_client_to_server : config.mutate_server_to_client;
}

std::size_t find_bytes(const ByteVec& haystack, const ByteVec& needle, std::size_t offset) {
    if (needle.empty() || haystack.size() < needle.size() || offset > haystack.size() - needle.size()) return std::string::npos;
    for (std::size_t i = offset; i + needle.size() <= haystack.size(); ++i) {
        if (std::equal(needle.begin(), needle.end(), haystack.begin() + static_cast<long>(i))) return i;
    }
    return std::string::npos;
}

ByteVec bytes_from_text(const std::string& text) {
    return ByteVec(text.begin(), text.end());
}

ByteVec replace_all_bytes(const ByteVec& input, const ByteVec& find_bytes_value, const ByteVec& replace_bytes_value, bool& replaced_any) {
    if (find_bytes_value.empty()) {
        replaced_any = !input.empty() || !replace_bytes_value.empty();
        return replace_bytes_value;
    }

    replaced_any = false;
    ByteVec output;
    std::size_t offset = 0;
    while (offset < input.size()) {
        const std::size_t found = find_bytes(input, find_bytes_value, offset);
        if (found == std::string::npos) {
            output.insert(output.end(), input.begin() + static_cast<long>(offset), input.end());
            break;
        }

        replaced_any = true;
        output.insert(output.end(), input.begin() + static_cast<long>(offset), input.begin() + static_cast<long>(found));
        output.insert(output.end(), replace_bytes_value.begin(), replace_bytes_value.end());
        offset = found + find_bytes_value.size();
    }
    return output;
}

class RawLivePlugin : public ProtocolPlugin {
public:
    explicit RawLivePlugin(const MutationConfig& config) : config_(config) {}

    std::string name() const override { return "raw-live"; }

    bool matches(const FlowContext&, Direction, std::uint16_t, const ByteVec&) const override {
        return config_.raw_live_mode;
    }

    bool uses_protocol_framing() const override { return true; }

    FramingResult frame(const FlowContext&, Direction, const ByteVec& buffer) const override {
        FramingResult result;
        if (buffer.empty()) return result;

        if (!config_.end_marker.empty()) {
            const std::size_t end = find_bytes(buffer, config_.end_marker, 0);
            if (end == std::string::npos) {
                result.disposition = FramingDisposition::NeedMoreBytes;
                result.detail = "waiting for raw end marker";
                return result;
            }
            result.disposition = FramingDisposition::FramedPacket;
            result.consumed_bytes = end + config_.end_marker.size();
            result.frame_bytes.assign(buffer.begin(), buffer.begin() + static_cast<long>(result.consumed_bytes));
            result.packet_type = "RAW-WINDOW";
            result.detail = "raw live framed by end marker";
            result.candidate_mutation_allowed = true;
            return result;
        }

        if (buffer.size() < config_.raw_chunk_bytes) {
            result.disposition = FramingDisposition::NeedMoreBytes;
            result.detail = "waiting for raw chunk bytes";
            return result;
        }

        result.disposition = FramingDisposition::FramedPacket;
        result.consumed_bytes = config_.raw_chunk_bytes;
        result.frame_bytes.assign(buffer.begin(), buffer.begin() + static_cast<long>(config_.raw_chunk_bytes));
        result.packet_type = "RAW-CHUNK";
        result.detail = "raw live fixed chunk";
        result.candidate_mutation_allowed = true;
        return result;
    }

    bool configure_window(const FlowContext&, Direction, WindowRule&) const override {
        return false;
    }

    Candidate build_candidate(const FlowContext&, Direction, const ByteVec& window, const FramingResult* framed) const override {
        Candidate candidate;
        candidate.plugin_name = name();
        candidate.trigger_label = "raw-live";
        candidate.packet_type = framed != nullptr ? framed->packet_type : "RAW";
        candidate.protocol_note = framed != nullptr ? framed->detail : "raw live candidate";
        candidate.original_bytes = window;
        candidate.modified_bytes = window;
        candidate.payload_offset = 0;
        candidate.payload_size = window.size();

        bool replaced_any = false;
        const ByteVec find_value = bytes_from_text(config_.raw_find_text);
        const ByteVec replacement = bytes_from_text(config_.replacement_text);
        candidate.modified_bytes = replace_all_bytes(window, find_value, replacement, replaced_any);
        candidate.size_delta = static_cast<long long>(candidate.modified_bytes.size()) - static_cast<long long>(candidate.original_bytes.size());
        candidate.allow_size_mutated = candidate.size_delta == 0 || config_.allow_size_mutation;
        candidate.review_label = candidate.size_delta == 0 ? "raw-live-inline" : "raw-live-size-change";
        candidate.note = mutation_note(candidate);
        if (!replaced_any) {
            candidate.modified_bytes = candidate.original_bytes;
            candidate.note = "raw live candidate produced no match";
        }
        return candidate;
    }

    CandidateDecision decide(const FlowContext&, Direction direction, Candidate& candidate) const override {
        CandidateDecision decision;
        if (!direction_is_mutable(config_, direction)) {
            decision.release = CandidateRelease::ReleaseOriginal;
            decision.outcome = ValidationOutcome::ValidationFallbackOriginal;
            decision.validation_label = "raw-live-direction-filter";
            decision.validation_detail = "raw live mutation disabled for this direction";
            decision.fallback_reason = "raw live direction is observe-only";
            return decision;
        }

        if (candidate.modified_bytes == candidate.original_bytes) {
            decision.release = CandidateRelease::ReleaseOriginal;
            decision.outcome = ValidationOutcome::ValidationFallbackOriginal;
            decision.validation_label = "raw-live-no-match";
            decision.validation_detail = "raw live mutation did not find a matching region";
            decision.fallback_reason = "raw live candidate produced no mutation";
            return decision;
        }

        decision.review_required = candidate.size_delta != 0;
        if (candidate.size_delta != 0 && !config_.allow_size_mutation) {
            candidate.pid_drift_risk = true;
            decision.release = CandidateRelease::ReleaseOriginal;
            decision.outcome = ValidationOutcome::ValidationObserveOnly;
            decision.observe_only = true;
            decision.create_action_item = true;
            decision.validation_label = "raw-live-size-blocked";
            decision.validation_detail = "operator disabled raw live size mutations";
            decision.fallback_reason = "raw live size mutation not allowed";
            decision.review_reason = "size-changing raw live mutation requires review";
            decision.action_title = "Review raw live mutation";
            decision.action_detail = "Ghostline preserved original raw bytes because the live mutation changed size and was not allowed.";
            return decision;
        }

        candidate.valid = true;
        decision.release = CandidateRelease::ReleaseModified;
        decision.outcome = ValidationOutcome::ValidationPassed;
        decision.validation_label = candidate.size_delta == 0 ? "raw-live-validated" : "raw-live-size-mutated";
        decision.validation_detail = candidate.size_delta == 0
            ? "raw live mutation validated inline"
            : "raw live mutation validated with a chunk size change";
        if (config_.raw_review_threshold_bytes > 0 && candidate.payload_size >= config_.raw_review_threshold_bytes) {
            decision.review_required = true;
            decision.create_action_item = true;
            decision.review_reason = "raw live mutation exceeded configured review threshold";
            decision.action_title = "Review raw live mutation";
            decision.action_detail = "Raw live mutation released successfully but crossed the configured review threshold.";
        } else {
            decision.review_reason = decision.review_required ? "raw live size mutation should be reviewed in audit trail" : "";
        }
        return decision;
    }

    std::string audit_label() const override { return "raw-live"; }

private:
    MutationConfig config_;
};

class ByteWindowPlugin : public ProtocolPlugin {
public:
    explicit ByteWindowPlugin(const MutationConfig& config) : config_(config) {}

    std::string name() const override { return "byte-window"; }

    bool matches(const FlowContext&, Direction, std::uint16_t, const ByteVec&) const override {
        return !config_.start_marker.empty() && !config_.end_marker.empty();
    }

    bool configure_window(const FlowContext&, Direction, WindowRule& rule) const override {
        rule.start_marker = config_.start_marker;
        rule.end_marker = config_.end_marker;
        rule.rewrite_u32_prefix = config_.rewrite_u32_prefix;
        return true;
    }

    Candidate build_candidate(const FlowContext&, Direction, const ByteVec& window, const FramingResult*) const override {
        Candidate candidate;
        candidate.plugin_name = name();
        candidate.trigger_label = "byte-pattern";
        candidate.packet_type = "byte-window";
        candidate.original_bytes = window;
        candidate.modified_bytes = window;
        candidate.header_size = config_.start_marker.size();
        candidate.footer_size = config_.end_marker.size();

        if (window.size() >= candidate.header_size + candidate.footer_size) {
            ByteVec replacement(config_.replacement_text.begin(), config_.replacement_text.end());
            candidate.modified_bytes.assign(window.begin(), window.begin() + static_cast<long>(candidate.header_size));
            candidate.modified_bytes.insert(candidate.modified_bytes.end(), replacement.begin(), replacement.end());
            candidate.modified_bytes.insert(candidate.modified_bytes.end(),
                                            window.end() - static_cast<long>(candidate.footer_size),
                                            window.end());
            candidate.payload_offset = candidate.header_size;
            candidate.payload_size = candidate.original_bytes.size() - candidate.header_size - candidate.footer_size;
            candidate.size_delta = static_cast<long long>(candidate.modified_bytes.size()) - static_cast<long long>(candidate.original_bytes.size());

            if (config_.rewrite_u32_prefix && candidate.modified_bytes.size() >= 4 + candidate.footer_size) {
                const std::uint32_t body_size = static_cast<std::uint32_t>(candidate.modified_bytes.size() - 4 - candidate.footer_size);
                candidate.modified_bytes[0] = static_cast<byte>((body_size >> 24) & 0xff);
                candidate.modified_bytes[1] = static_cast<byte>((body_size >> 16) & 0xff);
                candidate.modified_bytes[2] = static_cast<byte>((body_size >> 8) & 0xff);
                candidate.modified_bytes[3] = static_cast<byte>(body_size & 0xff);
                candidate.allow_size_mutated = true;
            }
        }

        candidate.note = mutation_note(candidate);
        return candidate;
    }

    CandidateDecision decide(const FlowContext&, Direction direction, Candidate& candidate) const override {
        CandidateDecision decision;
        if (!direction_is_mutable(config_, direction)) {
            decision.release = CandidateRelease::ReleaseOriginal;
            decision.outcome = ValidationOutcome::ValidationFallbackOriginal;
            decision.validation_label = "byte-window-direction-filter";
            decision.validation_detail = "byte-window mutation disabled for this direction";
            decision.fallback_reason = "byte-window direction is observe-only";
            return decision;
        }

        if (candidate.modified_bytes.empty() || candidate.modified_bytes == candidate.original_bytes) {
            decision.release = CandidateRelease::ReleaseOriginal;
            decision.outcome = ValidationOutcome::ValidationFallbackOriginal;
            decision.validation_label = "no-op";
            decision.validation_detail = "byte-window replacement produced no safe delta";
            decision.fallback_reason = "replacement produced no safe delta";
            return decision;
        }

        if (candidate.size_delta != 0 && !config_.allow_size_mutation) {
            candidate.pid_drift_risk = true;
            decision.release = CandidateRelease::ReleaseOriginal;
            decision.outcome = ValidationOutcome::ValidationObserveOnly;
            decision.observe_only = true;
            decision.create_action_item = true;
            decision.validation_label = "size-mutation-blocked";
            decision.validation_detail = "operator disabled size mutations";
            decision.fallback_reason = "size mutation not allowed";
            decision.action_title = "Begin framing mutation workflow";
            decision.action_detail = "Ghostline preserved original bytes because the candidate changed size without allow-size-mutation enabled.";
            return decision;
        }

        if (candidate.size_delta != 0 && !candidate.allow_size_mutated) {
            candidate.pid_drift_risk = true;
            decision.release = CandidateRelease::ReleaseOriginal;
            decision.outcome = ValidationOutcome::ValidationObserveOnly;
            decision.observe_only = true;
            decision.create_action_item = true;
            decision.validation_label = "pid-drift-risk";
            decision.validation_detail = "size-changing byte-window mutation could not prove a dependent header rewrite";
            decision.fallback_reason = "size mutation could not be proven safe";
            decision.action_title = "Begin live mutation workflow";
            decision.action_detail = "Locate header byte size, compute delta, and mutate dependent fields before retrying.";
            return decision;
        }

        candidate.valid = true;
        decision.release = CandidateRelease::ReleaseModified;
        decision.outcome = ValidationOutcome::ValidationPassed;
        decision.validation_label = candidate.allow_size_mutated ? "allow-size-mutated" : "validated";
        decision.validation_detail = "byte-window candidate validated";
        if (config_.byte_window_review_threshold_bytes > 0 && candidate.payload_size >= config_.byte_window_review_threshold_bytes) {
            decision.review_required = true;
            decision.create_action_item = true;
            decision.review_reason = "byte-window mutation exceeded configured review threshold";
            decision.action_title = "Review byte-window mutation";
            decision.action_detail = "Byte-window mutation released successfully but crossed the configured review threshold.";
        }
        return decision;
    }

    std::string audit_label() const override { return "byte-window-candidate"; }

private:
    MutationConfig config_;
};

class ObservationPlugin : public ProtocolPlugin {
public:
    ObservationPlugin(std::string plugin_name, std::uint16_t port_hint, std::string signature, std::string label, std::string detail)
        : plugin_name_(plugin_name), port_hint_(port_hint), signature_(signature), label_(label), detail_(detail) {}

    std::string name() const override { return plugin_name_; }

    bool matches(const FlowContext&, Direction, std::uint16_t upstream_port, const ByteVec& buffer) const override {
        return upstream_port == port_hint_ || (!signature_.empty() && starts_with(buffer, signature_.c_str()));
    }

    bool configure_window(const FlowContext&, Direction, WindowRule&) const override {
        return false;
    }

    Candidate build_candidate(const FlowContext&, Direction, const ByteVec& window, const FramingResult*) const override {
        Candidate candidate;
        candidate.plugin_name = plugin_name_;
        candidate.trigger_label = label_;
        candidate.packet_type = label_;
        candidate.original_bytes = window;
        candidate.modified_bytes = window;
        candidate.protocol_note = detail_;
        candidate.note = detail_;
        return candidate;
    }

    CandidateDecision decide(const FlowContext&, Direction, Candidate&) const override {
        CandidateDecision decision;
        decision.release = CandidateRelease::ReleaseOriginal;
        decision.outcome = ValidationOutcome::ValidationFallbackOriginal;
        decision.validation_label = "observe-only";
        decision.validation_detail = "protocol plugin provided detection and audit only";
        decision.fallback_reason = "protocol plugin has detection and audit only in Phase 1";
        return decision;
    }

    std::string audit_label() const override { return label_; }

private:
    std::string plugin_name_;
    std::uint16_t port_hint_;
    std::string signature_;
    std::string label_;
    std::string detail_;
};

enum class ObservationFraming {
    Amqp091,
    Amqp10,
    Kafka,
};

std::uint32_t read_u32_be(const ByteVec& bytes, const std::size_t offset) {
    return (static_cast<std::uint32_t>(bytes[offset]) << 24U)
        | (static_cast<std::uint32_t>(bytes[offset + 1]) << 16U)
        | (static_cast<std::uint32_t>(bytes[offset + 2]) << 8U)
        | static_cast<std::uint32_t>(bytes[offset + 3]);
}

std::uint16_t read_u16_be(const ByteVec& bytes, const std::size_t offset) {
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(bytes[offset]) << 8U)
        | static_cast<std::uint16_t>(bytes[offset + 1]));
}

class FramedObservationPlugin : public ProtocolPlugin {
public:
    FramedObservationPlugin(std::string plugin_name,
                            const std::uint16_t port_hint,
                            std::string signature,
                            std::string label,
                            std::string detail,
                            const ObservationFraming framing)
        : plugin_name_(std::move(plugin_name)),
          port_hint_(port_hint),
          signature_(std::move(signature)),
          label_(std::move(label)),
          detail_(std::move(detail)),
          framing_(framing) {}

    std::string name() const override { return plugin_name_; }

    bool matches(const FlowContext&, Direction, const std::uint16_t upstream_port, const ByteVec& buffer) const override {
        return upstream_port == port_hint_ || (!signature_.empty() && starts_with(buffer, signature_.c_str()));
    }

    bool uses_protocol_framing() const override { return true; }

    FramingResult frame(const FlowContext&, const Direction direction, const ByteVec& buffer) const override {
        if (framing_ == ObservationFraming::Amqp091) return frame_amqp091(direction, buffer);
        if (framing_ == ObservationFraming::Amqp10) return frame_amqp10(direction, buffer);
        return frame_kafka(direction, buffer);
    }

    bool configure_window(const FlowContext&, Direction, WindowRule&) const override { return false; }

    Candidate build_candidate(const FlowContext&, Direction, const ByteVec& window, const FramingResult* framed) const override {
        Candidate candidate;
        candidate.plugin_name = plugin_name_;
        candidate.trigger_label = label_;
        candidate.packet_type = framed == nullptr ? label_ : framed->packet_type;
        candidate.original_bytes = window;
        candidate.modified_bytes = window;
        candidate.protocol_note = framed == nullptr ? detail_ : framed->detail;
        candidate.note = detail_;
        return candidate;
    }

    CandidateDecision decide(const FlowContext&, Direction, Candidate&) const override {
        CandidateDecision decision;
        decision.release = CandidateRelease::ReleaseOriginal;
        decision.outcome = ValidationOutcome::ValidationFallbackOriginal;
        decision.validation_label = "framed-observe-only";
        decision.validation_detail = "bounded protocol frame was observed and retained unchanged";
        decision.fallback_reason = "protocol mutation policy is not configured";
        return decision;
    }

    std::string audit_label() const override { return label_; }

private:
    FramingResult need_more(const std::string& detail) const {
        FramingResult result;
        result.disposition = FramingDisposition::NeedMoreBytes;
        result.detail = detail;
        return result;
    }

    FramingResult failed(const std::string& detail) const {
        FramingResult result;
        result.disposition = FramingDisposition::FramingFailed;
        result.detail = detail;
        result.structural_risk = true;
        return result;
    }

    FramingResult frame_amqp_header(const ByteVec& buffer) const {
        if (buffer.size() < 8) return need_more("waiting for complete AMQP protocol header");
        FramingResult result;
        result.disposition = FramingDisposition::FramedPacket;
        result.consumed_bytes = 8;
        result.frame_bytes.assign(buffer.begin(), buffer.begin() + 8);
        result.packet_type = "AMQP-PROTOCOL-HEADER";
        result.detail = "AMQP protocol-id=" + std::to_string(buffer[4]) + " version="
            + std::to_string(buffer[5]) + "." + std::to_string(buffer[6]) + "." + std::to_string(buffer[7]);
        return result;
    }

    FramingResult frame_amqp091(const Direction, const ByteVec& buffer) const {
        if (buffer.size() < 7) return need_more("waiting for AMQP header or frame header");
        if (starts_with(buffer, "AMQP")) return frame_amqp_header(buffer);

        const std::uint32_t payload_size = read_u32_be(buffer, 3);
        constexpr std::uint32_t hard_frame_ceiling = 16U * 1024U * 1024U;
        if (payload_size > hard_frame_ceiling) return failed("AMQP frame exceeds hard structural ceiling");
        const std::size_t total = 7U + static_cast<std::size_t>(payload_size) + 1U;
        if (buffer.size() < total) return need_more("waiting for complete AMQP 0-9-1 frame");
        if (buffer[total - 1] != 0xceU) return failed("AMQP frame-end octet is not 0xCE");

        static const char* types[] = {"UNKNOWN", "METHOD", "HEADER", "BODY", "HEARTBEAT"};
        const byte type = buffer[0];
        FramingResult result;
        result.disposition = FramingDisposition::FramedPacket;
        result.consumed_bytes = total;
        result.frame_bytes.assign(buffer.begin(), buffer.begin() + static_cast<long>(total));
        result.packet_type = type <= 4 ? std::string("AMQP-") + types[type] : "AMQP-TYPE-" + std::to_string(type);
        result.detail = "AMQP frame channel=" + std::to_string(read_u16_be(buffer, 1))
            + " payload-bytes=" + std::to_string(payload_size);
        return result;
    }

    FramingResult frame_amqp10(const Direction, const ByteVec& buffer) const {
        if (buffer.size() < 8) return need_more("waiting for AMQP 1.0 protocol or frame header");
        if (starts_with(buffer, "AMQP")) return frame_amqp_header(buffer);

        const std::uint32_t frame_size = read_u32_be(buffer, 0);
        constexpr std::uint32_t hard_frame_ceiling = 16U * 1024U * 1024U;
        if (frame_size < 8 || frame_size > hard_frame_ceiling) {
            return failed("AMQP 1.0 frame size is outside structural bounds");
        }
        const std::size_t header_size = static_cast<std::size_t>(buffer[4]) * 4U;
        if (header_size < 8 || header_size > frame_size) {
            return failed("AMQP 1.0 data offset is outside frame bounds");
        }
        if (buffer.size() < frame_size) return need_more("waiting for complete AMQP 1.0 frame");

        FramingResult result;
        result.disposition = FramingDisposition::FramedPacket;
        result.consumed_bytes = frame_size;
        result.frame_bytes.assign(buffer.begin(), buffer.begin() + static_cast<long>(frame_size));
        result.packet_type = buffer[5] == 0 ? "AMQP10-FRAME" : buffer[5] == 1 ? "AMQP10-SASL" : "AMQP10-TYPE-" + std::to_string(buffer[5]);
        result.detail = "AMQP 1.0 frame channel=" + std::to_string(read_u16_be(buffer, 6))
            + " header-bytes=" + std::to_string(header_size)
            + " frame-bytes=" + std::to_string(frame_size);
        return result;
    }

    FramingResult frame_kafka(const Direction direction, const ByteVec& buffer) const {
        if (buffer.size() < 4) return need_more("waiting for Kafka length prefix");
        const std::uint32_t body_size = read_u32_be(buffer, 0);
        constexpr std::uint32_t hard_frame_ceiling = 100U * 1024U * 1024U;
        if (body_size == 0 || body_size > hard_frame_ceiling) return failed("Kafka frame length is outside structural bounds");
        const std::size_t total = 4U + static_cast<std::size_t>(body_size);
        if (buffer.size() < total) return need_more("waiting for complete Kafka request or response frame");

        FramingResult result;
        result.disposition = FramingDisposition::FramedPacket;
        result.consumed_bytes = total;
        result.frame_bytes.assign(buffer.begin(), buffer.begin() + static_cast<long>(total));
        if (direction == Direction::ClientToServer && body_size >= 8) {
            result.packet_type = "KAFKA-REQUEST";
            result.detail = "Kafka request api-key=" + std::to_string(read_u16_be(buffer, 4))
                + " api-version=" + std::to_string(read_u16_be(buffer, 6))
                + " correlation-id=" + std::to_string(read_u32_be(buffer, 8));
        } else {
            result.packet_type = "KAFKA-RESPONSE";
            result.detail = body_size >= 4
                ? "Kafka response correlation-id=" + std::to_string(read_u32_be(buffer, 4))
                : "Kafka response frame";
        }
        return result;
    }

    std::string plugin_name_;
    std::uint16_t port_hint_;
    std::string signature_;
    std::string label_;
    std::string detail_;
    ObservationFraming framing_;
};

struct MqttFrameInfo {
    bool valid = false;
    byte first_byte = 0;
    std::size_t remaining_length = 0;
    std::size_t remaining_length_field_size = 0;
    std::size_t total_size = 0;
    std::size_t payload_offset = 0;
    std::size_t payload_size = 0;
    std::size_t variable_header_size = 0;
    bool payload_mutable = false;
    bool opaque_payload = false;
    std::string packet_type;
    std::string detail;
};

bool decode_remaining_length(const ByteVec& frame, std::size_t& value, std::size_t& encoded_size, std::string& error) {
    value = 0;
    encoded_size = 0;
    std::size_t multiplier = 1;

    for (std::size_t i = 1; i < frame.size() && i <= 4; ++i) {
        const byte encoded = frame[i];
        ++encoded_size;
        value += static_cast<std::size_t>(encoded & 0x7fU) * multiplier;
        if ((encoded & 0x80U) == 0) return true;
        multiplier *= 128;
    }

    if (frame.size() < 2) {
        error = "need more bytes for MQTT remaining length";
    } else {
        error = "malformed MQTT remaining length";
    }
    return false;
}

ByteVec encode_remaining_length(std::size_t value) {
    ByteVec out;
    do {
        byte encoded = static_cast<byte>(value % 128U);
        value /= 128U;
        if (value > 0) encoded = static_cast<byte>(encoded | 0x80U);
        out.push_back(encoded);
    } while (value > 0 && out.size() < 4);
    return out;
}

std::string mqtt_packet_type_name(byte type) {
    switch (type) {
        case 1: return "CONNECT";
        case 2: return "CONNACK";
        case 3: return "PUBLISH";
        case 4: return "PUBACK";
        case 8: return "SUBSCRIBE";
        case 9: return "SUBACK";
        default: return "CONTROL";
    }
}

MqttFrameInfo parse_mqtt_frame(const ByteVec& frame) {
    MqttFrameInfo info;
    if (frame.size() < 2) {
        info.detail = "need more bytes for mqtt fixed header";
        return info;
    }

    std::size_t remaining_length = 0;
    std::size_t remaining_size = 0;
    std::string error;
    if (!decode_remaining_length(frame, remaining_length, remaining_size, error)) {
        info.detail = error;
        return info;
    }

    const std::size_t fixed_header_size = 1 + remaining_size;
    const std::size_t total_size = fixed_header_size + remaining_length;
    if (frame.size() < total_size) {
        info.detail = "need more bytes for complete mqtt frame";
        return info;
    }

    info.valid = true;
    info.first_byte = frame[0];
    info.remaining_length = remaining_length;
    info.remaining_length_field_size = remaining_size;
    info.total_size = total_size;
    info.packet_type = mqtt_packet_type_name(static_cast<byte>((frame[0] >> 4U) & 0x0fU));

    if (info.packet_type != "PUBLISH") {
        info.detail = "mqtt control packet";
        return info;
    }

    if (remaining_length < 2 || fixed_header_size + 2 > total_size) {
        info.valid = false;
        info.detail = "mqtt publish missing topic length";
        return info;
    }

    const std::size_t topic_length = (static_cast<std::size_t>(frame[fixed_header_size]) << 8U)
        | static_cast<std::size_t>(frame[fixed_header_size + 1]);
    const std::size_t qos = static_cast<std::size_t>((frame[0] >> 1U) & 0x03U);
    std::size_t variable_header_size = 2 + topic_length;
    if (qos > 0) variable_header_size += 2;

    if (fixed_header_size + variable_header_size > total_size) {
        info.valid = false;
        info.detail = "mqtt publish variable header exceeds frame";
        return info;
    }

    info.variable_header_size = variable_header_size;
    info.payload_offset = fixed_header_size + variable_header_size;
    info.payload_size = total_size - info.payload_offset;
    info.payload_mutable = true;
    info.opaque_payload = !is_printable_payload(ByteVec(frame.begin() + static_cast<long>(info.payload_offset),
                                                       frame.begin() + static_cast<long>(info.total_size)));
    info.detail = "mqtt publish frame";
    return info;
}

class MqttPlugin : public ProtocolPlugin {
public:
    explicit MqttPlugin(const MutationConfig& config) : config_(config) {}

    std::string name() const override { return "mqtt"; }

    bool matches(const FlowContext&, Direction, std::uint16_t upstream_port, const ByteVec& buffer) const override {
        if (upstream_port == 1883) return true;
        if (buffer.empty()) return false;
        const byte type = static_cast<byte>((buffer[0] >> 4U) & 0x0fU);
        return type >= 1 && type <= 14;
    }

    bool uses_protocol_framing() const override { return true; }

    FramingResult frame(const FlowContext&, Direction, const ByteVec& buffer) const override {
        FramingResult result;
        if (buffer.empty()) return result;

        std::size_t remaining_length = 0;
        std::size_t encoded_size = 0;
        std::string error;
        if (!decode_remaining_length(buffer, remaining_length, encoded_size, error)) {
            result.disposition = (error == "malformed MQTT remaining length")
                ? FramingDisposition::FramingFailed
                : FramingDisposition::NeedMoreBytes;
            result.detail = error;
            result.structural_risk = result.disposition == FramingDisposition::FramingFailed;
            return result;
        }

        const std::size_t total_size = 1 + encoded_size + remaining_length;
        if (buffer.size() < total_size) {
            result.disposition = FramingDisposition::NeedMoreBytes;
            result.detail = "need more bytes for complete mqtt frame";
            return result;
        }

        result.disposition = FramingDisposition::FramedPacket;
        result.consumed_bytes = total_size;
        result.frame_bytes.assign(buffer.begin(), buffer.begin() + static_cast<long>(total_size));

        const MqttFrameInfo info = parse_mqtt_frame(result.frame_bytes);
        if (!info.valid) {
            result.disposition = FramingDisposition::FramingFailed;
            result.detail = info.detail;
            result.structural_risk = true;
            return result;
        }

        result.packet_type = info.packet_type;
        result.detail = info.detail;
        result.candidate_mutation_allowed = info.packet_type == "PUBLISH";
        return result;
    }

    bool configure_window(const FlowContext&, Direction, WindowRule& rule) const override {
        rule = WindowRule();
        return false;
    }

    Candidate build_candidate(const FlowContext&, Direction, const ByteVec& window, const FramingResult* framed) const override {
        Candidate candidate;
        candidate.plugin_name = name();
        candidate.trigger_label = "mqtt-fixed-header";
        candidate.original_bytes = window;
        candidate.modified_bytes = window;
        candidate.packet_type = framed != nullptr ? framed->packet_type : "CONTROL";
        candidate.protocol_note = framed != nullptr ? framed->detail : "";

        const MqttFrameInfo info = parse_mqtt_frame(window);
        candidate.packet_type = info.packet_type;
        candidate.protocol_note = info.detail;
        candidate.header_size = 1 + info.remaining_length_field_size;
        candidate.payload_offset = info.payload_offset;
        candidate.payload_size = info.payload_size;

        if (!info.valid) {
            candidate.note = "mqtt framing invalid";
            return candidate;
        }

        if (info.packet_type != "PUBLISH") {
            candidate.note = "mqtt-framed-observe-only";
            return candidate;
        }

        if (config_.replacement_text.empty()) {
            candidate.note = "mqtt publish observed with no replacement text configured";
            return candidate;
        }

        if (info.opaque_payload) {
            candidate.note = "mqtt publish payload looked opaque";
            return candidate;
        }

        ByteVec replacement(config_.replacement_text.begin(), config_.replacement_text.end());
        ByteVec reframed;
        reframed.reserve(window.size() - info.payload_size + replacement.size());
        reframed.push_back(info.first_byte);

        const std::size_t new_remaining_length = info.remaining_length - info.payload_size + replacement.size();
        ByteVec encoded_remaining = encode_remaining_length(new_remaining_length);
        reframed.insert(reframed.end(), encoded_remaining.begin(), encoded_remaining.end());
        reframed.insert(reframed.end(),
                        window.begin() + static_cast<long>(candidate.header_size),
                        window.begin() + static_cast<long>(info.payload_offset));
        reframed.insert(reframed.end(), replacement.begin(), replacement.end());

        candidate.modified_bytes = reframed;
        candidate.payload_size = info.payload_size;
        candidate.size_delta = static_cast<long long>(candidate.modified_bytes.size()) - static_cast<long long>(candidate.original_bytes.size());
        candidate.allow_size_mutated = candidate.size_delta == 0 || !encoded_remaining.empty();
        candidate.note = mutation_note(candidate);
        return candidate;
    }

    CandidateDecision decide(const FlowContext&, Direction direction, Candidate& candidate) const override {
        CandidateDecision decision;

        if (candidate.packet_type != "PUBLISH") {
            decision.release = CandidateRelease::ReleaseOriginal;
            decision.outcome = ValidationOutcome::ValidationFallbackOriginal;
            decision.validation_label = "framed-observe-only";
            decision.validation_detail = "mqtt control packets are framed and audited first";
            decision.fallback_reason = "mqtt control packet kept on original path";
            return decision;
        }

        if (!direction_is_mutable(config_, direction)) {
            decision.release = CandidateRelease::ReleaseOriginal;
            decision.outcome = ValidationOutcome::ValidationFallbackOriginal;
            decision.validation_label = "mqtt-direction-filter";
            decision.validation_detail = "mqtt mutation disabled for this direction";
            decision.fallback_reason = "mqtt direction is observe-only";
            return decision;
        }

        if (candidate.modified_bytes == candidate.original_bytes) {
            candidate.pid_drift_risk = candidate.protocol_note == "mqtt publish payload looked opaque";
            decision.release = CandidateRelease::ReleaseOriginal;
            decision.outcome = candidate.pid_drift_risk ? ValidationOutcome::ValidationObserveOnly : ValidationOutcome::ValidationFallbackOriginal;
            decision.observe_only = candidate.pid_drift_risk;
            decision.create_action_item = candidate.pid_drift_risk;
            decision.validation_label = candidate.pid_drift_risk ? "opaque-publish-payload" : "no-op";
            decision.validation_detail = candidate.pid_drift_risk
                ? "mqtt publish payload did not look safely mutable"
                : "no replacement text or no safe payload delta";
            decision.fallback_reason = candidate.pid_drift_risk
                ? "mqtt payload appeared opaque and was kept original"
                : "mqtt publish produced no safe delta";
            if (candidate.pid_drift_risk) {
                decision.action_title = "Begin mqtt live mutation workflow";
                decision.action_detail = "Inspect MQTT publish payload framing and decide whether a live mutation attempt is safe.";
            }
            return decision;
        }

        const MqttFrameInfo reframed = parse_mqtt_frame(candidate.modified_bytes);
        if (!reframed.valid || reframed.packet_type != "PUBLISH") {
            candidate.pid_drift_risk = true;
            decision.release = CandidateRelease::ReleaseOriginal;
            decision.outcome = ValidationOutcome::ValidationObserveOnly;
            decision.observe_only = true;
            decision.create_action_item = true;
            decision.validation_label = "mqtt-reframe-invalid";
            decision.validation_detail = reframed.detail;
            decision.fallback_reason = "mqtt reframe validation failed";
            decision.action_title = "Begin mqtt live mutation workflow";
            decision.action_detail = "Ghostline could not validate the reframed MQTT publish packet and preserved the original bytes.";
            return decision;
        }

        if (candidate.size_delta != 0 && !config_.allow_size_mutation) {
            candidate.pid_drift_risk = true;
            decision.release = CandidateRelease::ReleaseOriginal;
            decision.outcome = ValidationOutcome::ValidationObserveOnly;
            decision.observe_only = true;
            decision.create_action_item = true;
            decision.validation_label = "mqtt-size-mutation-blocked";
            decision.validation_detail = "operator disabled size-changing mqtt mutations";
            decision.fallback_reason = "mqtt size mutation not allowed";
            decision.action_title = "Begin mqtt live mutation workflow";
            decision.action_detail = "Allow size mutation or keep observing the MQTT flow before attempting another payload rewrite.";
            return decision;
        }

        if (candidate.size_delta != 0 && !candidate.allow_size_mutated) {
            candidate.pid_drift_risk = true;
            decision.release = CandidateRelease::ReleaseOriginal;
            decision.outcome = ValidationOutcome::ValidationObserveOnly;
            decision.observe_only = true;
            decision.create_action_item = true;
            decision.validation_label = "mqtt-pid-drift-risk";
            decision.validation_detail = "size-changing mqtt publish candidate lacked a safe remaining-length rewrite";
            decision.fallback_reason = "mqtt size mutation could not be proven safe";
            decision.action_title = "Begin mqtt live mutation workflow";
            decision.action_detail = "Revisit MQTT remaining-length and payload framing before replacing this publish packet.";
            return decision;
        }

        candidate.valid = true;
        decision.release = CandidateRelease::ReleaseModified;
        decision.outcome = ValidationOutcome::ValidationPassed;
        decision.validation_label = candidate.size_delta == 0 ? "mqtt-publish-validated" : "mqtt-publish-reframed";
        decision.validation_detail = "mqtt publish candidate validated and reframed";
        if (config_.mqtt_review_threshold_bytes > 0 && candidate.payload_size >= config_.mqtt_review_threshold_bytes) {
            decision.review_required = true;
            decision.create_action_item = true;
            decision.review_reason = "mqtt mutation exceeded configured review threshold";
            decision.action_title = "Review mqtt mutation";
            decision.action_detail = "MQTT mutation released successfully but crossed the configured review threshold.";
        }
        return decision;
    }

    std::string audit_label() const override { return "mqtt"; }

private:
    MutationConfig config_;
};

} // namespace

std::vector<std::unique_ptr<ProtocolPlugin>> make_builtin_plugins(const MutationConfig& config) {
    std::vector<std::unique_ptr<ProtocolPlugin>> plugins;
    plugins.emplace_back(new RawLivePlugin(config));
    plugins.emplace_back(new ByteWindowPlugin(config));
    plugins.emplace_back(new MqttPlugin(config));
    plugins.emplace_back(new FramedObservationPlugin("rabbitmq", 5672, "AMQP", "amqp-0-9-1",
                                                      "rabbitmq AMQP 0-9-1 framed observation plugin",
                                                      ObservationFraming::Amqp091));
    plugins.emplace_back(new ObservationPlugin("activemq", 61616, "", "activemq-openwire", "activemq observe-only protocol plugin"));
    plugins.emplace_back(new FramedObservationPlugin("amqp", 5672, "AMQP", "amqp-generic",
                                                      "generic AMQP 1.0 framed observation plugin",
                                                      ObservationFraming::Amqp10));
    plugins.emplace_back(new ObservationPlugin("azure-service-bus", 5671, "", "azure-service-bus", "azure service bus observe-only protocol plugin"));
    plugins.emplace_back(new FramedObservationPlugin("kafka", 9092, "", "kafka",
                                                      "kafka length-framed observation plugin",
                                                      ObservationFraming::Kafka));
    return plugins;
}
