#include "ghostline/operator_state.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>

namespace {

std::string json_escape(const std::string& value) {
    std::ostringstream out;
    for (char ch : value) {
        switch (ch) {
            case '\\': out << "\\\\"; break;
            case '"': out << "\\\""; break;
            case '\n': out << "\\n"; break;
            case '\r': out << "\\r"; break;
            case '\t': out << "\\t"; break;
            default: out << ch; break;
        }
    }
    return out.str();
}

std::string read_text(const std::string& path) {
    std::ifstream in(path);
    if (!in) {
        throw std::runtime_error("failed to open " + path);
    }
    std::ostringstream buffer;
    buffer << in.rdbuf();
    return buffer.str();
}

void write_text(const std::string& path, const std::string& text) {
    std::ofstream out(path);
    if (!out) {
        throw std::runtime_error("failed to write " + path);
    }
    out << text;
}

std::string extract_string_field(const std::string& text, const std::string& key) {
    const std::string needle = "\"" + key + "\":";
    const std::size_t start = text.find(needle);
    if (start == std::string::npos) return "";
    const std::size_t quote = text.find('"', start + needle.size());
    if (quote == std::string::npos) return "";
    std::size_t end = quote + 1;
    while (true) {
        end = text.find('"', end);
        if (end == std::string::npos) return "";
        if (text[end - 1] != '\\') break;
        ++end;
    }
    return text.substr(quote + 1, end - quote - 1);
}

long long extract_integer_field(const std::string& text, const std::string& key, long long default_value = 0) {
    const std::string needle = "\"" + key + "\":";
    const std::size_t start = text.find(needle);
    if (start == std::string::npos) return default_value;
    std::size_t pos = start + needle.size();
    while (pos < text.size() && text[pos] == ' ') ++pos;
    std::size_t end = pos;
    while (end < text.size() && (std::isdigit(static_cast<unsigned char>(text[end])) || text[end] == '-')) ++end;
    if (end == pos) return default_value;
    return std::stoll(text.substr(pos, end - pos));
}

bool extract_bool_field(const std::string& text, const std::string& key, bool default_value = false) {
    const std::string needle = "\"" + key + "\":";
    const std::size_t start = text.find(needle);
    if (start == std::string::npos) return default_value;
    const std::size_t pos = start + needle.size();
    if (text.compare(pos, 4, "true") == 0) return true;
    if (text.compare(pos, 5, "false") == 0) return false;
    return default_value;
}

std::string query_to_json(const PidSearchQuery& query) {
    std::ostringstream out;
    out << "{"
        << "\"process_contains\":\"" << json_escape(query.process_contains) << "\""
        << ",\"pid\":" << query.pid
        << ",\"port\":" << query.port
        << ",\"state\":\"" << json_escape(query.state) << "\""
        << ",\"listen_only\":" << (query.listen_only ? "true" : "false")
        << ",\"established_only\":" << (query.established_only ? "true" : "false")
        << "}";
    return out.str();
}

std::string matches_to_json(const std::vector<ProcessSocketEntry>& matches) {
    std::ostringstream out;
    out << "[";
    for (std::size_t i = 0; i < matches.size(); ++i) {
        if (i != 0) out << ",";
        out << "{"
            << "\"pid\":" << matches[i].pid
            << ",\"command\":\"" << json_escape(matches[i].command) << "\""
            << ",\"user\":\"" << json_escape(matches[i].user) << "\""
            << ",\"socket_count\":" << matches[i].sockets.size()
            << "}";
    }
    out << "]";
    return out.str();
}

std::filesystem::path ensure_dir(const std::string& dir) {
    std::filesystem::path path(dir);
    std::filesystem::create_directories(path);
    return path;
}

std::string action_item_to_json(const ActionItem& item) {
    std::ostringstream out;
    out << "{"
        << "\"action_id\":\"" << json_escape(item.action_id) << "\""
        << ",\"trigger_id\":\"" << json_escape(item.trigger_id) << "\""
        << ",\"candidate_id\":\"" << json_escape(item.candidate_id) << "\""
        << ",\"flow\":" << item.flow_id
        << ",\"plugin\":\"" << json_escape(item.plugin_name) << "\""
        << ",\"direction\":\"" << (item.direction == Direction::ClientToServer ? "client_to_server" : "server_to_client") << "\""
        << ",\"title\":\"" << json_escape(item.title) << "\""
        << ",\"detail\":\"" << json_escape(item.detail) << "\""
        << ",\"validation_label\":\"" << json_escape(item.validation_label) << "\""
        << ",\"fallback_reason\":\"" << json_escape(item.fallback_reason) << "\""
        << ",\"original_hex\":\"" << item.original_hex << "\""
        << ",\"modified_hex\":\"" << item.modified_hex << "\""
        << ",\"review_status\":\"" << json_escape(item.review_status) << "\""
        << ",\"decision_note\":\"" << json_escape(item.decision_note) << "\""
        << ",\"replay_count\":" << item.replay_count
        << ",\"created_at_ns\":" << item.created_at_ns
        << "}\n";
    return out.str();
}

ActionItem parse_action_item_json(const std::string& text) {
    ActionItem item;
    item.action_id = extract_string_field(text, "action_id");
    item.trigger_id = extract_string_field(text, "trigger_id");
    item.candidate_id = extract_string_field(text, "candidate_id");
    item.flow_id = static_cast<std::uint32_t>(extract_integer_field(text, "flow", 0));
    item.plugin_name = extract_string_field(text, "plugin");
    item.direction = extract_string_field(text, "direction") == "server_to_client"
        ? Direction::ServerToClient
        : Direction::ClientToServer;
    item.title = extract_string_field(text, "title");
    item.detail = extract_string_field(text, "detail");
    item.validation_label = extract_string_field(text, "validation_label");
    item.fallback_reason = extract_string_field(text, "fallback_reason");
    item.original_hex = extract_string_field(text, "original_hex");
    item.modified_hex = extract_string_field(text, "modified_hex");
    item.review_status = extract_string_field(text, "review_status");
    if (item.review_status.empty()) item.review_status = "pending";
    item.decision_note = extract_string_field(text, "decision_note");
    item.replay_count = static_cast<std::uint32_t>(extract_integer_field(text, "replay_count", 0));
    item.created_at_ns = static_cast<std::uint64_t>(extract_integer_field(text, "created_at_ns", 0));
    return item;
}

} // namespace

std::string bytes_to_hex_string(const ByteVec& bytes) {
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (byte value : bytes) {
        out.push_back(kHex[(value >> 4U) & 0x0fU]);
        out.push_back(kHex[value & 0x0fU]);
    }
    return out;
}

void save_target_profile(const std::string& path, const TargetProfile& profile) {
    std::filesystem::path target(path);
    if (target.has_parent_path()) {
        std::filesystem::create_directories(target.parent_path());
    }
    std::ostringstream out;
    out << "{"
        << "\"label\":\"" << json_escape(profile.label) << "\""
        << ",\"process_contains\":\"" << json_escape(profile.query.process_contains) << "\""
        << ",\"pid\":" << profile.query.pid
        << ",\"port\":" << profile.query.port
        << ",\"state\":\"" << json_escape(profile.query.state) << "\""
        << ",\"listen_only\":" << (profile.query.listen_only ? "true" : "false")
        << ",\"established_only\":" << (profile.query.established_only ? "true" : "false")
        << ",\"transport\":\"" << json_escape(profile.transport) << "\""
        << ",\"listen_host\":\"" << json_escape(profile.listen_host) << "\""
        << ",\"listen_port\":" << profile.listen_port
        << ",\"upstream_host\":\"" << json_escape(profile.upstream_host) << "\""
        << ",\"upstream_port\":" << profile.upstream_port
        << ",\"serial_ingress_device\":\"" << json_escape(profile.serial_ingress_device) << "\""
        << ",\"serial_device\":\"" << json_escape(profile.serial_device) << "\""
        << ",\"ingress_baud\":" << profile.ingress_baud
        << ",\"baud\":" << profile.baud
        << ",\"data_bits\":" << profile.data_bits
        << ",\"stop_bits\":" << profile.stop_bits
        << ",\"parity\":\"" << json_escape(profile.parity) << "\""
        << ",\"flow_control\":\"" << json_escape(profile.flow_control) << "\""
        << ",\"protocol_hint\":\"" << json_escape(profile.protocol_hint) << "\""
        << ",\"observe_only\":" << (profile.observe_only ? "true" : "false")
        << ",\"expect_connack\":" << (profile.expect_connack ? "true" : "false")
        << ",\"capture_path\":\"" << json_escape(profile.capture_path) << "\""
        << ",\"capture_pcap_path\":\"" << json_escape(profile.capture_pcap_path) << "\""
        << ",\"capture_max_bytes\":" << profile.capture_max_bytes
        << ",\"capture_snaplen\":" << profile.capture_snaplen
        << ",\"query\":" << query_to_json(profile.query)
        << ",\"matches\":" << matches_to_json(profile.matches)
        << "}\n";
    write_text(path, out.str());
}

TargetProfile load_target_profile(const std::string& path) {
    const std::string text = read_text(path);
    TargetProfile profile;
    profile.label = extract_string_field(text, "label");
    profile.query.process_contains = extract_string_field(text, "process_contains");
    profile.query.pid = extract_integer_field(text, "pid", -1);
    profile.query.port = static_cast<std::int32_t>(extract_integer_field(text, "port", -1));
    profile.query.state = extract_string_field(text, "state");
    profile.query.listen_only = extract_bool_field(text, "listen_only", false);
    profile.query.established_only = extract_bool_field(text, "established_only", false);
    profile.transport = extract_string_field(text, "transport");
    if (profile.transport.empty()) profile.transport = "tcp";
    profile.listen_host = extract_string_field(text, "listen_host");
    if (profile.listen_host.empty()) profile.listen_host = "127.0.0.1";
    profile.listen_port = static_cast<std::int32_t>(extract_integer_field(text, "listen_port", 7777));
    profile.upstream_host = extract_string_field(text, "upstream_host");
    if (profile.upstream_host.empty()) profile.upstream_host = "127.0.0.1";
    profile.upstream_port = static_cast<std::int32_t>(extract_integer_field(text, "upstream_port", 8888));
    profile.serial_ingress_device = extract_string_field(text, "serial_ingress_device");
    profile.serial_device = extract_string_field(text, "serial_device");
    profile.ingress_baud = static_cast<std::int32_t>(extract_integer_field(text, "ingress_baud", 115200));
    profile.baud = static_cast<std::int32_t>(extract_integer_field(text, "baud", 115200));
    profile.data_bits = static_cast<std::int32_t>(extract_integer_field(text, "data_bits", 8));
    profile.stop_bits = static_cast<std::int32_t>(extract_integer_field(text, "stop_bits", 1));
    profile.parity = extract_string_field(text, "parity");
    if (profile.parity.empty()) profile.parity = "none";
    profile.flow_control = extract_string_field(text, "flow_control");
    if (profile.flow_control.empty()) profile.flow_control = "none";
    profile.protocol_hint = extract_string_field(text, "protocol_hint");
    profile.observe_only = extract_bool_field(text, "observe_only", true);
    profile.expect_connack = extract_bool_field(text, "expect_connack", false);
    profile.capture_path = extract_string_field(text, "capture_path");
    profile.capture_pcap_path = extract_string_field(text, "capture_pcap_path");
    profile.capture_max_bytes = static_cast<std::size_t>(extract_integer_field(text, "capture_max_bytes", 4U * 1024U * 1024U));
    profile.capture_snaplen = static_cast<std::size_t>(extract_integer_field(text, "capture_snaplen", 1024));
    return profile;
}

std::vector<std::string> list_target_profiles(const std::string& directory) {
    std::vector<std::string> paths;
    std::filesystem::path dir(directory);
    if (!std::filesystem::exists(dir)) {
        return paths;
    }
    for (const auto& entry : std::filesystem::directory_iterator(dir)) {
        if (entry.is_regular_file()) {
            paths.push_back(entry.path().string());
        }
    }
    std::sort(paths.begin(), paths.end());
    return paths;
}

std::string target_profile_to_json(const TargetProfile& profile) {
    std::ostringstream out;
    out << "{"
        << "\"label\":\"" << json_escape(profile.label) << "\""
        << ",\"process_contains\":\"" << json_escape(profile.query.process_contains) << "\""
        << ",\"pid\":" << profile.query.pid
        << ",\"port\":" << profile.query.port
        << ",\"state\":\"" << json_escape(profile.query.state) << "\""
        << ",\"listen_only\":" << (profile.query.listen_only ? "true" : "false")
        << ",\"established_only\":" << (profile.query.established_only ? "true" : "false")
        << ",\"transport\":\"" << json_escape(profile.transport) << "\""
        << ",\"listen_host\":\"" << json_escape(profile.listen_host) << "\""
        << ",\"listen_port\":" << profile.listen_port
        << ",\"upstream_host\":\"" << json_escape(profile.upstream_host) << "\""
        << ",\"upstream_port\":" << profile.upstream_port
        << ",\"serial_ingress_device\":\"" << json_escape(profile.serial_ingress_device) << "\""
        << ",\"serial_device\":\"" << json_escape(profile.serial_device) << "\""
        << ",\"ingress_baud\":" << profile.ingress_baud
        << ",\"baud\":" << profile.baud
        << ",\"data_bits\":" << profile.data_bits
        << ",\"stop_bits\":" << profile.stop_bits
        << ",\"parity\":\"" << json_escape(profile.parity) << "\""
        << ",\"flow_control\":\"" << json_escape(profile.flow_control) << "\""
        << ",\"protocol_hint\":\"" << json_escape(profile.protocol_hint) << "\""
        << ",\"observe_only\":" << (profile.observe_only ? "true" : "false")
        << ",\"expect_connack\":" << (profile.expect_connack ? "true" : "false")
        << ",\"capture_path\":\"" << json_escape(profile.capture_path) << "\""
        << ",\"capture_pcap_path\":\"" << json_escape(profile.capture_pcap_path) << "\""
        << ",\"capture_max_bytes\":" << profile.capture_max_bytes
        << ",\"capture_snaplen\":" << profile.capture_snaplen
        << ",\"query\":" << query_to_json(profile.query)
        << ",\"matches\":" << matches_to_json(profile.matches)
        << "}";
    return out.str();
}

std::vector<TargetProfile> default_protocol_target_profiles() {
    std::vector<TargetProfile> profiles;

    auto add_profile = [&profiles](const std::string& label,
                                   const std::string& process_contains,
                                   int port,
                                   const std::string& state = std::string(),
                                   bool listen_only = true) {
        TargetProfile profile;
        profile.label = label;
        profile.query.process_contains = process_contains;
        profile.query.port = port;
        profile.query.state = state;
        profile.query.listen_only = listen_only;
        profile.upstream_port = port;
        profile.listen_port = port == 1883 ? 11883 : port + 10000;
        profile.observe_only = true;
        profile.protocol_hint = label == "mqtt-broker" ? "mqtt" : std::string();
        profile.expect_connack = label == "mqtt-broker";
        profile.capture_path = label + ".glcap";
        profile.capture_pcap_path = label + ".pcap";
        profiles.push_back(profile);
    };

    add_profile("mqtt-broker", "mqtt", 1883);
    add_profile("rabbitmq-rmq", "rabbit", 5672);
    add_profile("amqp-generic", "amqp", 5672);
    add_profile("activemq-broker", "activemq", 61616);
    add_profile("azure-service-bus", "azure", 5671);
    add_profile("kafka-broker", "kafka", 9092);

    TargetProfile com0com;
    com0com.label = "com0com-serial-pair";
    com0com.transport = "serial-pair";
    com0com.serial_ingress_device = "COM5";
    com0com.serial_device = "COM6";
    com0com.ingress_baud = 115200;
    com0com.baud = 115200;
    com0com.protocol_hint = "raw-live";
    com0com.observe_only = true;
    com0com.capture_path = "com0com-serial-pair.glcap";
    com0com.capture_pcap_path = "com0com-serial-pair.pcap";
    profiles.push_back(com0com);

    TargetProfile field_serial;
    field_serial.label = "field-serial-console";
    field_serial.transport = "tcp-serial";
    field_serial.listen_port = 17777;
    field_serial.serial_device = "/dev/ttyWK0";
    field_serial.baud = 115200;
    field_serial.protocol_hint = "raw-live";
    field_serial.observe_only = true;
    field_serial.capture_path = "field-serial-console.glcap";
    field_serial.capture_pcap_path = "field-serial-console.pcap";
    profiles.push_back(field_serial);

    return profiles;
}

std::vector<std::string> seed_protocol_target_profiles(const std::string& directory) {
    const auto dir = ensure_dir(directory);
    std::vector<std::string> written;
    for (const auto& profile : default_protocol_target_profiles()) {
        const std::filesystem::path path = dir / (profile.label + ".json");
        save_target_profile(path.string(), profile);
        written.push_back(path.string());
    }
    return written;
}

void save_review_item(const std::string& queue_dir, const ActionItem& item) {
    const auto dir = ensure_dir(queue_dir);
    write_text((dir / (item.action_id + ".json")).string(), action_item_to_json(item));
}

ActionItem load_review_item(const std::string& path) {
    return parse_action_item_json(read_text(path));
}

std::vector<ActionItem> list_review_items(const std::string& queue_dir) {
    std::vector<ActionItem> items;
    for (const auto& path : list_target_profiles(queue_dir)) {
        items.push_back(load_review_item(path));
    }
    return items;
}

void update_review_item(const std::string& queue_dir,
                        const std::string& action_id,
                        const std::string& status,
                        const std::string& decision_note) {
    const auto dir = ensure_dir(queue_dir);
    const std::filesystem::path path = dir / (action_id + ".json");
    ActionItem item = load_review_item(path.string());
    item.review_status = status;
    item.decision_note = decision_note;
    write_text(path.string(), action_item_to_json(item));
}

std::string replay_review_item(const std::string& queue_dir,
                               const std::string& action_id,
                               const std::string& replay_dir,
                               const std::string& decision_note) {
    const auto queue = ensure_dir(queue_dir);
    ActionItem item = load_review_item((queue / (action_id + ".json")).string());
    item.review_status = "replayed";
    item.decision_note = decision_note;
    ++item.replay_count;
    write_text((queue / (action_id + ".json")).string(), action_item_to_json(item));

    const auto replay = ensure_dir(replay_dir);
    const std::filesystem::path replay_path = replay / (action_id + "-replay-" + std::to_string(item.replay_count) + ".json");
    std::ostringstream out;
    out << "{"
        << "\"action_id\":\"" << json_escape(item.action_id) << "\""
        << ",\"candidate_id\":\"" << json_escape(item.candidate_id) << "\""
        << ",\"trigger_id\":\"" << json_escape(item.trigger_id) << "\""
        << ",\"plugin\":\"" << json_escape(item.plugin_name) << "\""
        << ",\"status\":\"" << json_escape(item.review_status) << "\""
        << ",\"decision_note\":\"" << json_escape(item.decision_note) << "\""
        << ",\"modified_hex\":\"" << item.modified_hex << "\""
        << ",\"original_hex\":\"" << item.original_hex << "\""
        << "}\n";
    write_text(replay_path.string(), out.str());
    return replay_path.string();
}
