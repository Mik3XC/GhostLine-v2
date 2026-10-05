#include "ghostline/plugin.hpp"
#include "ghostline/pid_search.hpp"
#include "ghostline/operator_state.hpp"
#include "ghostline/capture.hpp"

#include <filesystem>
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <stdexcept>

namespace {

void expect(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}

ByteVec bytes_from_ascii(const std::string& text) {
    return ByteVec(text.begin(), text.end());
}

void test_byte_window_plugin_releases_modified() {
    MutationConfig config;
    config.start_marker = bytes_from_ascii("HEAD");
    config.end_marker = bytes_from_ascii("TAIL");
    config.replacement_text = "NEW";
    config.allow_size_mutation = true;

    PluginRegistry registry(config);
    FlowContext flow;
    flow.flow_id = 1;

    ByteVec input = bytes_from_ascii("HEADoldTAIL");
    const ProtocolPlugin* plugin = registry.match(flow, Direction::ClientToServer, 7777, input);
    expect(plugin != nullptr, "expected byte-window plugin");

    WindowRule rule;
    expect(plugin->configure_window(flow, Direction::ClientToServer, rule), "expected byte-window rule");

    Candidate candidate = plugin->build_candidate(flow, Direction::ClientToServer, input);
    CandidateDecision decision = plugin->decide(flow, Direction::ClientToServer, candidate);
    expect(decision.release == CandidateRelease::ReleaseModified, "expected modified candidate release");
    expect(std::string(candidate.modified_bytes.begin(), candidate.modified_bytes.end()) == "HEADNEWTAIL", "expected replacement bytes");
}

void test_observation_plugin_stays_passive() {
    MutationConfig config;
    PluginRegistry registry(config);
    FlowContext flow;
    flow.flow_id = 2;

    ByteVec input = bytes_from_ascii("AMQP\x00\x00\x09\x01");
    const ProtocolPlugin* plugin = registry.match(flow, Direction::ClientToServer, 5672, input);
    expect(plugin != nullptr, "expected AMQP plugin");

    WindowRule rule;
    expect(!plugin->configure_window(flow, Direction::ClientToServer, rule), "expected observe-only plugin");

    Candidate candidate = plugin->build_candidate(flow, Direction::ClientToServer, input);
    CandidateDecision decision = plugin->decide(flow, Direction::ClientToServer, candidate);
    expect(decision.release == CandidateRelease::ReleaseOriginal, "observe-only plugin should release original");
}

void test_amqp_observation_plugin_frames_protocol_and_method_frames() {
    MutationConfig config;
    PluginRegistry registry(config);
    FlowContext flow;
    flow.preferred_plugin = "rabbitmq";
    const ProtocolPlugin* plugin = registry.match(flow, Direction::ClientToServer, 5672, ByteVec{'A', 'M', 'Q', 'P'});
    expect(plugin != nullptr && plugin->uses_protocol_framing(), "expected framed rabbitmq plugin");

    const ByteVec protocol_header{'A', 'M', 'Q', 'P', 0, 0, 9, 1};
    FramingResult framed = plugin->frame(flow, Direction::ClientToServer, protocol_header);
    expect(framed.disposition == FramingDisposition::FramedPacket, "expected AMQP protocol header frame");
    expect(framed.consumed_bytes == 8, "expected eight-byte AMQP protocol header");

    const ByteVec method_frame{1, 0, 1, 0, 0, 0, 2, 0, 10, 0xce};
    framed = plugin->frame(flow, Direction::ClientToServer, method_frame);
    expect(framed.disposition == FramingDisposition::FramedPacket, "expected complete AMQP method frame");
    expect(framed.packet_type == "AMQP-METHOD", "expected AMQP method label");
    Candidate candidate = plugin->build_candidate(flow, Direction::ClientToServer, framed.frame_bytes, &framed);
    CandidateDecision decision = plugin->decide(flow, Direction::ClientToServer, candidate);
    expect(decision.release == CandidateRelease::ReleaseOriginal, "AMQP observation must retain original frame");
}

void test_kafka_observation_plugin_frames_length_prefix() {
    MutationConfig config;
    PluginRegistry registry(config);
    FlowContext flow;
    flow.preferred_plugin = "kafka";
    const ByteVec request{0, 0, 0, 8, 0, 3, 0, 9, 0, 0, 0, 42};
    const ProtocolPlugin* plugin = registry.match(flow, Direction::ClientToServer, 9092, request);
    expect(plugin != nullptr && plugin->uses_protocol_framing(), "expected framed kafka plugin");
    const FramingResult framed = plugin->frame(flow, Direction::ClientToServer, request);
    expect(framed.disposition == FramingDisposition::FramedPacket, "expected complete Kafka request frame");
    expect(framed.packet_type == "KAFKA-REQUEST", "expected Kafka request label");
    expect(framed.detail.find("correlation-id=42") != std::string::npos, "expected Kafka correlation id");
}

void test_amqp10_observation_plugin_frames_performative() {
    MutationConfig config;
    PluginRegistry registry(config);
    FlowContext flow;
    flow.preferred_plugin = "amqp";
    const ByteVec frame{0, 0, 0, 8, 2, 0, 0, 7};
    const ProtocolPlugin* plugin = registry.match(flow, Direction::ClientToServer, 5672, frame);
    expect(plugin != nullptr && plugin->uses_protocol_framing(), "expected framed AMQP 1.0 plugin");
    const FramingResult framed = plugin->frame(flow, Direction::ClientToServer, frame);
    expect(framed.disposition == FramingDisposition::FramedPacket, "expected complete AMQP 1.0 frame");
    expect(framed.packet_type == "AMQP10-FRAME", "expected AMQP 1.0 frame label");
    expect(framed.detail.find("channel=7") != std::string::npos, "expected AMQP 1.0 channel");
}

void test_size_mutation_requires_safe_rewrite() {
    MutationConfig config;
    config.start_marker = bytes_from_ascii("HEAD");
    config.end_marker = bytes_from_ascii("TAIL");
    config.replacement_text = "A-LONGER-BODY";
    config.allow_size_mutation = true;

    PluginRegistry registry(config);
    FlowContext flow;
    flow.flow_id = 3;

    ByteVec input = bytes_from_ascii("HEADoldTAIL");
    const ProtocolPlugin* plugin = registry.match(flow, Direction::ClientToServer, 7777, input);
    expect(plugin != nullptr, "expected byte-window plugin");

    Candidate candidate = plugin->build_candidate(flow, Direction::ClientToServer, input);
    CandidateDecision decision = plugin->decide(flow, Direction::ClientToServer, candidate);
    expect(decision.release == CandidateRelease::ReleaseOriginal, "unsafe size mutation should keep original");
    expect(decision.observe_only, "unsafe size mutation should force observe-only");
    expect(decision.create_action_item, "unsafe size mutation should create action item");
    expect(candidate.pid_drift_risk, "unsafe size mutation should mark pid drift risk");
}

void test_protocol_hint_selects_requested_plugin() {
    MutationConfig config;
    PluginRegistry registry(config);
    FlowContext flow;
    flow.flow_id = 4;
    flow.preferred_plugin = "kafka";

    ByteVec input = bytes_from_ascii("plain-bytes-without-kafka-signature");
    const ProtocolPlugin* plugin = registry.match(flow, Direction::ClientToServer, 1234, input);
    expect(plugin != nullptr, "expected preferred plugin");
    expect(plugin->name() == "kafka", "expected preferred plugin to win");
}

void test_all_named_plugins_are_registered() {
    MutationConfig config;
    PluginRegistry registry(config);
    expect(registry.find_by_name("raw-live") != nullptr, "missing raw-live plugin");
    expect(registry.find_by_name("mqtt") != nullptr, "missing mqtt plugin");
    expect(registry.find_by_name("rabbitmq") != nullptr, "missing rabbitmq plugin");
    expect(registry.find_by_name("activemq") != nullptr, "missing activemq plugin");
    expect(registry.find_by_name("amqp") != nullptr, "missing amqp plugin");
    expect(registry.find_by_name("azure-service-bus") != nullptr, "missing azure-service-bus plugin");
    expect(registry.find_by_name("kafka") != nullptr, "missing kafka plugin");
}

void test_raw_live_mutation_releases_modified() {
    MutationConfig config;
    config.raw_live_mode = true;
    config.raw_find_text = "old";
    config.replacement_text = "new";
    config.raw_chunk_bytes = 6;

    PluginRegistry registry(config);
    FlowContext flow;
    flow.flow_id = 8;
    flow.preferred_plugin = "raw-live";

    ByteVec input = bytes_from_ascii("old!!!");
    const ProtocolPlugin* plugin = registry.match(flow, Direction::ClientToServer, 9999, input);
    expect(plugin != nullptr && plugin->name() == "raw-live", "expected raw-live plugin");
    expect(plugin->uses_protocol_framing(), "raw-live should use protocol framing");

    FramingResult framed = plugin->frame(flow, Direction::ClientToServer, input);
    expect(framed.disposition == FramingDisposition::FramedPacket, "raw-live should frame a fixed chunk");

    Candidate candidate = plugin->build_candidate(flow, Direction::ClientToServer, framed.frame_bytes, &framed);
    CandidateDecision decision = plugin->decide(flow, Direction::ClientToServer, candidate);
    expect(decision.release == CandidateRelease::ReleaseModified, "raw-live should release modified bytes");
    expect(std::string(candidate.modified_bytes.begin(), candidate.modified_bytes.end()) == "new!!!", "raw-live should mutate the live raw chunk");
}

void test_raw_live_size_change_can_force_review() {
    MutationConfig config;
    config.raw_live_mode = true;
    config.raw_find_text = "a";
    config.replacement_text = "longer";
    config.raw_chunk_bytes = 4;
    config.allow_size_mutation = false;

    PluginRegistry registry(config);
    FlowContext flow;
    flow.flow_id = 9;
    flow.preferred_plugin = "raw-live";

    ByteVec input = bytes_from_ascii("a---");
    const ProtocolPlugin* plugin = registry.match(flow, Direction::ClientToServer, 9999, input);
    expect(plugin != nullptr, "expected raw-live plugin");

    FramingResult framed = plugin->frame(flow, Direction::ClientToServer, input);
    Candidate candidate = plugin->build_candidate(flow, Direction::ClientToServer, framed.frame_bytes, &framed);
    CandidateDecision decision = plugin->decide(flow, Direction::ClientToServer, candidate);
    expect(decision.release == CandidateRelease::ReleaseOriginal, "raw-live size change should keep original when blocked");
    expect(decision.review_required, "raw-live size change should require review");
    expect(decision.observe_only, "raw-live size change should push observe-only");
    expect(decision.create_action_item, "raw-live size change should create an action item");
}

void test_raw_live_direction_filter_keeps_original() {
    MutationConfig config;
    config.raw_live_mode = true;
    config.raw_find_text = "old";
    config.replacement_text = "new";
    config.raw_chunk_bytes = 6;
    config.mutate_client_to_server = true;
    config.mutate_server_to_client = false;

    PluginRegistry registry(config);
    FlowContext flow;
    flow.flow_id = 10;
    flow.preferred_plugin = "raw-live";

    ByteVec input = bytes_from_ascii("old!!!");
    const ProtocolPlugin* plugin = registry.match(flow, Direction::ServerToClient, 9999, input);
    expect(plugin != nullptr, "expected raw-live plugin");
    FramingResult framed = plugin->frame(flow, Direction::ServerToClient, input);
    Candidate candidate = plugin->build_candidate(flow, Direction::ServerToClient, framed.frame_bytes, &framed);
    CandidateDecision decision = plugin->decide(flow, Direction::ServerToClient, candidate);
    expect(decision.release == CandidateRelease::ReleaseOriginal, "raw-live direction filter should keep original");
    expect(decision.validation_label == "raw-live-direction-filter", "raw-live direction filter label mismatch");
}

void test_raw_live_review_threshold_creates_action_item() {
    MutationConfig config;
    config.raw_live_mode = true;
    config.raw_find_text = "old";
    config.replacement_text = "new";
    config.raw_chunk_bytes = 6;
    config.raw_review_threshold_bytes = 4;

    PluginRegistry registry(config);
    FlowContext flow;
    flow.flow_id = 11;
    flow.preferred_plugin = "raw-live";

    ByteVec input = bytes_from_ascii("old!!!");
    const ProtocolPlugin* plugin = registry.match(flow, Direction::ClientToServer, 9999, input);
    FramingResult framed = plugin->frame(flow, Direction::ClientToServer, input);
    Candidate candidate = plugin->build_candidate(flow, Direction::ClientToServer, framed.frame_bytes, &framed);
    CandidateDecision decision = plugin->decide(flow, Direction::ClientToServer, candidate);
    expect(decision.release == CandidateRelease::ReleaseModified, "raw-live threshold should not block safe mutation");
    expect(decision.review_required, "raw-live threshold should require review");
    expect(decision.create_action_item, "raw-live threshold should create action item");
}

ByteVec mqtt_publish_packet(const std::string& topic, const std::string& payload) {
    ByteVec packet;
    const std::size_t remaining_length = 2 + topic.size() + payload.size();
    packet.push_back(0x30);

    std::size_t value = remaining_length;
    do {
        byte encoded = static_cast<byte>(value % 128U);
        value /= 128U;
        if (value > 0) encoded = static_cast<byte>(encoded | 0x80U);
        packet.push_back(encoded);
    } while (value > 0);

    packet.push_back(static_cast<byte>((topic.size() >> 8U) & 0xff));
    packet.push_back(static_cast<byte>(topic.size() & 0xff));
    packet.insert(packet.end(), topic.begin(), topic.end());
    packet.insert(packet.end(), payload.begin(), payload.end());
    return packet;
}

void test_mqtt_publish_mutation_reframes_remaining_length() {
    MutationConfig config;
    config.replacement_text = "patched-payload";
    config.allow_size_mutation = true;

    PluginRegistry registry(config);
    FlowContext flow;
    flow.flow_id = 5;
    flow.preferred_plugin = "mqtt";

    ByteVec packet = mqtt_publish_packet("topic", "hello");
    const ProtocolPlugin* plugin = registry.match(flow, Direction::ClientToServer, 1883, packet);
    expect(plugin != nullptr && plugin->name() == "mqtt", "expected mqtt plugin");
    expect(plugin->uses_protocol_framing(), "mqtt should use protocol framing");

    FramingResult framed = plugin->frame(flow, Direction::ClientToServer, packet);
    expect(framed.disposition == FramingDisposition::FramedPacket, "expected framed mqtt packet");
    expect(framed.packet_type == "PUBLISH", "expected publish packet");

    Candidate candidate = plugin->build_candidate(flow, Direction::ClientToServer, framed.frame_bytes, &framed);
    CandidateDecision decision = plugin->decide(flow, Direction::ClientToServer, candidate);
    expect(decision.release == CandidateRelease::ReleaseModified, "mqtt publish should release modified candidate");
    expect(candidate.valid, "mqtt publish candidate should validate");
    expect(candidate.allow_size_mutated, "mqtt publish should allow reframed size mutation");
    expect(candidate.modified_bytes[0] == 0x30, "mqtt fixed header should be preserved");
    expect(candidate.modified_bytes[1] == static_cast<byte>(2 + 5 + std::string("patched-payload").size()), "mqtt remaining length should be rewritten");
}

void test_mqtt_incomplete_frame_needs_more_bytes() {
    MutationConfig config;
    PluginRegistry registry(config);
    FlowContext flow;
    flow.flow_id = 6;
    flow.preferred_plugin = "mqtt";

    ByteVec partial;
    partial.push_back(0x30);
    partial.push_back(0x07);
    partial.push_back(0x00);

    const ProtocolPlugin* plugin = registry.match(flow, Direction::ClientToServer, 1883, partial);
    expect(plugin != nullptr, "expected mqtt plugin");

    FramingResult framed = plugin->frame(flow, Direction::ClientToServer, partial);
    expect(framed.disposition == FramingDisposition::NeedMoreBytes, "partial mqtt frame should need more bytes");
}

void test_mqtt_invalid_remaining_length_fails_framing() {
    MutationConfig config;
    PluginRegistry registry(config);
    FlowContext flow;
    flow.flow_id = 7;
    flow.preferred_plugin = "mqtt";

    ByteVec invalid;
    invalid.push_back(0x30);
    invalid.push_back(0xff);
    invalid.push_back(0xff);
    invalid.push_back(0xff);
    invalid.push_back(0xff);
    invalid.push_back(0x01);

    const ProtocolPlugin* plugin = registry.match(flow, Direction::ClientToServer, 1883, invalid);
    expect(plugin != nullptr, "expected mqtt plugin");

    FramingResult framed = plugin->frame(flow, Direction::ClientToServer, invalid);
    expect(framed.disposition == FramingDisposition::FramingFailed, "invalid mqtt remaining length should fail framing");
}

void test_mqtt_direction_filter_keeps_original_publish() {
    MutationConfig config;
    config.replacement_text = "patched-payload";
    config.mutate_client_to_server = false;
    config.mutate_server_to_client = true;
    PluginRegistry registry(config);
    FlowContext flow;
    flow.flow_id = 12;
    flow.preferred_plugin = "mqtt";

    ByteVec packet = mqtt_publish_packet("topic", "hello");
    const ProtocolPlugin* plugin = registry.match(flow, Direction::ClientToServer, 1883, packet);
    FramingResult framed = plugin->frame(flow, Direction::ClientToServer, packet);
    Candidate candidate = plugin->build_candidate(flow, Direction::ClientToServer, framed.frame_bytes, &framed);
    CandidateDecision decision = plugin->decide(flow, Direction::ClientToServer, candidate);
    expect(decision.release == CandidateRelease::ReleaseOriginal, "mqtt direction filter should keep original");
    expect(decision.validation_label == "mqtt-direction-filter", "mqtt direction filter label mismatch");
}

void test_mqtt_review_threshold_creates_action_item() {
    MutationConfig config;
    config.replacement_text = "patched-payload";
    config.mqtt_review_threshold_bytes = 4;
    PluginRegistry registry(config);
    FlowContext flow;
    flow.flow_id = 13;
    flow.preferred_plugin = "mqtt";

    ByteVec packet = mqtt_publish_packet("topic", "hello");
    const ProtocolPlugin* plugin = registry.match(flow, Direction::ClientToServer, 1883, packet);
    FramingResult framed = plugin->frame(flow, Direction::ClientToServer, packet);
    Candidate candidate = plugin->build_candidate(flow, Direction::ClientToServer, framed.frame_bytes, &framed);
    CandidateDecision decision = plugin->decide(flow, Direction::ClientToServer, candidate);
    expect(decision.release == CandidateRelease::ReleaseModified, "mqtt threshold should keep safe modified release");
    expect(decision.review_required, "mqtt threshold should require review");
    expect(decision.create_action_item, "mqtt threshold should create action item");
}

void test_pid_search_parser_extracts_tcp_entries() {
    const std::string listing =
        "p111\n"
        "cPython\n"
        "u501\n"
        "f10\n"
        "tIPv4\n"
        "n127.0.0.1:1883\n"
        "TST=LISTEN\n"
        "f11\n"
        "tIPv4\n"
        "n127.0.0.1:1883->127.0.0.1:62000\n"
        "TST=ESTABLISHED\n"
        "p222\n"
        "cMqttWorker\n"
        "u501\n"
        "f6\n"
        "tIPv4\n"
        "n192.168.1.2:62000->127.0.0.1:1883\n"
        "TST=ESTABLISHED\n";

    const auto entries = parse_lsof_tcp_listing(listing);
    expect(entries.size() == 2, "expected two parsed processes");
    expect(entries[0].pid == 111, "expected first pid");
    expect(entries[0].command == "Python", "expected first command");
    expect(entries[0].sockets.size() == 2, "expected two sockets for first process");
    expect(entries[0].sockets[0].is_listen, "expected listen socket");
    expect(entries[0].sockets[0].local_port == 1883, "expected listen port");
    expect(entries[0].sockets[1].has_remote, "expected remote endpoint");
    expect(entries[0].sockets[1].remote_port == 62000, "expected remote port");
}

void test_pid_search_filters_by_process_and_port() {
    const std::string listing =
        "p111\n"
        "cPython\n"
        "u501\n"
        "f10\n"
        "tIPv4\n"
        "n127.0.0.1:1883\n"
        "TST=LISTEN\n"
        "p222\n"
        "cMqttWorker\n"
        "u501\n"
        "f6\n"
        "tIPv4\n"
        "n192.168.1.2:62000->127.0.0.1:1883\n"
        "TST=ESTABLISHED\n";

    PidSearchQuery query;
    query.process_contains = "mqtt";
    query.port = 1883;
    query.established_only = true;

    const auto filtered = filter_process_sockets(parse_lsof_tcp_listing(listing), query);
    expect(filtered.size() == 1, "expected one filtered process");
    expect(filtered[0].pid == 222, "expected mqtt worker pid");
    expect(filtered[0].sockets.size() == 1, "expected one matching socket");
    expect(filtered[0].sockets[0].state == "ESTABLISHED", "expected established socket");
}

void test_pid_search_json_contains_core_fields() {
    ProcessSocketEntry process;
    process.pid = 3860;
    process.command = "ollama";
    process.user = "501";

    TcpSocketEntry socket;
    socket.file_descriptor = "4";
    socket.address_family = "IPv4";
    socket.endpoint = "127.0.0.1:11434";
    socket.state = "LISTEN";
    socket.local_port = 11434;
    socket.remote_port = -1;
    socket.has_remote = false;
    socket.is_listen = true;
    process.sockets.push_back(socket);

    const std::string json = process_sockets_to_json({process});
    expect(json.find("\"pid\": 3860") != std::string::npos, "expected pid field in json");
    expect(json.find("\"command\": \"ollama\"") != std::string::npos, "expected command field in json");
    expect(json.find("\"endpoint\": \"127.0.0.1:11434\"") != std::string::npos, "expected endpoint field in json");
    expect(json.find("\"is_listen\": true") != std::string::npos, "expected listen field in json");
}

void test_target_profile_save_and_load() {
    const std::string path = "/tmp/ghostline_target_profile_test.json";
    TargetProfile profile;
    profile.label = "ollama-local";
    profile.query.process_contains = "ollama";
    profile.query.port = 11434;
    profile.query.listen_only = true;
    profile.transport = "serial-pair";
    profile.serial_ingress_device = "COM5";
    profile.serial_device = "COM6";
    profile.ingress_baud = 57600;
    profile.baud = 115200;
    profile.protocol_hint = "mqtt";
    profile.expect_connack = true;
    profile.capture_path = "field.glcap";

    ProcessSocketEntry match;
    match.pid = 3860;
    match.command = "ollama";
    profile.matches.push_back(match);

    save_target_profile(path, profile);
    TargetProfile loaded = load_target_profile(path);
    expect(loaded.label == "ollama-local", "expected target profile label");
    expect(loaded.query.process_contains == "ollama", "expected process query");
    expect(loaded.query.port == 11434, "expected port query");
    expect(loaded.query.listen_only, "expected listen flag");
    expect(loaded.transport == "serial-pair", "expected profile transport");
    expect(loaded.serial_ingress_device == "COM5" && loaded.serial_device == "COM6",
           "expected com0com endpoints");
    expect(loaded.ingress_baud == 57600 && loaded.baud == 115200,
           "expected profile baud rates");
    expect(loaded.expect_connack && loaded.protocol_hint == "mqtt",
           "expected mqtt connack profile state");
}

void test_default_protocol_target_profiles_cover_mq_family() {
    const auto profiles = default_protocol_target_profiles();
    expect(profiles.size() == 8, "expected protocol and field-I/O target profiles");

    bool saw_mqtt = false;
    bool saw_rmq = false;
    bool saw_amqp = false;
    bool saw_activemq = false;
    bool saw_asb = false;
    bool saw_kafka = false;
    bool saw_com0com = false;
    bool saw_field_serial = false;

    for (const auto& profile : profiles) {
        if (profile.label == "mqtt-broker" && profile.query.port == 1883) saw_mqtt = true;
        if (profile.label == "rabbitmq-rmq" && profile.query.port == 5672) saw_rmq = true;
        if (profile.label == "amqp-generic" && profile.query.port == 5672) saw_amqp = true;
        if (profile.label == "activemq-broker" && profile.query.port == 61616) saw_activemq = true;
        if (profile.label == "azure-service-bus" && profile.query.port == 5671) saw_asb = true;
        if (profile.label == "kafka-broker" && profile.query.port == 9092) saw_kafka = true;
        if (profile.label == "com0com-serial-pair" &&
            profile.serial_ingress_device == "COM5" && profile.baud == 115200) saw_com0com = true;
        if (profile.label == "field-serial-console" &&
            profile.transport == "tcp-serial" && profile.listen_port == 17777) saw_field_serial = true;
    }

    expect(saw_mqtt, "missing mqtt profile");
    expect(saw_rmq, "missing rabbitmq profile");
    expect(saw_amqp, "missing amqp profile");
    expect(saw_activemq, "missing activemq profile");
    expect(saw_asb, "missing azure service bus profile");
    expect(saw_kafka, "missing kafka profile");
    expect(saw_com0com, "missing com0com serial profile");
    expect(saw_field_serial, "missing field serial profile");
}

void test_micro_capture_connack_hex_and_pcap() {
    const std::string capture_path = "/tmp/ghostline_micro_capture_test.glcap";
    const std::string pcap_path = "/tmp/ghostline_micro_capture_test.pcap";
    std::filesystem::remove(capture_path);
    std::filesystem::remove(pcap_path);

    const ByteVec connack{0x20, 0x02, 0x00, 0x00};
    const auto summary = mqtt_packet_summary(Direction::ServerToClient, connack);
    expect(summary.find("MQTT CONNACK") != std::string::npos,
           "expected CONNACK packet summary");
    expect(summary.find("reason=success") != std::string::npos,
           "expected CONNACK reason decoding");
    expect(capture_hex_dump(bytes_from_ascii("AB")).find("41 42") != std::string::npos,
           "expected terminal hex dump");

    {
        CaptureConfig config;
        config.stream_path = capture_path;
        config.pcap_path = pcap_path;
        config.max_bytes = 128;
        config.snaplen = 64;
        config.expect_mqtt_connack = true;
        MicroCapture capture(config);
        capture.record(7, Direction::ServerToClient, "tcp", "mqtt", connack);
        expect(capture.connack_seen(), "expected capture CONNACK state");
        expect(capture.captured_bytes() == connack.size(), "expected capture byte accounting");
    }

    expect(std::filesystem::file_size(pcap_path) > 24,
           "expected DLT_USER0 pcap records");
    std::ostringstream rendered;
    std::string error;
    expect(render_capture_file(capture_path, rendered, 0, &error),
           "expected readable GLCAP1 capture");
    expect(rendered.str().find("MQTT CONNACK") != std::string::npos &&
           rendered.str().find("20 02 00 00") != std::string::npos,
           "expected CONNACK terminal capture rendering");
}

void test_review_queue_save_update_and_replay() {
    const std::string queue_dir = "/tmp/ghostline_review_queue_test";
    const std::string replay_dir = "/tmp/ghostline_review_replay_test";
    std::filesystem::remove_all(queue_dir);
    std::filesystem::remove_all(replay_dir);

    ActionItem item;
    item.action_id = "action-1-3";
    item.trigger_id = "trigger-1";
    item.candidate_id = "candidate-1";
    item.flow_id = 1;
    item.plugin_name = "mqtt";
    item.title = "Review mqtt mutation";
    item.detail = "Needs approval";
    item.original_hex = "aa";
    item.modified_hex = "bb";
    item.created_at_ns = 123;
    save_review_item(queue_dir, item);

    const auto items = list_review_items(queue_dir);
    expect(items.size() == 1, "expected one review item");
    expect(items[0].review_status == "pending", "expected pending status");

    update_review_item(queue_dir, "action-1-3", "approved", "looks good");
    ActionItem approved = load_review_item(queue_dir + "/action-1-3.json");
    expect(approved.review_status == "approved", "expected approved status");
    expect(approved.decision_note == "looks good", "expected approval note");

    const std::string replay_path = replay_review_item(queue_dir, "action-1-3", replay_dir, "replay now");
    expect(std::filesystem::exists(replay_path), "expected replay artifact");
    ActionItem replayed = load_review_item(queue_dir + "/action-1-3.json");
    expect(replayed.review_status == "replayed", "expected replayed status");
    expect(replayed.replay_count == 1, "expected replay count");
}

} // namespace

int main() {
    try {
        test_byte_window_plugin_releases_modified();
        test_observation_plugin_stays_passive();
        test_amqp_observation_plugin_frames_protocol_and_method_frames();
        test_kafka_observation_plugin_frames_length_prefix();
        test_amqp10_observation_plugin_frames_performative();
        test_size_mutation_requires_safe_rewrite();
        test_protocol_hint_selects_requested_plugin();
        test_all_named_plugins_are_registered();
        test_raw_live_mutation_releases_modified();
        test_raw_live_size_change_can_force_review();
        test_raw_live_direction_filter_keeps_original();
        test_raw_live_review_threshold_creates_action_item();
        test_mqtt_publish_mutation_reframes_remaining_length();
        test_mqtt_incomplete_frame_needs_more_bytes();
        test_mqtt_invalid_remaining_length_fails_framing();
        test_mqtt_direction_filter_keeps_original_publish();
        test_mqtt_review_threshold_creates_action_item();
        test_pid_search_parser_extracts_tcp_entries();
        test_pid_search_filters_by_process_and_port();
        test_pid_search_json_contains_core_fields();
        test_target_profile_save_and_load();
        test_default_protocol_target_profiles_cover_mq_family();
        test_micro_capture_connack_hex_and_pcap();
        test_review_queue_save_update_and_replay();
    } catch (const std::exception& error) {
        std::cerr << "ghostline_tests failed: " << error.what() << "\n";
        return EXIT_FAILURE;
    }

    std::cout << "ghostline_tests passed\n";
    return EXIT_SUCCESS;
}
