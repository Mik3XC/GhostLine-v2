#pragma once

#include "ghostline/audit.hpp"
#include "ghostline/plugin.hpp"
#include <cstddef>
#include <cstdint>
#include <string>

struct ProxyConfig {
    std::string listen_host = "127.0.0.1";
    uint16_t listen_port = 7777;

    std::string upstream_host = "127.0.0.1";
    uint16_t upstream_port = 8888;

    std::size_t max_chunk = 64 * 1024;
    std::size_t max_inspect_bytes = 64 * 1024;
    std::size_t max_plugin_buffer_bytes = 256 * 1024;

    std::string start_marker_hex;
    std::string end_marker_hex;
    std::string replacement_text;
    std::string raw_find_text;
    bool allow_size_mutation = true;
    bool rewrite_u32_prefix = false;
    bool raw_live_mode = false;
    std::size_t raw_chunk_bytes = 1024;
    bool mutate_client_to_server = true;
    bool mutate_server_to_client = true;
    std::size_t raw_review_threshold_bytes = 0;
    std::size_t mqtt_review_threshold_bytes = 0;
    std::size_t byte_window_review_threshold_bytes = 0;
    std::string protocol_hint;
    bool observe_only = false;

    std::string serial_device;
    std::string serial_ingress_device;
    int baud = 115200;
    int ingress_baud = 115200;
    int data_bits = 8;
    int stop_bits = 1;
    std::string parity = "none";
    std::string flow_control = "none";

    std::string capture_path;
    std::string capture_pcap_path;
    std::size_t capture_max_bytes = 4U * 1024U * 1024U;
    std::size_t capture_snaplen = 1024;
    bool capture_hex = false;
    bool expect_mqtt_connack = false;

    std::string trace_text;
    std::string trace_hex;
    bool cut_on_trace = false;
    bool trace_client_to_server = true;
    bool trace_server_to_client = true;

    std::string audit_log_path = "ghostline_audit.log";
    std::string action_log_path = "ghostline_actions.log";
    std::string audit_json_path;
    std::string action_json_path;
    std::string review_queue_dir = "ghostline_review_queue";
};

int run_transport_core(const ProxyConfig& cfg);
int run_serial_bridge(const ProxyConfig& cfg);
