#pragma once

#include "ghostline/model.hpp"
#include "ghostline/pid_search.hpp"

#include <string>
#include <vector>

struct TargetProfile {
    std::string label;
    PidSearchQuery query;
    std::vector<ProcessSocketEntry> matches;
    std::string transport = "tcp";
    std::string listen_host = "127.0.0.1";
    std::int32_t listen_port = 7777;
    std::string upstream_host = "127.0.0.1";
    std::int32_t upstream_port = 8888;
    std::string serial_ingress_device;
    std::string serial_device;
    std::int32_t ingress_baud = 115200;
    std::int32_t baud = 115200;
    std::int32_t data_bits = 8;
    std::int32_t stop_bits = 1;
    std::string parity = "none";
    std::string flow_control = "none";
    std::string protocol_hint;
    bool observe_only = true;
    bool expect_connack = false;
    std::string capture_path;
    std::string capture_pcap_path;
    std::size_t capture_max_bytes = 4U * 1024U * 1024U;
    std::size_t capture_snaplen = 1024;
};

std::string bytes_to_hex_string(const ByteVec& bytes);

void save_target_profile(const std::string& path, const TargetProfile& profile);
TargetProfile load_target_profile(const std::string& path);
std::vector<std::string> list_target_profiles(const std::string& directory);
std::string target_profile_to_json(const TargetProfile& profile);
std::vector<TargetProfile> default_protocol_target_profiles();
std::vector<std::string> seed_protocol_target_profiles(const std::string& directory);

void save_review_item(const std::string& queue_dir, const ActionItem& item);
ActionItem load_review_item(const std::string& path);
std::vector<ActionItem> list_review_items(const std::string& queue_dir);
void update_review_item(const std::string& queue_dir,
                        const std::string& action_id,
                        const std::string& status,
                        const std::string& decision_note);
std::string replay_review_item(const std::string& queue_dir,
                               const std::string& action_id,
                               const std::string& replay_dir,
                               const std::string& decision_note);
