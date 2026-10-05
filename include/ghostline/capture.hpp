#pragma once

#include "core/types.hpp"
#include "ghostline/model.hpp"

#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iosfwd>
#include <string>

struct CaptureConfig {
    std::string stream_path;
    std::string pcap_path;
    std::size_t max_bytes = 4U * 1024U * 1024U;
    std::size_t snaplen = 1024;
    bool print_hex = false;
    bool expect_mqtt_connack = false;
};

std::string capture_hex_dump(const ByteVec& bytes, std::size_t width = 16);
std::string capture_ascii(const ByteVec& bytes);
std::string mqtt_packet_summary(Direction direction, const ByteVec& bytes);

class MicroCapture {
public:
    explicit MicroCapture(CaptureConfig config);

    bool enabled() const;
    bool connack_seen() const { return connack_seen_; }
    std::size_t captured_bytes() const { return captured_bytes_; }
    bool limit_reached() const { return limit_reached_; }

    void record(std::uint32_t flow_id,
                Direction direction,
                const std::string& transport,
                const std::string& protocol_hint,
                const ByteVec& bytes);

private:
    void ensure_stream_header();
    void ensure_pcap_header();

    CaptureConfig config_;
    std::ofstream stream_;
    std::ofstream pcap_;
    std::size_t captured_bytes_ = 0;
    bool stream_header_written_ = false;
    bool pcap_header_written_ = false;
    bool connack_seen_ = false;
    bool limit_reached_ = false;
};

bool render_capture_file(const std::string& path,
                         std::ostream& out,
                         std::size_t tail_records = 0,
                         std::string* error = nullptr);
