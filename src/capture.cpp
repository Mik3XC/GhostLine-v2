#include "ghostline/capture.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <vector>

namespace {

std::uint64_t wall_clock_ns() {
    using namespace std::chrono;
    return static_cast<std::uint64_t>(
        duration_cast<nanoseconds>(system_clock::now().time_since_epoch()).count());
}

std::string direction_name(Direction direction) {
    return direction == Direction::ClientToServer ? "c2s" : "s2c";
}

std::string clean_field(std::string value) {
    std::replace(value.begin(), value.end(), '\t', ' ');
    std::replace(value.begin(), value.end(), '\r', ' ');
    std::replace(value.begin(), value.end(), '\n', ' ');
    return value;
}

void ensure_parent(const std::string& path) {
    const std::filesystem::path target(path);
    if (target.has_parent_path()) {
        std::filesystem::create_directories(target.parent_path());
    }
}

void write_u16_le(std::ostream& out, std::uint16_t value) {
    const std::array<char, 2> bytes{{
        static_cast<char>(value & 0xffU),
        static_cast<char>((value >> 8U) & 0xffU)}};
    out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
}

void write_u32_le(std::ostream& out, std::uint32_t value) {
    const std::array<char, 4> bytes{{
        static_cast<char>(value & 0xffU),
        static_cast<char>((value >> 8U) & 0xffU),
        static_cast<char>((value >> 16U) & 0xffU),
        static_cast<char>((value >> 24U) & 0xffU)}};
    out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
}

void append_u32_be(ByteVec& output, std::uint32_t value) {
    output.push_back(static_cast<byte>((value >> 24U) & 0xffU));
    output.push_back(static_cast<byte>((value >> 16U) & 0xffU));
    output.push_back(static_cast<byte>((value >> 8U) & 0xffU));
    output.push_back(static_cast<byte>(value & 0xffU));
}

std::string mqtt_type_name(byte type) {
    static const std::array<const char*, 16> names{{
        "RESERVED", "CONNECT", "CONNACK", "PUBLISH", "PUBACK", "PUBREC",
        "PUBREL", "PUBCOMP", "SUBSCRIBE", "SUBACK", "UNSUBSCRIBE",
        "UNSUBACK", "PINGREQ", "PINGRESP", "DISCONNECT", "AUTH"}};
    return names[type & 0x0fU];
}

bool decode_remaining_length(const ByteVec& bytes,
                             std::size_t& header_bytes,
                             std::size_t& remaining_length) {
    if (bytes.size() < 2) return false;
    std::size_t multiplier = 1;
    std::size_t value = 0;
    std::size_t index = 1;
    for (int count = 0; count < 4; ++count) {
        if (index >= bytes.size()) return false;
        const byte encoded = bytes[index++];
        value += static_cast<std::size_t>(encoded & 0x7fU) * multiplier;
        if ((encoded & 0x80U) == 0) {
            header_bytes = index;
            remaining_length = value;
            return true;
        }
        multiplier *= 128;
    }
    return false;
}

std::string connack_reason(byte reason) {
    switch (reason) {
        case 0x00: return "success";
        case 0x80: return "unspecified-error";
        case 0x81: return "malformed-packet";
        case 0x82: return "protocol-error";
        case 0x83: return "implementation-specific-error";
        case 0x84: return "unsupported-protocol-version";
        case 0x85: return "client-identifier-not-valid";
        case 0x86: return "bad-user-name-or-password";
        case 0x87: return "not-authorized";
        case 0x88: return "server-unavailable";
        case 0x89: return "server-busy";
        case 0x8a: return "banned";
        case 0x8c: return "bad-authentication-method";
        case 0x95: return "packet-too-large";
        case 0x97: return "quota-exceeded";
        default: return "reason-0x" + [&]() {
            std::ostringstream out;
            out << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<unsigned>(reason);
            return out.str();
        }();
    }
}

std::vector<std::string> split_tabs(const std::string& line) {
    std::vector<std::string> fields;
    std::size_t offset = 0;
    while (offset <= line.size()) {
        const auto delimiter = line.find('\t', offset);
        if (delimiter == std::string::npos) {
            fields.push_back(line.substr(offset));
            break;
        }
        fields.push_back(line.substr(offset, delimiter - offset));
        offset = delimiter + 1;
    }
    return fields;
}

ByteVec decode_hex(const std::string& text) {
    ByteVec bytes;
    if (text.size() % 2 != 0) return bytes;
    auto nibble = [](char ch) -> int {
        if (ch >= '0' && ch <= '9') return ch - '0';
        if (ch >= 'a' && ch <= 'f') return 10 + ch - 'a';
        if (ch >= 'A' && ch <= 'F') return 10 + ch - 'A';
        return -1;
    };
    for (std::size_t index = 0; index < text.size(); index += 2) {
        const int high = nibble(text[index]);
        const int low = nibble(text[index + 1]);
        if (high < 0 || low < 0) return {};
        bytes.push_back(static_cast<byte>((high << 4) | low));
    }
    return bytes;
}

} // namespace

std::string capture_ascii(const ByteVec& bytes) {
    std::string output;
    output.reserve(bytes.size());
    for (const byte value : bytes) {
        output.push_back(std::isprint(static_cast<unsigned char>(value)) && value != '\t'
            ? static_cast<char>(value) : '.');
    }
    return output;
}

std::string capture_hex_dump(const ByteVec& bytes, const std::size_t width) {
    std::ostringstream output;
    const std::size_t row_width = std::max<std::size_t>(1, width);
    for (std::size_t offset = 0; offset < bytes.size(); offset += row_width) {
        output << std::hex << std::setfill('0') << std::setw(6) << offset << "  ";
        const auto end = std::min(bytes.size(), offset + row_width);
        for (std::size_t index = offset; index < offset + row_width; ++index) {
            if (index < end) output << std::setw(2) << static_cast<unsigned>(bytes[index]) << ' ';
            else output << "   ";
        }
        output << " |";
        for (std::size_t index = offset; index < end; ++index) {
            const auto value = bytes[index];
            output << (std::isprint(static_cast<unsigned char>(value))
                ? static_cast<char>(value) : '.');
        }
        output << "|\n";
    }
    return output.str();
}

std::string mqtt_packet_summary(Direction direction, const ByteVec& bytes) {
    if (bytes.empty()) return {};
    const byte type = static_cast<byte>((bytes[0] >> 4U) & 0x0fU);
    if (type == 0) return {};
    std::size_t header_bytes = 0;
    std::size_t remaining_length = 0;
    if (!decode_remaining_length(bytes, header_bytes, remaining_length)) {
        return "MQTT " + mqtt_type_name(type) + " partial";
    }
    std::ostringstream summary;
    summary << "MQTT " << mqtt_type_name(type) << " "
            << (direction == Direction::ClientToServer ? "client->server" : "server->client")
            << " remaining=" << remaining_length;
    if (type == 2 && remaining_length >= 2 && bytes.size() >= header_bytes + 2) {
        const byte flags = bytes[header_bytes];
        const byte reason = bytes[header_bytes + 1];
        summary << " session-present=" << ((flags & 0x01U) ? "yes" : "no")
                << " reason=" << connack_reason(reason);
    }
    return summary.str();
}

MicroCapture::MicroCapture(CaptureConfig config) : config_(std::move(config)) {
    config_.snaplen = std::max<std::size_t>(1, config_.snaplen);
    config_.max_bytes = std::max<std::size_t>(1, config_.max_bytes);
    if (!config_.stream_path.empty()) {
        ensure_parent(config_.stream_path);
        stream_.open(config_.stream_path, std::ios::out | std::ios::trunc);
    }
    if (!config_.pcap_path.empty()) {
        ensure_parent(config_.pcap_path);
        pcap_.open(config_.pcap_path,
                   std::ios::out | std::ios::binary | std::ios::trunc);
        pcap_header_written_ = false;
    }
}

bool MicroCapture::enabled() const {
    return stream_.is_open() || pcap_.is_open() || config_.print_hex;
}

void MicroCapture::ensure_stream_header() {
    if (!stream_.is_open() || stream_header_written_) return;
    if (stream_.tellp() == 0) {
        stream_ << "# GLCAP1\tunix_ns\tflow\tdirection\ttransport\tbytes\tsummary\thex\tascii\n";
    }
    stream_header_written_ = true;
}

void MicroCapture::ensure_pcap_header() {
    if (!pcap_.is_open() || pcap_header_written_) return;
    write_u32_le(pcap_, 0xa1b2c3d4U);
    write_u16_le(pcap_, 2);
    write_u16_le(pcap_, 4);
    write_u32_le(pcap_, 0);
    write_u32_le(pcap_, 0);
    write_u32_le(pcap_, static_cast<std::uint32_t>(config_.snaplen + 12));
    write_u32_le(pcap_, 147); // DLT_USER0 / LINKTYPE_USER0
    pcap_header_written_ = true;
}

void MicroCapture::record(const std::uint32_t flow_id,
                          const Direction direction,
                          const std::string& transport,
                          const std::string& protocol_hint,
                          const ByteVec& bytes) {
    if (!enabled() || bytes.empty() || limit_reached_) return;
    const auto remaining_budget = config_.max_bytes - captured_bytes_;
    const auto stored_size = std::min({bytes.size(), config_.snaplen, remaining_budget});
    if (stored_size == 0) {
        limit_reached_ = true;
        return;
    }
    const ByteVec stored(bytes.begin(), bytes.begin() + static_cast<long>(stored_size));
    captured_bytes_ += stored_size;
    limit_reached_ = captured_bytes_ >= config_.max_bytes;
    const auto timestamp = wall_clock_ns();
    const bool mqtt_hint = protocol_hint == "mqtt" || config_.expect_mqtt_connack;
    std::string summary = mqtt_hint ? mqtt_packet_summary(direction, stored) : std::string();
    if (summary.empty()) summary = transport + " stream payload";
    if (summary.find("MQTT CONNACK") != std::string::npos) connack_seen_ = true;
    if (stored_size < bytes.size()) summary += " [snaplen/budget truncated]";

    static const char* hex_chars = "0123456789abcdef";
    std::string compact_hex;
    compact_hex.reserve(stored.size() * 2);
    for (const byte value : stored) {
        compact_hex.push_back(hex_chars[(value >> 4U) & 0x0fU]);
        compact_hex.push_back(hex_chars[value & 0x0fU]);
    }

    if (stream_.is_open()) {
        ensure_stream_header();
        stream_ << "GLCAP1\t" << timestamp << '\t' << flow_id << '\t'
                << direction_name(direction) << '\t' << clean_field(transport) << '\t'
                << bytes.size() << '\t' << clean_field(summary) << '\t'
                << compact_hex << '\t' << capture_ascii(stored) << '\n';
        stream_.flush();
    }

    if (pcap_.is_open()) {
        ensure_pcap_header();
        ByteVec packet{'G', 'L', 'C', '1', 1,
            static_cast<byte>(transport == "serial" ? 2 : 1),
            static_cast<byte>(direction == Direction::ClientToServer ? 0 : 1), 0};
        append_u32_be(packet, flow_id);
        packet.insert(packet.end(), stored.begin(), stored.end());
        const auto seconds = static_cast<std::uint32_t>(timestamp / 1000000000ULL);
        const auto microseconds = static_cast<std::uint32_t>((timestamp / 1000ULL) % 1000000ULL);
        write_u32_le(pcap_, seconds);
        write_u32_le(pcap_, microseconds);
        write_u32_le(pcap_, static_cast<std::uint32_t>(packet.size()));
        write_u32_le(pcap_, static_cast<std::uint32_t>(12 + bytes.size()));
        pcap_.write(reinterpret_cast<const char*>(packet.data()),
                    static_cast<std::streamsize>(packet.size()));
        pcap_.flush();
    }

    if (config_.print_hex) {
        std::cout << "[CAPTURE] flow=" << flow_id << " dir=" << direction_name(direction)
                  << " transport=" << transport << " bytes=" << bytes.size()
                  << " // " << summary << '\n' << capture_hex_dump(stored);
    }
}

bool render_capture_file(const std::string& path,
                         std::ostream& out,
                         const std::size_t tail_records,
                         std::string* error) {
    std::ifstream input(path);
    if (!input) {
        if (error) *error = "could not open capture " + path;
        return false;
    }
    std::vector<std::string> records;
    std::string line;
    while (std::getline(input, line)) {
        if (line.rfind("GLCAP1\t", 0) == 0) records.push_back(line);
    }
    const auto first = tail_records > 0 && records.size() > tail_records
        ? records.size() - tail_records : 0;
    for (std::size_t index = first; index < records.size(); ++index) {
        const auto fields = split_tabs(records[index]);
        if (fields.size() < 9) continue;
        const ByteVec bytes = decode_hex(fields[7]);
        out << fields[1] << "  FLOW " << fields[2] << "  " << fields[3]
            << "  " << fields[4] << "  " << fields[5] << " BYTES\n"
            << fields[6] << '\n' << capture_hex_dump(bytes) << '\n';
    }
    if (records.empty()) {
        if (error) *error = "capture contains no GLCAP1 records";
        return false;
    }
    return true;
}
