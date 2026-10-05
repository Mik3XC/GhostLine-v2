#include "net/proxy.hpp"

#include "ghostline/capture.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>

#ifdef _WIN32

int run_serial_bridge(const ProxyConfig&) {
    std::cerr << "Ghostline serial bridge is not yet built on Windows. "
                 "The profile is com0com-compatible; use the POSIX field build "
                 "or the future Win32 serial backend.\n";
    return 2;
}

#else

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <termios.h>
#include <unistd.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

namespace {

speed_t baud_constant(int baud) {
    switch (baud) {
        case 300: return B300;
        case 1200: return B1200;
        case 2400: return B2400;
        case 4800: return B4800;
        case 9600: return B9600;
        case 19200: return B19200;
        case 38400: return B38400;
        case 57600: return B57600;
        case 115200: return B115200;
#ifdef B230400
        case 230400: return B230400;
#endif
#ifdef B460800
        case 460800: return B460800;
#endif
#ifdef B921600
        case 921600: return B921600;
#endif
        default: return 0;
    }
}

int open_serial(const std::string& path,
                int baud,
                const ProxyConfig& cfg,
                std::string& error) {
    const int fd = ::open(path.c_str(), O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (fd < 0) {
        error = "open " + path + " failed: " + std::strerror(errno);
        return -1;
    }
    termios options{};
    if (tcgetattr(fd, &options) != 0) {
        error = "tcgetattr " + path + " failed: " + std::strerror(errno);
        ::close(fd);
        return -1;
    }
    const auto speed = baud_constant(baud);
    if (speed == 0) {
        error = "unsupported baud " + std::to_string(baud);
        ::close(fd);
        return -1;
    }
    cfmakeraw(&options);
    options.c_cflag |= CLOCAL | CREAD;
    options.c_cflag &= ~HUPCL;
    options.c_cflag &= ~CSIZE;
    options.c_cflag |= cfg.data_bits == 7 ? CS7 : CS8;
    options.c_cflag &= ~(PARENB | PARODD);
    if (cfg.parity == "even") options.c_cflag |= PARENB;
    else if (cfg.parity == "odd") options.c_cflag |= PARENB | PARODD;
    if (cfg.stop_bits == 2) options.c_cflag |= CSTOPB;
    else options.c_cflag &= ~CSTOPB;
#ifdef CRTSCTS
    if (cfg.flow_control == "hardware") options.c_cflag |= CRTSCTS;
    else options.c_cflag &= ~CRTSCTS;
#endif
    if (cfg.flow_control == "xonxoff") options.c_iflag |= IXON | IXOFF;
    else options.c_iflag &= ~(IXON | IXOFF | IXANY);
    cfsetispeed(&options, speed);
    cfsetospeed(&options, speed);
    options.c_cc[VMIN] = 0;
    options.c_cc[VTIME] = 1;
    if (tcsetattr(fd, TCSANOW, &options) != 0) {
        error = "tcsetattr " + path + " failed: " + std::strerror(errno);
        ::close(fd);
        return -1;
    }
    return fd;
}

int create_listener(const std::string& host, std::uint16_t port) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    addrinfo* addresses = nullptr;
    const auto port_text = std::to_string(port);
    if (getaddrinfo(host.c_str(), port_text.c_str(), &hints, &addresses) != 0) return -1;
    int listener = -1;
    for (auto* address = addresses; address != nullptr; address = address->ai_next) {
        const int candidate = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
        if (candidate < 0) continue;
        const int yes = 1;
        setsockopt(candidate, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
        if (bind(candidate, address->ai_addr, address->ai_addrlen) == 0 &&
            listen(candidate, 4) == 0) {
            listener = candidate;
            break;
        }
        ::close(candidate);
    }
    freeaddrinfo(addresses);
    return listener;
}

bool write_all(int fd, const byte* data, std::size_t size, bool socket_peer) {
    std::size_t offset = 0;
    while (offset < size) {
        const ssize_t written = socket_peer
            ? ::send(fd, data + offset, size - offset, MSG_NOSIGNAL)
            : ::write(fd, data + offset, size - offset);
        if (written > 0) {
            offset += static_cast<std::size_t>(written);
            continue;
        }
        if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            pollfd output{fd, POLLOUT, 0};
            if (poll(&output, 1, 1000) > 0) continue;
        }
        return false;
    }
    return true;
}

int relay_pair(int ingress,
               bool ingress_socket,
               int upstream,
               const ProxyConfig& cfg,
               MicroCapture& capture,
               std::uint32_t flow_id) {
    std::array<byte, 4096> buffer{};
    while (true) {
        std::array<pollfd, 2> fds{{
            {ingress, POLLIN, 0},
            {upstream, POLLIN, 0}}};
        const int ready = poll(fds.data(), fds.size(), -1);
        if (ready < 0 && errno == EINTR) continue;
        if (ready <= 0) return 1;
        for (std::size_t index = 0; index < fds.size(); ++index) {
            if (fds[index].revents & (POLLERR | POLLHUP | POLLNVAL)) return 0;
            if (!(fds[index].revents & POLLIN)) continue;
            const ssize_t count = index == 0 && ingress_socket
                ? ::recv(fds[index].fd, buffer.data(), buffer.size(), 0)
                : ::read(fds[index].fd, buffer.data(), buffer.size());
            if (count == 0) return 0;
            if (count < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
                return 1;
            }
            const ByteVec bytes(buffer.begin(), buffer.begin() + count);
            const Direction direction = index == 0
                ? Direction::ClientToServer : Direction::ServerToClient;
            capture.record(flow_id, direction, "serial", cfg.protocol_hint, bytes);
            const int destination = index == 0 ? upstream : ingress;
            const bool destination_socket = index == 1 && ingress_socket;
            if (!write_all(destination, bytes.data(), bytes.size(), destination_socket)) return 1;
        }
    }
}

} // namespace

int run_serial_bridge(const ProxyConfig& cfg) {
    signal(SIGPIPE, SIG_IGN);
    if (cfg.serial_device.empty()) {
        std::cerr << "serial bridge requires --serial-device\n";
        return 2;
    }
    if (!cfg.serial_ingress_device.empty() && cfg.serial_ingress_device == cfg.serial_device) {
        std::cerr << "serial ingress and upstream device must differ\n";
        return 2;
    }
    std::string error;
    const int upstream = open_serial(cfg.serial_device, cfg.baud, cfg, error);
    if (upstream < 0) {
        std::cerr << error << '\n';
        return 1;
    }
    CaptureConfig capture_config;
    capture_config.stream_path = cfg.capture_path;
    capture_config.pcap_path = cfg.capture_pcap_path;
    capture_config.max_bytes = cfg.capture_max_bytes;
    capture_config.snaplen = cfg.capture_snaplen;
    capture_config.print_hex = cfg.capture_hex;
    capture_config.expect_mqtt_connack = cfg.expect_mqtt_connack;
    MicroCapture capture(capture_config);

    if (!cfg.serial_ingress_device.empty()) {
        const int ingress = open_serial(
            cfg.serial_ingress_device, cfg.ingress_baud, cfg, error);
        if (ingress < 0) {
            std::cerr << error << '\n';
            ::close(upstream);
            return 1;
        }
        std::cout << "Ghostline serial pair " << cfg.serial_ingress_device << " @ "
                  << cfg.ingress_baud << " <-> " << cfg.serial_device << " @ "
                  << cfg.baud << " // observe-only\n";
        const int result = relay_pair(ingress, false, upstream, cfg, capture, 1);
        ::close(ingress);
        ::close(upstream);
        return result;
    }

    const int listener = create_listener(cfg.listen_host, cfg.listen_port);
    if (listener < 0) {
        std::cerr << "could not bind serial bridge listener " << cfg.listen_host
                  << ':' << cfg.listen_port << '\n';
        ::close(upstream);
        return 1;
    }
    std::cout << "Ghostline TCP " << cfg.listen_host << ':' << cfg.listen_port
              << " <-> serial " << cfg.serial_device << " @ " << cfg.baud
              << " // observe-only\n";
    std::uint32_t flow_id = 1;
    while (true) {
        const int client = accept(listener, nullptr, nullptr);
        if (client < 0) {
            if (errno == EINTR) continue;
            break;
        }
        (void)relay_pair(client, true, upstream, cfg, capture, flow_id++);
        ::close(client);
    }
    ::close(listener);
    ::close(upstream);
    return 1;
}

#endif
