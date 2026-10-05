#include "ghostline/operator_state.hpp"

#include <algorithm>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <deque>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <poll.h>
#include <sstream>
#include <string>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>
#include <vector>

namespace {

volatile std::sig_atomic_t resized = 0;

void on_resize(int) {
    resized = 1;
}

std::string trim(std::string value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return {};
    const auto last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

std::string shorten(const std::string& value, const std::size_t width) {
    if (value.size() <= width) return value;
    if (width < 2) return value.substr(0, width);
    return value.substr(0, width - 1) + "~";
}

std::string home_path() {
    const char* home = std::getenv("HOME");
    return home == nullptr ? ".ghostline-shell.state"
                           : std::string(home) + "/.config/ghostline/shell.state";
}

struct ShellConfig {
    std::string audit_path = "ghostline_audit.log";
    std::string action_path = "ghostline_actions.log";
    std::string review_dir = "ghostline_review_queue";
    std::string profile_dir = "ghostline_target_profiles";
    std::string filter;
    std::string state_path = home_path();
    int refresh_ms = 250;
    bool use_state = true;
};

void load_state(ShellConfig& config) {
    if (!config.use_state) return;
    std::ifstream input(config.state_path);
    std::string line;
    while (std::getline(input, line)) {
        const auto split = line.find('=');
        if (split == std::string::npos) continue;
        const std::string key = line.substr(0, split);
        const std::string value = line.substr(split + 1);
        if (key == "audit") config.audit_path = value;
        else if (key == "actions") config.action_path = value;
        else if (key == "reviews") config.review_dir = value;
        else if (key == "profiles") config.profile_dir = value;
        else if (key == "filter") config.filter = value;
        else if (key == "refresh_ms") {
            try { config.refresh_ms = std::max(50, std::stoi(value)); } catch (...) {}
        }
    }
}

void save_state(const ShellConfig& config) {
    if (!config.use_state) return;
    const std::filesystem::path path(config.state_path);
    if (path.has_parent_path()) std::filesystem::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::trunc);
    if (!output) return;
    output << "audit=" << config.audit_path << '\n'
           << "actions=" << config.action_path << '\n'
           << "reviews=" << config.review_dir << '\n'
           << "profiles=" << config.profile_dir << '\n'
           << "filter=" << config.filter << '\n'
           << "refresh_ms=" << config.refresh_ms << '\n';
}

class TailFeed {
public:
    explicit TailFeed(std::size_t keep = 500) : keep_(keep) {}

    void set_path(std::string path) {
        path_ = std::move(path);
        offset_ = 0;
        lines_.clear();
    }

    const std::string& path() const { return path_; }
    const std::deque<std::string>& lines() const { return lines_; }

    void refresh() {
        if (path_.empty()) return;
        std::error_code error;
        const auto size = std::filesystem::file_size(path_, error);
        if (error) return;
        if (size < offset_) {
            offset_ = 0;
            lines_.clear();
        }
        std::ifstream input(path_);
        if (!input) return;
        input.seekg(static_cast<std::streamoff>(offset_));
        std::string line;
        while (std::getline(input, line)) {
            if (!line.empty()) {
                lines_.push_back(line);
                while (lines_.size() > keep_) lines_.pop_front();
            }
        }
        const auto pos = input.tellg();
        offset_ = pos < 0 ? size : static_cast<std::uintmax_t>(pos);
    }

private:
    std::string path_;
    std::uintmax_t offset_ = 0;
    std::size_t keep_;
    std::deque<std::string> lines_;
};

struct Metrics {
    std::size_t events = 0;
    std::size_t flows = 0;
    std::size_t modified = 0;
    std::size_t original = 0;
    std::size_t observe = 0;
    std::size_t containment = 0;
    std::size_t actions = 0;
};

std::string field(const std::string& line, const std::string& name) {
    const std::string marker = name + "=";
    const auto start = line.find(marker);
    if (start == std::string::npos) return {};
    const auto value_start = start + marker.size();
    if (value_start < line.size() && line[value_start] == '"') {
        const auto end = line.find('"', value_start + 1);
        return end == std::string::npos ? line.substr(value_start + 1)
                                        : line.substr(value_start + 1, end - value_start - 1);
    }
    const auto end = line.find(' ', value_start);
    return line.substr(value_start, end == std::string::npos ? end : end - value_start);
}

Metrics metrics_for(const TailFeed& audit, const TailFeed& actions) {
    Metrics metrics;
    std::map<std::string, bool> flows;
    for (const auto& line : audit.lines()) {
        ++metrics.events;
        const auto flow = field(line, "flow");
        if (!flow.empty()) flows[flow] = true;
        if (line.find("type=candidate ") != std::string::npos &&
            line.find("stage=released-modified") != std::string::npos) ++metrics.modified;
        if (line.find("type=candidate ") != std::string::npos &&
            line.find("stage=released-original") != std::string::npos) ++metrics.original;
        if (line.find("observe-transition") != std::string::npos) ++metrics.observe;
        if (line.find("containment") != std::string::npos ||
            line.find("stream-cut") != std::string::npos) ++metrics.containment;
    }
    metrics.flows = flows.size();
    metrics.actions = actions.lines().size();
    return metrics;
}

std::size_t json_file_count(const std::string& directory) {
    std::error_code error;
    if (!std::filesystem::is_directory(directory, error)) return 0;
    std::size_t count = 0;
    for (const auto& entry : std::filesystem::directory_iterator(directory, error)) {
        if (!error && entry.is_regular_file() && entry.path().extension() == ".json") ++count;
    }
    return count;
}

struct TerminalSize { int rows = 24; int cols = 100; };

TerminalSize terminal_size() {
    winsize value{};
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &value) == 0 && value.ws_row > 0 && value.ws_col > 0) {
        return {value.ws_row, value.ws_col};
    }
    return {};
}

class RawTerminal {
public:
    RawTerminal() {
        active_ = isatty(STDIN_FILENO) && tcgetattr(STDIN_FILENO, &saved_) == 0;
        if (!active_) return;
        termios raw = saved_;
        raw.c_lflag &= static_cast<unsigned long>(~(ICANON | ECHO));
        raw.c_cc[VMIN] = 0;
        raw.c_cc[VTIME] = 0;
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
        std::cout << "\033[?1049h\033[?25l";
    }

    ~RawTerminal() {
        if (!active_) return;
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &saved_);
        std::cout << "\033[?25h\033[?1049l" << std::flush;
    }

private:
    termios saved_{};
    bool active_ = false;
};

std::string event_summary(const std::string& line, const int width) {
    std::ostringstream output;
    const auto flow = field(line, "flow");
    auto dir = field(line, "dir");
    if (dir == "client_to_server") dir = "C2S";
    else if (dir == "server_to_client") dir = "S2C";
    else if (dir == "c2s") dir = "C2S";
    else if (dir == "s2c") dir = "S2C";
    const auto plugin = field(line, "plugin");
    const auto type = field(line, "type");
    const auto stage = field(line, "stage");
    output << std::setw(4) << (flow.empty() ? "-" : flow) << "  "
           << std::left << std::setw(4) << shorten(dir, 4) << " "
           << std::setw(13) << shorten(plugin, 13) << " "
           << std::setw(22) << shorten(type, 22) << " "
           << shorten(stage, 18);
    return shorten(output.str(), static_cast<std::size_t>(std::max(1, width)));
}

class Shell {
public:
    explicit Shell(ShellConfig config) : config_(std::move(config)) {
        audit_.set_path(config_.audit_path);
        actions_.set_path(config_.action_path);
    }

    void snapshot() {
        audit_.refresh();
        actions_.refresh();
        render(false);
    }

    int run() {
        if (!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO)) {
            std::cerr << "ghostline_shell requires a terminal; use --snapshot for redirected output\n";
            return 2;
        }
        std::signal(SIGWINCH, on_resize);
        RawTerminal terminal;
        while (running_) {
            if (!paused_) {
                audit_.refresh();
                actions_.refresh();
            }
            render(true);
            pollfd input{STDIN_FILENO, POLLIN, 0};
            if (::poll(&input, 1, config_.refresh_ms) > 0 && (input.revents & POLLIN)) {
                char buffer[64];
                const auto count = ::read(STDIN_FILENO, buffer, sizeof(buffer));
                for (ssize_t index = 0; index < count; ++index) handle_key(buffer[index]);
            }
        }
        save_state(config_);
        return 0;
    }

private:
    void command(const std::string& raw) {
        const std::string value = trim(raw);
        const auto split = value.find(' ');
        const std::string verb = value.substr(0, split);
        const std::string argument = split == std::string::npos ? "" : trim(value.substr(split + 1));
        if (verb == "q" || verb == "quit" || verb == "exit") running_ = false;
        else if (verb == "pause") { paused_ = true; status_ = "event feed paused"; }
        else if (verb == "resume") { paused_ = false; status_ = "event feed resumed"; }
        else if (verb == "filter") { config_.filter = argument; status_ = argument.empty() ? "filter cleared" : "filter=" + argument; }
        else if (verb == "audit" && !argument.empty()) { config_.audit_path = argument; audit_.set_path(argument); status_ = "audit=" + argument; }
        else if (verb == "actions" && !argument.empty()) { config_.action_path = argument; actions_.set_path(argument); status_ = "actions=" + argument; }
        else if (verb == "reviews" && !argument.empty()) { config_.review_dir = argument; status_ = "reviews=" + argument; }
        else if (verb == "profiles" && !argument.empty()) { config_.profile_dir = argument; status_ = "profiles=" + argument; }
        else if (verb == "save") { save_state(config_); status_ = "settings saved"; }
        else if (verb == "clear") { audit_.set_path(config_.audit_path); actions_.set_path(config_.action_path); status_ = "local tape cleared"; }
        else if (verb == "help" || verb == "?") show_help_ = true;
        else status_ = value.empty() ? "" : "unknown command: " + verb;
        if (verb != "help" && verb != "?") save_state(config_);
    }

    void handle_key(char key) {
        if (show_help_) {
            show_help_ = false;
            return;
        }
        if (command_mode_) {
            if (key == 27) { command_mode_ = false; command_buffer_.clear(); }
            else if (key == '\r' || key == '\n') {
                command_mode_ = false;
                command(command_buffer_);
                command_buffer_.clear();
            } else if (key == 127 || key == 8) {
                if (!command_buffer_.empty()) command_buffer_.pop_back();
            } else if (key >= 32 && key < 127) command_buffer_.push_back(key);
            return;
        }
        if (key == 'q') running_ = false;
        else if (key == ':') command_mode_ = true;
        else if (key == '?' || key == 'h') show_help_ = true;
        else if (key == 'p' || key == ' ') paused_ = !paused_;
        else if (key == 'r') { audit_.refresh(); actions_.refresh(); status_ = "refreshed"; }
    }

    void render(bool ansi) const {
        const auto size = terminal_size();
        const int width = std::max(60, size.cols);
        std::ostringstream output;
        if (ansi) output << "\033[H\033[2J";
        output << (ansi ? "\033[1;36m" : "") << "GHOSTLINE // TRANSPORT OPERATIONS"
               << (ansi ? "\033[0m" : "") << "  "
               << (ansi ? (paused_ ? "\033[33m" : "\033[32m") : "")
               << (paused_ ? "PAUSED" : "LIVE") << (ansi ? "\033[0m" : "")
               << "  original-first / one-release gate\n";
        output << std::string(static_cast<std::size_t>(width), '-') << '\n';

        const auto metrics = metrics_for(audit_, actions_);
        output << "FLOWS " << std::setw(4) << metrics.flows
               << "  EVENTS " << std::setw(5) << metrics.events
               << "  ORIGINAL " << std::setw(4) << metrics.original
               << "  MODIFIED " << std::setw(4) << metrics.modified
               << "  OBSERVE " << std::setw(4) << metrics.observe
               << "  CUT " << std::setw(3) << metrics.containment
               << "  ACTIONS " << std::setw(4) << metrics.actions << '\n';
        output << "REVIEWS " << json_file_count(config_.review_dir)
               << "  PROFILES " << json_file_count(config_.profile_dir)
               << "  FILTER " << (config_.filter.empty() ? "*" : config_.filter) << '\n';
        output << std::string(static_cast<std::size_t>(width), '-') << '\n';
        output << "PROTOCOL CAPABILITIES\n"
               << "  RAW/WINDOW  frame + candidate + validate     MQTT      frame + PUBLISH reframe\n"
               << "  RMQ 0-9-1   bounded frame + observe          AMQP 1.0  bounded frame + observe\n"
               << "  KAFKA       length frame + observe           ASB/TLS   opaque observe\n"
               << "  ACTIVEMQ    detect + observe\n";
        output << std::string(static_cast<std::size_t>(width), '-') << '\n';
        output << "FLOW  DIR  PLUGIN        EVENT                  STAGE\n";

        std::vector<std::string> visible;
        for (const auto& line : audit_.lines()) {
            if (config_.filter.empty() || line.find(config_.filter) != std::string::npos) visible.push_back(line);
        }
        const int fixed_rows = 13;
        const int event_rows = std::max(3, size.rows - fixed_rows);
        const std::size_t first = visible.size() > static_cast<std::size_t>(event_rows)
            ? visible.size() - static_cast<std::size_t>(event_rows) : 0;
        for (std::size_t index = first; index < visible.size(); ++index) {
            output << event_summary(visible[index], width) << '\n';
        }
        for (int row = static_cast<int>(visible.size() - first); row < event_rows; ++row) output << '\n';

        output << std::string(static_cast<std::size_t>(width), '-') << '\n';
        if (show_help_) {
            output << "q quit | p/space pause | r refresh | : command | any key closes help\n"
                   << ":filter TEXT | :audit PATH | :actions PATH | :reviews DIR | :profiles DIR | :save\n";
        } else if (command_mode_) {
            output << ":" << command_buffer_ << "\033[?25h";
        } else {
            output << (status_.empty() ? "Press : for commands, ? for help, q to quit" : status_);
        }
        if (ansi && !command_mode_) output << "\033[?25l";
        std::cout << output.str() << std::flush;
    }

    ShellConfig config_;
    TailFeed audit_;
    TailFeed actions_;
    bool running_ = true;
    bool paused_ = false;
    bool command_mode_ = false;
    bool show_help_ = false;
    std::string command_buffer_;
    std::string status_;
};

void help(const char* argv0) {
    std::cout
        << "Ghostline persistent terminal operator shell\n\n"
        << "Usage: " << argv0 << " [options]\n\n"
        << "  --audit PATH       Audit event log (default ghostline_audit.log)\n"
        << "  --actions PATH     Action log (default ghostline_actions.log)\n"
        << "  --reviews DIR      Review queue directory\n"
        << "  --profiles DIR     Target profile directory\n"
        << "  --filter TEXT      Initial event filter\n"
        << "  --refresh-ms N     Refresh period, minimum 50 ms\n"
        << "  --state PATH       Persistent shell settings path\n"
        << "  --no-state         Do not load or save settings\n"
        << "  --snapshot         Print one noninteractive dashboard snapshot\n"
        << "  -h, --help         Show this help\n\n"
        << "Keys: q quit, p/space pause, r refresh, : command, ? help\n";
}

} // namespace

int main(int argc, char** argv) {
    ShellConfig config;
    bool snapshot = false;
    bool explicit_audit = false;
    bool explicit_actions = false;
    bool explicit_reviews = false;
    bool explicit_profiles = false;
    bool explicit_filter = false;
    for (int index = 1; index < argc; ++index) {
        const std::string arg = argv[index];
        auto next = [&]() -> std::string {
            if (++index >= argc) throw std::runtime_error("missing value for " + arg);
            return argv[index];
        };
        try {
            if (arg == "-h" || arg == "--help") { help(argv[0]); return 0; }
            else if (arg == "--audit") { config.audit_path = next(); explicit_audit = true; }
            else if (arg == "--actions") { config.action_path = next(); explicit_actions = true; }
            else if (arg == "--reviews") { config.review_dir = next(); explicit_reviews = true; }
            else if (arg == "--profiles") { config.profile_dir = next(); explicit_profiles = true; }
            else if (arg == "--filter") { config.filter = next(); explicit_filter = true; }
            else if (arg == "--refresh-ms") config.refresh_ms = std::max(50, std::stoi(next()));
            else if (arg == "--state") config.state_path = next();
            else if (arg == "--no-state") config.use_state = false;
            else if (arg == "--snapshot") snapshot = true;
            else throw std::runtime_error("unknown option: " + arg);
        } catch (const std::exception& error) {
            std::cerr << "ghostline_shell: " << error.what() << '\n';
            return 2;
        }
    }

    const ShellConfig arguments = config;
    load_state(config);
    if (explicit_audit) config.audit_path = arguments.audit_path;
    if (explicit_actions) config.action_path = arguments.action_path;
    if (explicit_reviews) config.review_dir = arguments.review_dir;
    if (explicit_profiles) config.profile_dir = arguments.profile_dir;
    if (explicit_filter) config.filter = arguments.filter;

    Shell shell(config);
    if (snapshot) { shell.snapshot(); return 0; }
    return shell.run();
}
