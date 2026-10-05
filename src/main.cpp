#include "net/proxy.hpp"
#include "ghostline/operator_state.hpp"
#include "ghostline/pid_search.hpp"
#include "ghostline/capture.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdlib>
#include <cstdio>
#include <filesystem>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

constexpr const char* kUsefulAnswers =
    "Useful answers:\n"
    "  How do I find a target process?\n"
    "    ghostline_cli --search-pid ollama\n"
    "    ghostline_cli --search-port 1883 --listen-only\n"
    "  How do I run raw live mutation?\n"
    "    ghostline_cli 7777 127.0.0.1 8888 --protocol-hint raw-live --raw-live --raw-find-text hello --replace-text patch\n"
    "  How do I run MQTT mutation?\n"
    "    ghostline_cli 7777 127.0.0.1 1883 --protocol-hint mqtt --replace-text patched-payload\n"
    "  How do I drive Ghostline from a file?\n"
    "    ghostline_cli 7777 127.0.0.1 8888 --rules examples/rules/raw-live.json\n"
    "  How do I get machine-readable streams?\n"
    "    ghostline_cli ... --audit-json ghostline_audit.jsonl --actions-json ghostline_actions.jsonl\n"
    "  How do I save a target profile?\n"
    "    ghostline_cli --seed-target-profiles ghostline_target_profiles\n"
    "    ghostline_cli --search-pid ollama --save-target-profile ghostline_target_profiles/ollama.json --target-label ollama-local\n"
    "  How do I work the review queue?\n"
    "    ghostline_cli --review-list\n"
    "    ghostline_cli --review-approve action-1-2 --review-note approved\n"
    "    ghostline_cli --review-replay action-1-2 --review-note replay-now\n";

std::uint16_t to_u16(const char* value) {
    const long parsed = std::strtol(value, nullptr, 10);
    if (parsed < 1 || parsed > 65535) {
        throw std::runtime_error("port out of range");
    }
    return static_cast<std::uint16_t>(parsed);
}

void print_core_options(std::ostream& out) {
    out
        << "  --start-hex <hex>       Start marker for byte-window plugin\n"
        << "  --end-hex <hex>         End marker for byte-window plugin\n"
        << "  --replace-text <text>   Replacement body for matched windows\n"
        << "  --raw-find-text <text>  Find text for raw live stream mutation\n"
        << "  --raw-live              Enable protocol-agnostic live raw mutation\n"
        << "  --raw-chunk-bytes <n>   Frame raw live mutation in fixed-size chunks\n"
        << "  --mutate-direction <v>  Mutation direction: c2s, s2c, or both\n"
        << "  --raw-review-threshold <n>   Require review/action item for raw mutations at or above this byte size\n"
        << "  --mqtt-review-threshold <n>  Require review/action item for mqtt mutations at or above this payload size\n"
        << "  --byte-review-threshold <n>  Require review/action item for byte-window mutations at or above this payload size\n"
        << "  --rewrite-u32-prefix    Rewrite the leading 4-byte big-endian body size\n"
        << "  --max-plugin-buffer <n> Max bytes a protocol plugin may hold before fallback\n"
        << "  --protocol-hint <name>  Prefer a compiled-in plugin\n";
    out << "  --observe-only          Capture and audit; never release a modified candidate\n"
        << "  --trace-text <text>     Detect an exact byte trace across TCP read boundaries\n"
        << "  --trace-hex <hex>       Detect an exact hexadecimal byte trace\n"
        << "  --trace-direction <v>  Trace direction: c2s, s2c, or both\n"
        << "  --cut-on-trace         Close both flow directions after a trace match\n"
        << "  --listen-host <host>    Explicit local bind address\n"
        << "  --listen-port <port>    Explicit local TCP port (also TCP-to-serial ingress)\n"
        << "  --upstream-host <host>  Explicit upstream host without positional arguments\n"
        << "  --upstream-port <port>  Explicit upstream port without positional arguments\n";
}

void print_capture_options(std::ostream& out) {
    out << "  --capture <path>        Bounded GLCAP1 stream capture with summaries + payload hex\n"
        << "  --capture-pcap <path>   Wireshark-readable DLT_USER0 PCAP payload capture\n"
        << "  --capture-hex           Print micro-Wireshark hex/ASCII rows in the terminal\n"
        << "  --capture-max-bytes <n> Hard payload-byte ceiling (default 4194304)\n"
        << "  --capture-snaplen <n>   Maximum bytes retained per stream read (default 1024)\n"
        << "  --expect-connack        Decode and label an MQTT server CONNACK\n"
        << "  --read-capture <path>   Render a GLCAP1 file as terminal hex/ASCII\n"
        << "  --capture-tail <n>      With --read-capture, show the last n records\n";
}

void print_serial_options(std::ostream& out) {
    out << "  --serial-device <path>  Upstream serial/COM endpoint\n"
        << "  --serial-ingress <path> Optional ingress vCOM/PTY for a serial-to-serial relay\n"
        << "  --baud <n>              Upstream baud (default 115200)\n"
        << "  --ingress-baud <n>      Ingress vCOM/PTY baud (default 115200)\n"
        << "  --data-bits <7|8>       Serial data bits\n"
        << "  --stop-bits <1|2>       Serial stop bits\n"
        << "  --parity <none|even|odd> Serial parity\n"
        << "  --flow-control <value>  none, hardware, or xonxoff\n";
}

void print_rules_options(std::ostream& out) {
    out
        << "  --rules <path>          Load external control rules from JSON, Jinja, or HCL/Terraform-style files\n"
        << "  --rules-var k=v         Template variable for Jinja-style rules\n"
        << "  Supported rule keys:\n"
        << "    listen_port, upstream_host, upstream_port\n"
        << "    protocol_hint, start_marker_hex, end_marker_hex\n"
        << "    replace_text, raw_find_text, raw_live, raw_live_mode\n"
        << "    raw_chunk_bytes, mutate_direction, rewrite_u32_prefix\n"
        << "    raw_review_threshold_bytes, mqtt_review_threshold_bytes\n"
        << "    byte_window_review_threshold_bytes, max_plugin_buffer_bytes\n"
        << "    audit_log_path, action_log_path, audit_json_path, action_json_path, review_queue_dir\n";
}

void print_search_options(std::ostream& out) {
    out
        << "  --search-pid <term>     Search running TCP processes by command substring or PID\n"
        << "  --search-port <port>    Filter PID search by local or remote TCP port\n"
        << "  --search-state <state>  Filter PID search by TCP state (LISTEN, ESTABLISHED, ...)\n"
        << "  --search-json           Emit PID search results as JSON\n"
        << "  --listen-only           Filter PID search to listening sockets\n"
        << "  --established-only      Filter PID search to established sockets\n";
}

void print_output_options(std::ostream& out) {
    out
        << "  --audit-log <path>      Audit log destination\n"
        << "  --audit-json <path>     Audit JSONL destination\n"
        << "  --action-log <path>     Action item log destination\n"
        << "  --actions-json <path>   Action item JSONL destination\n"
        << "  --review-queue-dir <d>  Directory for saved pending review items\n";
}

void print_profile_options(std::ostream& out) {
    out
        << "  --seed-target-profiles <dir>  Write preset MQTT/RMQ/AMQP/ActiveMQ/ASB/Kafka target profiles\n"
        << "  --save-target-profile <path>  Save current PID search query and matches as a profile\n"
        << "  --target-label <label>        Label for a saved target profile\n"
        << "  --load-target-profile <path>  Load a saved target profile into PID search mode\n"
        << "  --show-target-profile <path>  Print a saved target profile\n"
        << "  --list-target-profiles <dir>  List saved target profile files\n";
    out << "  --run-target-profile <path>   Run TCP or serial settings stored in a profile\n"
        << "  --save-runtime-profile <path> Save the current relay/capture settings as a profile\n";
}

void print_review_options(std::ostream& out) {
    out
        << "  --review-list                List pending/saved review items\n"
        << "  --review-approve <action>    Mark a review item approved\n"
        << "  --review-reject <action>     Mark a review item rejected\n"
        << "  --review-replay <action>     Create a replay artifact from a blocked mutation\n"
        << "  --review-note <text>         Decision note for approve/reject/replay\n"
        << "  --replay-dir <dir>           Directory for replay artifacts\n";
}

void print_examples(const char* argv0, std::ostream& out) {
    out
        << "Useful commands:\n"
        << "  Search for a process:\n"
        << "    " << argv0 << " --search-pid ollama\n"
        << "  Search for listeners on MQTT port 1883:\n"
        << "    " << argv0 << " --search-port 1883 --listen-only\n"
        << "  Raw live mutation:\n"
        << "    " << argv0 << " 7777 127.0.0.1 8888 --protocol-hint raw-live --raw-live --raw-find-text hello --replace-text patch --mutate-direction c2s\n"
        << "  MQTT mutation:\n"
        << "    " << argv0 << " 7777 127.0.0.1 1883 --protocol-hint mqtt --replace-text patched-payload --mqtt-review-threshold 8\n"
        << "  Rules-driven run:\n"
        << "    " << argv0 << " 7777 127.0.0.1 8888 --rules examples/rules/raw-live.json\n"
        << "  Jinja rules-driven MQTT run:\n"
        << "    " << argv0 << " 7777 127.0.0.1 1883 --rules examples/rules/mqtt_publish.jinja --rules-var replacement_text=patched-payload --rules-var mqtt_review_threshold=8\n"
        << "  Seed protocol target profiles:\n"
        << "    " << argv0 << " --seed-target-profiles ghostline_target_profiles\n"
        << "  Save a target profile:\n"
        << "    " << argv0 << " --search-pid ollama --save-target-profile ghostline_target_profiles/ollama.json --target-label ollama-local\n"
        << "  Review queue list/approve/replay:\n"
        << "    " << argv0 << " --review-list\n"
        << "    " << argv0 << " --review-approve action-1-3 --review-note approved\n"
        << "    " << argv0 << " --review-replay action-1-3 --review-note replay-now\n";
}

void print_cheatsheet(const char* argv0, std::ostream& out) {
    out << "Ghostline CLI Cheatsheet\n"
        << "========================\n\n";
    print_examples(argv0, out);
    out << "\n" << kUsefulAnswers;
}

void print_rules_help(const char* argv0) {
    std::cout << "Ghostline Rules Help\n\n";
    print_rules_options(std::cout);
    std::cout
        << "\nRules formats:\n"
        << "  JSON: native rules object\n"
        << "  Jinja-style JSON: template variables filled by --rules-var key=value\n"
        << "  HCL/Terraform-style flat config: key = value\n"
        << "\nExamples:\n";
    print_examples(argv0, std::cout);
}

void print_search_help(const char* argv0) {
    std::cout << "Ghostline Search Help\n\n";
    print_search_options(std::cout);
    std::cout
        << "\nExamples:\n"
        << "  " << argv0 << " --search-pid ollama\n"
        << "  " << argv0 << " --search-port 1883 --listen-only\n"
        << "  " << argv0 << " --search-pid python --search-port 443 --established-only\n"
        << "  " << argv0 << " --search-json --search-pid ollama\n";
}

void print_profile_help(const char* argv0) {
    std::cout << "Ghostline Target Profiles Help\n\n";
    print_profile_options(std::cout);
    std::cout
        << "\nExamples:\n"
        << "  " << argv0 << " --search-pid ollama --save-target-profile ghostline_target_profiles/ollama.json --target-label ollama-local\n"
        << "  " << argv0 << " --load-target-profile ghostline_target_profiles/ollama.json\n"
        << "  " << argv0 << " --show-target-profile ghostline_target_profiles/ollama.json\n"
        << "  " << argv0 << " --list-target-profiles ghostline_target_profiles\n";
}

void print_review_help(const char* argv0) {
    std::cout << "Ghostline Review Queue Help\n\n";
    print_review_options(std::cout);
    std::cout
        << "\nExamples:\n"
        << "  " << argv0 << " --review-list\n"
        << "  " << argv0 << " --review-approve action-1-3 --review-note approved\n"
        << "  " << argv0 << " --review-reject action-1-3 --review-note rejected\n"
        << "  " << argv0 << " --review-replay action-1-3 --review-note replay-now\n";
}

void print_usage(const char* argv0) {
    std::cerr
        << "Usage: " << argv0 << " <listen_port> <upstream_host> <upstream_port> [options]\n"
        << "   or: " << argv0 << " --search-pid <name-or-pid> [search options]\n"
        << "   or: " << argv0 << " --help-rules | --help-search | --help-profiles | --help-review | --help-examples | --help-cheatsheet\n"
        << "Core Options:\n";
    print_core_options(std::cerr);
    std::cerr << "Rules Options:\n";
    print_rules_options(std::cerr);
    std::cerr << "Search Options:\n";
    print_search_options(std::cerr);
    std::cerr << "Profile Options:\n";
    print_profile_options(std::cerr);
    std::cerr << "Review Options:\n";
    print_review_options(std::cerr);
    std::cerr << "Output Options:\n";
    print_output_options(std::cerr);
    std::cerr << "Capture Options:\n";
    print_capture_options(std::cerr);
    std::cerr << "Serial / vCOM Options:\n";
    print_serial_options(std::cerr);
    std::cerr << "\n" << kUsefulAnswers
              << "More help:\n"
              << "  " << argv0 << " --help-rules\n"
              << "  " << argv0 << " --help-search\n"
              << "  " << argv0 << " --help-profiles\n"
              << "  " << argv0 << " --help-review\n"
              << "  " << argv0 << " --help-examples\n"
              << "  " << argv0 << " --help-cheatsheet\n";
}

void apply_target_profile(const TargetProfile& profile, ProxyConfig& config) {
    config.listen_host = profile.listen_host;
    if (profile.listen_port > 0 && profile.listen_port <= 65535) {
        config.listen_port = static_cast<std::uint16_t>(profile.listen_port);
    }
    config.upstream_host = profile.upstream_host;
    if (profile.upstream_port > 0 && profile.upstream_port <= 65535) {
        config.upstream_port = static_cast<std::uint16_t>(profile.upstream_port);
    }
    config.serial_ingress_device = profile.serial_ingress_device;
    config.serial_device = profile.serial_device;
    config.ingress_baud = profile.ingress_baud;
    config.baud = profile.baud;
    config.data_bits = profile.data_bits;
    config.stop_bits = profile.stop_bits;
    config.parity = profile.parity;
    config.flow_control = profile.flow_control;
    config.protocol_hint = profile.protocol_hint;
    config.observe_only = profile.observe_only;
    config.expect_mqtt_connack = profile.expect_connack;
    config.capture_path = profile.capture_path;
    config.capture_pcap_path = profile.capture_pcap_path;
    config.capture_max_bytes = profile.capture_max_bytes;
    config.capture_snaplen = profile.capture_snaplen;
}

TargetProfile runtime_target_profile(const ProxyConfig& config, const std::string& label) {
    TargetProfile profile;
    profile.label = label;
    profile.transport = !config.serial_ingress_device.empty() ? "serial-pair" :
        !config.serial_device.empty() ? "tcp-serial" : "tcp";
    profile.listen_host = config.listen_host;
    profile.listen_port = config.listen_port;
    profile.upstream_host = config.upstream_host;
    profile.upstream_port = config.upstream_port;
    profile.serial_ingress_device = config.serial_ingress_device;
    profile.serial_device = config.serial_device;
    profile.ingress_baud = config.ingress_baud;
    profile.baud = config.baud;
    profile.data_bits = config.data_bits;
    profile.stop_bits = config.stop_bits;
    profile.parity = config.parity;
    profile.flow_control = config.flow_control;
    profile.protocol_hint = config.protocol_hint;
    profile.observe_only = config.observe_only;
    profile.expect_connack = config.expect_mqtt_connack;
    profile.capture_path = config.capture_path;
    profile.capture_pcap_path = config.capture_pcap_path;
    profile.capture_max_bytes = config.capture_max_bytes;
    profile.capture_snaplen = config.capture_snaplen;
    return profile;
}

void print_pid_matches(const std::vector<ProcessSocketEntry>& matches) {
    if (matches.empty()) {
        std::cout << "No TCP PID matches found.\n";
        return;
    }

    for (const auto& process : matches) {
        std::cout << "PID " << process.pid
                  << " command=" << process.command
                  << " user=" << process.user << "\n";
        for (const auto& socket : process.sockets) {
            std::cout << "  fd=" << socket.file_descriptor
                      << " family=" << socket.address_family
                      << " state=" << socket.state
                      << " endpoint=" << socket.endpoint << "\n";
        }
    }
}

std::string shell_quote(const std::string& value) {
    std::string quoted = "'";
    for (char ch : value) {
        if (ch == '\'') {
            quoted += "'\\''";
        } else {
            quoted.push_back(ch);
        }
    }
    quoted.push_back('\'');
    return quoted;
}

std::vector<std::string> resolve_rules_args(const std::string& rules_path, const std::vector<std::string>& vars) {
    std::string command = "python3 tools/resolve_rules.py --rules " + shell_quote(rules_path);
    for (const auto& var : vars) {
        command += " --var " + shell_quote(var);
    }

    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(command.c_str(), "r"), pclose);
    if (!pipe) {
        throw std::runtime_error("failed to run rules resolver");
    }

    std::vector<std::string> args;
    std::array<char, 4096> buffer{};
    std::string line;
    while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe.get()) != nullptr) {
        line.assign(buffer.data());
        while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) {
            line.pop_back();
        }
        if (!line.empty()) {
            args.push_back(line);
        }
    }

    const int status = pclose(pipe.release());
    if (status != 0) {
        throw std::runtime_error("rules resolver failed for " + rules_path);
    }
    return args;
}

} // namespace

int main(int argc, char** argv) {
    if (argc == 2 && (std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h")) {
        print_usage(argv[0]);
        return 0;
    }
    if (argc == 2 && std::string(argv[1]) == "--help-rules") {
        print_rules_help(argv[0]);
        return 0;
    }
    if (argc == 2 && std::string(argv[1]) == "--help-search") {
        print_search_help(argv[0]);
        return 0;
    }
    if (argc == 2 && std::string(argv[1]) == "--help-profiles") {
        print_profile_help(argv[0]);
        return 0;
    }
    if (argc == 2 && std::string(argv[1]) == "--help-review") {
        print_review_help(argv[0]);
        return 0;
    }
    if (argc == 2 && std::string(argv[1]) == "--help-examples") {
        print_examples(argv[0], std::cout);
        return 0;
    }
    if (argc == 2 && std::string(argv[1]) == "--help-cheatsheet") {
        print_cheatsheet(argv[0], std::cout);
        return 0;
    }

    std::vector<std::string> input_args;
    for (int i = 1; i < argc; ++i) {
        input_args.push_back(argv[i]);
    }

    std::string rules_path;
    std::vector<std::string> rules_vars;
    std::vector<std::string> passthrough_args;
    std::string run_target_profile_path;
    std::string read_capture_path;
    std::size_t capture_tail = 0;
    for (std::size_t i = 0; i < input_args.size(); ++i) {
        if (input_args[i] == "--rules" && i + 1 < input_args.size()) {
            rules_path = input_args[++i];
        } else if (input_args[i] == "--rules-var" && i + 1 < input_args.size()) {
            rules_vars.push_back(input_args[++i]);
        } else if (input_args[i] == "--run-target-profile" && i + 1 < input_args.size()) {
            run_target_profile_path = input_args[++i];
        } else if (input_args[i] == "--read-capture" && i + 1 < input_args.size()) {
            read_capture_path = input_args[++i];
        } else if (input_args[i] == "--capture-tail" && i + 1 < input_args.size()) {
            capture_tail = static_cast<std::size_t>(std::stoull(input_args[++i]));
        } else {
            passthrough_args.push_back(input_args[i]);
        }
    }

    if (!rules_path.empty()) {
        std::vector<std::string> resolved_args = resolve_rules_args(rules_path, rules_vars);
        resolved_args.insert(resolved_args.end(), passthrough_args.begin(), passthrough_args.end());
        input_args = std::move(resolved_args);
    } else {
        input_args = std::move(passthrough_args);
    }

    if (!read_capture_path.empty()) {
        std::string error;
        if (!render_capture_file(read_capture_path, std::cout, capture_tail, &error)) {
            std::cerr << error << '\n';
            return 1;
        }
        return 0;
    }

    ProxyConfig config;
    bool runtime_profile_loaded = false;
    if (!run_target_profile_path.empty()) {
        try {
            apply_target_profile(load_target_profile(run_target_profile_path), config);
            runtime_profile_loaded = true;
        } catch (const std::exception& error) {
            std::cerr << "Profile error: " << error.what() << '\n';
            return 2;
        }
    }
    bool search_mode = false;
    bool search_json = false;
    PidSearchQuery search_query;
    std::string save_target_profile_path;
    std::string seed_target_profiles_dir;
    std::string load_target_profile_path;
    std::string show_target_profile_path;
    std::string list_target_profiles_dir;
    std::string target_label;
    bool review_list = false;
    std::string review_approve_id;
    std::string review_reject_id;
    std::string review_replay_id;
    std::string review_note;
    std::string replay_dir = "ghostline_replays";
    std::string save_runtime_profile_path;
    std::size_t positional_start = 0;
    bool have_positionals = false;

    try {
        for (std::size_t i = 0; i < input_args.size(); ++i) {
            const std::string arg = input_args[i];
            if (arg == "--search-pid" && i + 1 < input_args.size()) {
                search_mode = true;
                search_query.process_contains = input_args[++i];
                const std::string term = search_query.process_contains;
                if (!term.empty() && std::all_of(term.begin(), term.end(), ::isdigit)) {
                    search_query.pid = std::stoll(term);
                }
            } else if (arg == "--search-port" && i + 1 < input_args.size()) {
                search_mode = true;
                search_query.port = static_cast<std::int32_t>(std::stol(input_args[++i]));
            } else if (arg == "--search-state" && i + 1 < input_args.size()) {
                search_mode = true;
                search_query.state = input_args[++i];
            } else if (arg == "--search-json") {
                search_mode = true;
                search_json = true;
            } else if (arg == "--seed-target-profiles" && i + 1 < input_args.size()) {
                seed_target_profiles_dir = input_args[++i];
            } else if (arg == "--save-target-profile" && i + 1 < input_args.size()) {
                save_target_profile_path = input_args[++i];
            } else if (arg == "--target-label" && i + 1 < input_args.size()) {
                target_label = input_args[++i];
            } else if (arg == "--load-target-profile" && i + 1 < input_args.size()) {
                load_target_profile_path = input_args[++i];
                search_mode = true;
            } else if (arg == "--show-target-profile" && i + 1 < input_args.size()) {
                show_target_profile_path = input_args[++i];
            } else if (arg == "--list-target-profiles" && i + 1 < input_args.size()) {
                list_target_profiles_dir = input_args[++i];
            } else if (arg == "--review-list") {
                review_list = true;
            } else if (arg == "--review-approve" && i + 1 < input_args.size()) {
                review_approve_id = input_args[++i];
            } else if (arg == "--review-reject" && i + 1 < input_args.size()) {
                review_reject_id = input_args[++i];
            } else if (arg == "--review-replay" && i + 1 < input_args.size()) {
                review_replay_id = input_args[++i];
            } else if (arg == "--review-note" && i + 1 < input_args.size()) {
                review_note = input_args[++i];
            } else if (arg == "--replay-dir" && i + 1 < input_args.size()) {
                replay_dir = input_args[++i];
            } else if (arg == "--listen-only") {
                search_mode = true;
                search_query.listen_only = true;
            } else if (arg == "--established-only") {
                search_mode = true;
                search_query.established_only = true;
            } else if (arg == "--observe-only") {
                config.observe_only = true;
            } else if (arg == "--trace-text" && i + 1 < input_args.size()) {
                config.trace_text = input_args[++i];
            } else if (arg == "--trace-hex" && i + 1 < input_args.size()) {
                config.trace_hex = input_args[++i];
            } else if (arg == "--cut-on-trace") {
                config.cut_on_trace = true;
            } else if (arg == "--trace-direction" && i + 1 < input_args.size()) {
                const std::string value = input_args[++i];
                config.trace_client_to_server = value == "c2s" || value == "both";
                config.trace_server_to_client = value == "s2c" || value == "both";
                if (!config.trace_client_to_server && !config.trace_server_to_client) {
                    throw std::runtime_error("unknown trace direction: " + value);
                }
            } else if (arg == "--listen-host" && i + 1 < input_args.size()) {
                config.listen_host = input_args[++i];
            } else if (arg == "--listen-port" && i + 1 < input_args.size()) {
                config.listen_port = to_u16(input_args[++i].c_str());
            } else if (arg == "--upstream-host" && i + 1 < input_args.size()) {
                config.upstream_host = input_args[++i];
            } else if (arg == "--upstream-port" && i + 1 < input_args.size()) {
                config.upstream_port = to_u16(input_args[++i].c_str());
            } else if (arg == "--serial-device" && i + 1 < input_args.size()) {
                config.serial_device = input_args[++i];
                config.observe_only = true;
            } else if (arg == "--serial-ingress" && i + 1 < input_args.size()) {
                config.serial_ingress_device = input_args[++i];
                config.observe_only = true;
            } else if (arg == "--baud" && i + 1 < input_args.size()) {
                config.baud = std::stoi(input_args[++i]);
            } else if (arg == "--ingress-baud" && i + 1 < input_args.size()) {
                config.ingress_baud = std::stoi(input_args[++i]);
            } else if (arg == "--data-bits" && i + 1 < input_args.size()) {
                config.data_bits = std::stoi(input_args[++i]);
            } else if (arg == "--stop-bits" && i + 1 < input_args.size()) {
                config.stop_bits = std::stoi(input_args[++i]);
            } else if (arg == "--parity" && i + 1 < input_args.size()) {
                config.parity = input_args[++i];
            } else if (arg == "--flow-control" && i + 1 < input_args.size()) {
                config.flow_control = input_args[++i];
            } else if (arg == "--capture" && i + 1 < input_args.size()) {
                config.capture_path = input_args[++i];
            } else if (arg == "--capture-pcap" && i + 1 < input_args.size()) {
                config.capture_pcap_path = input_args[++i];
            } else if (arg == "--capture-hex") {
                config.capture_hex = true;
            } else if (arg == "--capture-max-bytes" && i + 1 < input_args.size()) {
                config.capture_max_bytes = static_cast<std::size_t>(std::stoull(input_args[++i]));
            } else if (arg == "--capture-snaplen" && i + 1 < input_args.size()) {
                config.capture_snaplen = static_cast<std::size_t>(std::stoull(input_args[++i]));
            } else if (arg == "--expect-connack") {
                config.expect_mqtt_connack = true;
            } else if (arg == "--save-runtime-profile" && i + 1 < input_args.size()) {
                save_runtime_profile_path = input_args[++i];
            } else if (arg == "--start-hex" && i + 1 < input_args.size()) {
                config.start_marker_hex = input_args[++i];
            } else if (arg == "--end-hex" && i + 1 < input_args.size()) {
                config.end_marker_hex = input_args[++i];
            } else if (arg == "--replace-text" && i + 1 < input_args.size()) {
                config.replacement_text = input_args[++i];
            } else if (arg == "--raw-find-text" && i + 1 < input_args.size()) {
                config.raw_find_text = input_args[++i];
            } else if (arg == "--raw-live") {
                config.raw_live_mode = true;
            } else if (arg == "--raw-chunk-bytes" && i + 1 < input_args.size()) {
                config.raw_chunk_bytes = static_cast<std::size_t>(std::stoul(input_args[++i]));
            } else if (arg == "--mutate-direction" && i + 1 < input_args.size()) {
                const std::string value = input_args[++i];
                if (value == "c2s") {
                    config.mutate_client_to_server = true;
                    config.mutate_server_to_client = false;
                } else if (value == "s2c") {
                    config.mutate_client_to_server = false;
                    config.mutate_server_to_client = true;
                } else if (value == "both") {
                    config.mutate_client_to_server = true;
                    config.mutate_server_to_client = true;
                } else {
                    throw std::runtime_error("unknown mutate direction: " + value);
                }
            } else if (arg == "--raw-review-threshold" && i + 1 < input_args.size()) {
                config.raw_review_threshold_bytes = static_cast<std::size_t>(std::stoul(input_args[++i]));
            } else if (arg == "--mqtt-review-threshold" && i + 1 < input_args.size()) {
                config.mqtt_review_threshold_bytes = static_cast<std::size_t>(std::stoul(input_args[++i]));
            } else if (arg == "--byte-review-threshold" && i + 1 < input_args.size()) {
                config.byte_window_review_threshold_bytes = static_cast<std::size_t>(std::stoul(input_args[++i]));
            } else if (arg == "--rewrite-u32-prefix") {
                config.rewrite_u32_prefix = true;
            } else if (arg == "--max-plugin-buffer" && i + 1 < input_args.size()) {
                config.max_plugin_buffer_bytes = static_cast<std::size_t>(std::stoul(input_args[++i]));
            } else if (arg == "--protocol-hint" && i + 1 < input_args.size()) {
                config.protocol_hint = input_args[++i];
            } else if (arg == "--audit-log" && i + 1 < input_args.size()) {
                config.audit_log_path = input_args[++i];
            } else if (arg == "--audit-json" && i + 1 < input_args.size()) {
                config.audit_json_path = input_args[++i];
            } else if (arg == "--action-log" && i + 1 < input_args.size()) {
                config.action_log_path = input_args[++i];
            } else if (arg == "--actions-json" && i + 1 < input_args.size()) {
                config.action_json_path = input_args[++i];
            } else if (arg == "--review-queue-dir" && i + 1 < input_args.size()) {
                config.review_queue_dir = input_args[++i];
            } else {
                positional_start = i;
                have_positionals = true;
                break;
            }
        }

        if (!seed_target_profiles_dir.empty()) {
            const auto written = seed_protocol_target_profiles(seed_target_profiles_dir);
            for (const auto& path : written) {
                std::cout << path << "\n";
            }
            return written.empty() ? 1 : 0;
        }

        if (!show_target_profile_path.empty()) {
            const TargetProfile profile = load_target_profile(show_target_profile_path);
            std::cout << target_profile_to_json(profile) << "\n";
            return 0;
        }

        if (!list_target_profiles_dir.empty()) {
            const auto paths = list_target_profiles(list_target_profiles_dir);
            for (const auto& path : paths) {
                std::cout << path << "\n";
            }
            return paths.empty() ? 1 : 0;
        }

        if (review_list || !review_approve_id.empty() || !review_reject_id.empty() || !review_replay_id.empty()) {
            if (!review_approve_id.empty()) {
                update_review_item(config.review_queue_dir, review_approve_id, "approved", review_note);
                std::cout << "Approved review item " << review_approve_id << "\n";
                return 0;
            }
            if (!review_reject_id.empty()) {
                update_review_item(config.review_queue_dir, review_reject_id, "rejected", review_note);
                std::cout << "Rejected review item " << review_reject_id << "\n";
                return 0;
            }
            if (!review_replay_id.empty()) {
                const std::string replay_path = replay_review_item(config.review_queue_dir, review_replay_id, replay_dir, review_note);
                std::cout << "Replay artifact written to " << replay_path << "\n";
                return 0;
            }

            const auto items = list_review_items(config.review_queue_dir);
            if (items.empty()) {
                std::cout << "No review items found.\n";
                return 1;
            }
            for (const auto& item : items) {
                std::cout << item.action_id
                          << " status=" << item.review_status
                          << " plugin=" << item.plugin_name
                          << " flow=" << item.flow_id
                          << " title=\"" << item.title << "\"\n";
            }
            return 0;
        }

        if (!load_target_profile_path.empty()) {
            const TargetProfile profile = load_target_profile(load_target_profile_path);
            if (target_label.empty()) {
                target_label = profile.label;
            }
            search_query = profile.query;
        }

        if (search_mode) {
            const auto matches = query_tcp_processes(search_query);
            if (!save_target_profile_path.empty()) {
                TargetProfile profile;
                profile.label = target_label.empty() ? std::filesystem::path(save_target_profile_path).stem().string() : target_label;
                profile.query = search_query;
                profile.matches = matches;
                save_target_profile(save_target_profile_path, profile);
                std::cerr << "Saved target profile " << save_target_profile_path << "\n";
            }
            if (search_json) {
                std::cout << process_sockets_to_json(matches);
            } else {
                print_pid_matches(matches);
            }
            return matches.empty() ? 1 : 0;
        }

        std::size_t trailing_options_start = input_args.size();
        if (have_positionals) {
            if (input_args.size() - positional_start < 3) {
                print_usage(argv[0]);
                return 2;
            }
            config.listen_port = to_u16(input_args[positional_start].c_str());
            config.upstream_host = input_args[positional_start + 1];
            config.upstream_port = to_u16(input_args[positional_start + 2].c_str());
            trailing_options_start = positional_start + 3;
        } else if (!runtime_profile_loaded && config.serial_device.empty()) {
            print_usage(argv[0]);
            return 2;
        }

        for (std::size_t i = trailing_options_start; i < input_args.size(); ++i) {
            const std::string arg = input_args[i];
            if (arg == "--start-hex" && i + 1 < input_args.size()) {
                config.start_marker_hex = input_args[++i];
            } else if (arg == "--end-hex" && i + 1 < input_args.size()) {
                config.end_marker_hex = input_args[++i];
            } else if (arg == "--replace-text" && i + 1 < input_args.size()) {
                config.replacement_text = input_args[++i];
            } else if (arg == "--raw-find-text" && i + 1 < input_args.size()) {
                config.raw_find_text = input_args[++i];
            } else if (arg == "--raw-live") {
                config.raw_live_mode = true;
            } else if (arg == "--raw-chunk-bytes" && i + 1 < input_args.size()) {
                config.raw_chunk_bytes = static_cast<std::size_t>(std::stoul(input_args[++i]));
            } else if (arg == "--mutate-direction" && i + 1 < input_args.size()) {
                const std::string value = input_args[++i];
                if (value == "c2s") {
                    config.mutate_client_to_server = true;
                    config.mutate_server_to_client = false;
                } else if (value == "s2c") {
                    config.mutate_client_to_server = false;
                    config.mutate_server_to_client = true;
                } else if (value == "both") {
                    config.mutate_client_to_server = true;
                    config.mutate_server_to_client = true;
                } else {
                    throw std::runtime_error("unknown mutate direction: " + value);
                }
            } else if (arg == "--raw-review-threshold" && i + 1 < input_args.size()) {
                config.raw_review_threshold_bytes = static_cast<std::size_t>(std::stoul(input_args[++i]));
            } else if (arg == "--mqtt-review-threshold" && i + 1 < input_args.size()) {
                config.mqtt_review_threshold_bytes = static_cast<std::size_t>(std::stoul(input_args[++i]));
            } else if (arg == "--byte-review-threshold" && i + 1 < input_args.size()) {
                config.byte_window_review_threshold_bytes = static_cast<std::size_t>(std::stoul(input_args[++i]));
            } else if (arg == "--rewrite-u32-prefix") {
                config.rewrite_u32_prefix = true;
            } else if (arg == "--max-plugin-buffer" && i + 1 < input_args.size()) {
                config.max_plugin_buffer_bytes = static_cast<std::size_t>(std::stoul(input_args[++i]));
            } else if (arg == "--protocol-hint" && i + 1 < input_args.size()) {
                config.protocol_hint = input_args[++i];
            } else if (arg == "--observe-only") {
                config.observe_only = true;
            } else if (arg == "--trace-text" && i + 1 < input_args.size()) {
                config.trace_text = input_args[++i];
            } else if (arg == "--trace-hex" && i + 1 < input_args.size()) {
                config.trace_hex = input_args[++i];
            } else if (arg == "--cut-on-trace") {
                config.cut_on_trace = true;
            } else if (arg == "--trace-direction" && i + 1 < input_args.size()) {
                const std::string value = input_args[++i];
                config.trace_client_to_server = value == "c2s" || value == "both";
                config.trace_server_to_client = value == "s2c" || value == "both";
                if (!config.trace_client_to_server && !config.trace_server_to_client) {
                    throw std::runtime_error("unknown trace direction: " + value);
                }
            } else if (arg == "--capture" && i + 1 < input_args.size()) {
                config.capture_path = input_args[++i];
            } else if (arg == "--capture-pcap" && i + 1 < input_args.size()) {
                config.capture_pcap_path = input_args[++i];
            } else if (arg == "--capture-hex") {
                config.capture_hex = true;
            } else if (arg == "--capture-max-bytes" && i + 1 < input_args.size()) {
                config.capture_max_bytes = static_cast<std::size_t>(std::stoull(input_args[++i]));
            } else if (arg == "--capture-snaplen" && i + 1 < input_args.size()) {
                config.capture_snaplen = static_cast<std::size_t>(std::stoull(input_args[++i]));
            } else if (arg == "--expect-connack") {
                config.expect_mqtt_connack = true;
            } else if (arg == "--save-runtime-profile" && i + 1 < input_args.size()) {
                save_runtime_profile_path = input_args[++i];
            } else if (arg == "--audit-log" && i + 1 < input_args.size()) {
                config.audit_log_path = input_args[++i];
            } else if (arg == "--audit-json" && i + 1 < input_args.size()) {
                config.audit_json_path = input_args[++i];
            } else if (arg == "--action-log" && i + 1 < input_args.size()) {
                config.action_log_path = input_args[++i];
            } else if (arg == "--actions-json" && i + 1 < input_args.size()) {
                config.action_json_path = input_args[++i];
            } else if (arg == "--review-queue-dir" && i + 1 < input_args.size()) {
                config.review_queue_dir = input_args[++i];
            } else {
                throw std::runtime_error("unknown option: " + arg);
            }
        }

        if (config.data_bits != 7 && config.data_bits != 8) {
            throw std::runtime_error("data bits must be 7 or 8");
        }
        if (config.stop_bits != 1 && config.stop_bits != 2) {
            throw std::runtime_error("stop bits must be 1 or 2");
        }
        if (config.parity != "none" && config.parity != "even" && config.parity != "odd") {
            throw std::runtime_error("parity must be none, even, or odd");
        }
        if (config.flow_control != "none" && config.flow_control != "hardware" &&
            config.flow_control != "xonxoff") {
            throw std::runtime_error("flow control must be none, hardware, or xonxoff");
        }
        if (config.capture_max_bytes == 0 || config.capture_snaplen == 0) {
            throw std::runtime_error("capture ceilings must be greater than zero");
        }
        if (!save_runtime_profile_path.empty()) {
            const auto label = target_label.empty()
                ? std::filesystem::path(save_runtime_profile_path).stem().string()
                : target_label;
            save_target_profile(
                save_runtime_profile_path, runtime_target_profile(config, label));
            std::cerr << "Saved runtime target profile " << save_runtime_profile_path << '\n';
            if (!have_positionals && !runtime_profile_loaded) return 0;
        }
    } catch (const std::exception& error) {
        std::cerr << "Argument error: " << error.what() << "\n";
        print_usage(argv[0]);
        return 2;
    }

    if (!config.serial_device.empty()) {
        std::cout << "Ghostline field serial mode // upstream=" << config.serial_device
                  << " baud=" << config.baud;
        if (!config.serial_ingress_device.empty()) {
            std::cout << " ingress=" << config.serial_ingress_device
                      << " ingress-baud=" << config.ingress_baud;
        } else {
            std::cout << " tcp-ingress=" << config.listen_host << ':' << config.listen_port;
        }
        std::cout << " // observe-only\n";
        if (!config.capture_path.empty()) std::cout << "Capture: " << config.capture_path << '\n';
        if (!config.capture_pcap_path.empty()) std::cout << "Capture PCAP: " << config.capture_pcap_path << '\n';
        return run_serial_bridge(config);
    }

    std::cout << "Ghostline listening on " << config.listen_host << ":" << config.listen_port
              << " -> upstream " << config.upstream_host << ":" << config.upstream_port << "\n";
    if (!config.protocol_hint.empty()) {
        std::cout << "Preferred plugin: " << config.protocol_hint << "\n";
    }
    if (config.raw_live_mode) {
        std::cout << "Raw live mutation enabled"
                  << " chunk-bytes=" << config.raw_chunk_bytes
                  << " find=\"" << config.raw_find_text << "\"\n";
    }
    std::cout << "Mutate direction: "
              << (config.mutate_client_to_server && config.mutate_server_to_client
                      ? "both"
                      : (config.mutate_client_to_server ? "c2s" : "s2c"))
              << "\n";
    std::cout << "Audit log: " << config.audit_log_path << "\n";
    std::cout << "Action log: " << config.action_log_path << "\n";
    if (!config.audit_json_path.empty()) {
        std::cout << "Audit JSON: " << config.audit_json_path << "\n";
    }
    if (!config.action_json_path.empty()) {
        std::cout << "Action JSON: " << config.action_json_path << "\n";
    }
    std::cout << "Review queue: " << config.review_queue_dir << "\n";
    std::cout << "Mode: " << (config.observe_only ? "OBSERVE-ONLY" : "PLUGIN DECISION PIPELINE") << '\n';
    if (!config.capture_path.empty()) std::cout << "Capture: " << config.capture_path << '\n';
    if (!config.capture_pcap_path.empty()) {
        std::cout << "Capture PCAP: " << config.capture_pcap_path << " (DLT_USER0)\n";
    }
    if (config.expect_mqtt_connack) {
        std::cout << "MQTT: CONNACK summary armed\n";
    }

    return run_transport_core(config);
}
