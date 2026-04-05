# Ghostline CLI Cheatsheet

Ghostline is built around one operating rule:

`original delivery wins unless modified release is proven safe`

Use this page as the fast operator reference. For the full manual, run:

```bash
MANPATH="$PWD/man:${MANPATH}" man ghostline_cli
```

## Fast Help

```bash
./build-local/ghostline_cli -h
./build-local/ghostline_cli --help-rules
./build-local/ghostline_cli --help-search
./build-local/ghostline_cli --help-profiles
./build-local/ghostline_cli --help-review
./build-local/ghostline_cli --help-examples
./build-local/ghostline_cli --help-cheatsheet
```

## Quick Start

Build:

```bash
cmake -S . -B build-local
cmake --build build-local
ctest --test-dir build-local --output-on-failure
```

Run the Qt operator app:

```bash
./build-local/ghostline_qt
```

## Common Workflows

### Find a target process

```bash
./build-local/ghostline_cli --search-pid ollama
./build-local/ghostline_cli --search-port 1883 --listen-only
./build-local/ghostline_cli --search-pid python --search-port 443 --established-only
./build-local/ghostline_cli --search-json --search-pid ollama
```

### Save and inspect target profiles

```bash
./build-local/ghostline_cli --save-target-profile /tmp/targets/ollama.json --target-label ollama-local
./build-local/ghostline_cli --show-target-profile /tmp/targets/ollama.json
./build-local/ghostline_cli --list-target-profiles ghostline_target_profiles
./build-local/ghostline_cli --seed-target-profiles ghostline_target_profiles
```

### Run raw live mutation

```bash
./build-local/ghostline_cli 7777 127.0.0.1 8888 \
  --protocol-hint raw-live \
  --raw-live \
  --raw-find-text hello \
  --replace-text patch \
  --mutate-direction c2s \
  --raw-review-threshold 8
```

### Run MQTT mutation

```bash
./build-local/ghostline_cli 7777 127.0.0.1 1883 \
  --protocol-hint mqtt \
  --replace-text patched-payload \
  --mutate-direction c2s \
  --mqtt-review-threshold 8
```

### Run generic byte-window mutation

```bash
./build-local/ghostline_cli 7777 127.0.0.1 8888 \
  --protocol-hint byte-window \
  --start-hex 48454144 \
  --end-hex 5441494c \
  --replace-text NEW \
  --byte-review-threshold 8
```

## Rules-Driven Control

### JSON rules

```bash
./build-local/ghostline_cli 7777 127.0.0.1 8888 \
  --rules examples/rules/raw-live.json
```

### Jinja-style JSON rules

```bash
./build-local/ghostline_cli 7777 127.0.0.1 1883 \
  --rules examples/rules/mqtt_publish.jinja \
  --rules-var replacement_text=patched-payload \
  --rules-var mqtt_review_threshold=8 \
  --rules-var audit_json_path=sim-output/mqtt/audit.jsonl \
  --rules-var action_json_path=sim-output/mqtt/actions.jsonl
```

### Lightweight HCL / Terraform-style rules

```bash
./build-local/ghostline_cli 7777 127.0.0.1 8888 \
  --rules examples/rules/raw-live.tfvars
```

Common rule keys:

- `listen_port`
- `upstream_host`
- `upstream_port`
- `protocol_hint`
- `raw_live`
- `raw_find_text`
- `replace_text`
- `mutate_direction`
- `raw_chunk_bytes`
- `start_marker_hex`
- `end_marker_hex`
- `raw_review_threshold_bytes`
- `mqtt_review_threshold_bytes`
- `byte_window_review_threshold_bytes`
- `max_plugin_buffer_bytes`
- `audit_json_path`
- `action_json_path`
- `review_queue_dir`

## Machine-Readable Outputs

### Audit and action JSONL

```bash
./build-local/ghostline_cli 7777 127.0.0.1 8888 \
  --rules examples/rules/raw-live.json \
  --audit-json ghostline_audit.jsonl \
  --actions-json ghostline_actions.jsonl
```

Typical outputs:

- `ghostline_audit.log`
- `ghostline_actions.log`
- `ghostline_audit.jsonl`
- `ghostline_actions.jsonl`
- `ghostline_review_queue/`
- `ghostline_replays/`

## Review Queue

```bash
./build-local/ghostline_cli --review-list
./build-local/ghostline_cli --review-approve action-1-3 --review-note approved
./build-local/ghostline_cli --review-reject action-1-3 --review-note rejected
./build-local/ghostline_cli --review-replay action-1-3 --review-note replay-now
```

What replay means today:

- it creates a replay artifact for operator follow-up
- it does not inject back into a live session yet

## Simulation Harness

```bash
MODE=raw ./sim.bash
MODE=mqtt ./sim.bash
```

Simulation outputs usually land under:

- `sim-output/raw/`
- `sim-output/mqtt/`

## Protocol Hints

Available today:

- `raw-live`
- `byte-window`
- `mqtt`
- `rabbitmq`
- `amqp`
- `activemq`
- `azure-service-bus`
- `kafka`

Current reality:

- MQTT is the only protocol-owned framing and active mutation plugin
- the other MQ-family plugins are detection and audit targets today

## Operator Notes

- PID search is discovery, not transport ownership
- target profiles are reusable search/session seeds, not hard PID pinning
- risky mutations become review items instead of forced releases
- JSONL output is the best bridge to Python and Lua adapters

## If You Only Remember Five Commands

```bash
./build-local/ghostline_cli --search-pid ollama
./build-local/ghostline_cli --seed-target-profiles ghostline_target_profiles
./build-local/ghostline_cli 7777 127.0.0.1 8888 --rules examples/rules/raw-live.json
./build-local/ghostline_cli --review-list
./build-local/ghostline_qt
```
