# Ghostline Gate

Ghostline Gate is an inline transport workbench for traffic deliberately routed
through it. It observes a TCP stream, frames supported messages, and can release
one validated mutation or the original bytes. An exact byte trace can also
produce an audit event or close that relay flow when containment is explicitly
enabled.

The original RuneScape Tool is the myth and legend. Ghostline Gate
keeps that story alive as a new transport proof of concept. It is powerful,
and it still needs more testing.

**Original delivery has priority when Ghostline cannot validate a modified
release.** A configured containment rule is a separate decision: it closes the
matched flow.

![Ghostline overview](Ghostline.png)

## What is here

| Binary | Purpose |
| --- | --- |
| `gl` | Short name for the Ghostline relay CLI |
| `ghostline_cli` | Relay, capture, mutation, trace observation, and explicit flow cutoff |
| `ghostline_shell` | Persistent full-screen terminal view of audit and action logs |
| `ghostline_qt` | Qt operator window for targets, files, and review items |
| `ghostline_qt --mode=ShadowBoxing` | Small blind-input Ghostline HUD |

The Python host and server files under `tests/` generate controlled traffic.
They are fixtures, not required client or server components of the product.
Ghostline sees bytes only when a client connects through its listener, or when
the serial bridge is placed between endpoints. It does not passively capture
other processes' traffic.

## First build

Requires CMake, a C++17 compiler, and Python 3 for the rules resolver and test
harness. Qt Widgets is optional.

```bash
cmake -S . -B build-local
cmake --build build-local -j
ctest --test-dir build-local --output-on-failure
```

The build creates `gl`, `ghostline_cli`, `ghostline_shell`, and
`ghostline_tests`. It creates `ghostline_qt` when Qt Widgets is available.
For Qt 5 or Qt 6 selection, dependencies, and troubleshooting, see
[BUILD.md](BUILD.md). Linux validation and remaining work are recorded in
[LINUX.md](LINUX.md).

## Run

Start the persistent terminal view from the repository root:

```bash
./build-local/ghostline_shell
```

In a second terminal, start an observe-only relay to a local service you
control:

```bash
./build-local/gl 17777 127.0.0.1 9000 \
  --observe-only \
  --audit-log ghostline_audit.log \
  --actions-json ghostline_actions.jsonl
```

Point the test client at `127.0.0.1:17777`. The upstream service must be
listening on `127.0.0.1:9000`. The shell follows the audit and action logs
as they change. Press `?` for controls, `p` to pause, `:` for commands,
and `q` to exit. Run `./build-local/ghostline_shell --snapshot --no-state`
for a single printable view. Shell settings persist in
`~/.config/ghostline/shell.state` unless `--no-state` is used.

## Observe a trace or cut a flow

Trace matching spans TCP read boundaries. Observation is the default:

```bash
./build-local/gl 17777 127.0.0.1 9000 \
  --trace-text "classified-demo-trace" \
  --trace-direction c2s
```

Enable inline cutoff explicitly:

```bash
./build-local/gl 17777 127.0.0.1 9000 \
  --trace-hex 636c61737369666965642d64656d6f2d7472616365 \
  --trace-direction c2s \
  --cut-on-trace
```

The text and hex examples represent the same bytes. A match emits
`trace-match`; a cutoff emits `containment-stream-cut`. Cutoff closes both
directions of that relay flow. Bytes already forwarded before the match cannot
be recalled. Payload signatures are not visible inside end-to-end encrypted
traffic.

## Frame and mutation support

| Plugin | Current behavior |
| --- | --- |
| `raw-live` | Frames fixed chunks or end-marker windows; stages and validates a replacement |
| `byte-window` | Matches configured start/end markers; falls back to original when a size change cannot be validated |
| `mqtt` | Frames MQTT packets; can replace a PUBLISH payload and recalculate Remaining Length |
| `rabbitmq` | Frames AMQP 0-9-1 headers and frames; observe only |
| `amqp` | Frames AMQP 1.0 headers and frames; observe only |
| `kafka` | Frames length-prefixed requests/responses; observe only |
| `activemq`, `azure-service-bus` | Detection and audit targets; observe only |

The candidate path keeps original and modified bytes separate, validates a
replacement, and queues exactly one release. On framing failure or a plugin
buffer ceiling, the affected flow switches to original-byte observation.
Risky changes can create review items. An approved review or generated replay
artifact does not reinject bytes into a live flow.

MQTT example:

```bash
./build-local/gl 17777 127.0.0.1 1883 \
  --protocol-hint mqtt \
  --replace-text patched-payload \
  --mutate-direction c2s
```

## Capture and operator modes

Capture stores bounded application-stream reads before plugin decisions:

```bash
./build-local/gl 17777 127.0.0.1 1883 \
  --observe-only --protocol-hint mqtt --expect-connack \
  --capture state/mqtt.glcap --capture-pcap state/mqtt.pcap
./build-local/gl --read-capture state/mqtt.glcap --capture-tail 24
```

`GLCAP1` is text with hex/ASCII. The PCAP uses `DLT_USER0` application data;
it contains no reconstructed Ethernet, IP, or TCP headers. The POSIX serial
bridge supports TCP-to-serial and serial-pair observation. See
[Field Capture](docs/GHOSTLINE-FIELD-CAPTURE.md).

The full Qt operator window:

```bash
./build-local/ghostline_qt
```

The ShadowBoxing HUD:

```bash
./build-local/ghostline_qt --mode=ShadowBoxing
```

It opens at the bottom-right, approximately 1.5 by 1 logical inches, with a
grey backing and 80% window opacity. Click it, type without an input echo, and
press Enter to see a compact result. `gl --search-port 1883 --listen-only`
invokes the adjacent Ghostline CLI. `gl | pwd & ls` runs `pwd`, then `ls`,
as direct terminal programs. `&` is sequential in this HUD; shell expansion
and redirection are not implemented. Blind built-ins are `help`, `clear`,
`stop`, and `quit`. Use `--corner=bottom-left` for the other corner.

## Test fixtures and evidence

```bash
MODE=raw ./sim.bash
MODE=mqtt ./sim.bash
```

The CTest suite includes C++ plugin and capture checks, Python rules loading,
and a localhost trace test that splits a signature across two writes and
checks both observation and cutoff. The raw and MQTT simulations exercise
fixture traffic end to end. The byte-window simulation currently reuses an
expectation that conflicts with its safe original fallback, so it is not part
of the passing quick path.

Ghostline uses text and optional JSONL audit/action outputs. Review items and
replay artifacts are saved on disk. Logs and captures may include complete
payload bytes, so inspect them before sharing a run.

## Scope and next work

The active runtime uses a portable `poll()` TCP relay and a POSIX serial
bridge. The older `src/linux_epoll_proxy.cpp` is a separate prototype and is
not built by the current CMake target. Linux needs a clean native build and
runtime pass before it is called validated. Windows serial execution is not
implemented. Queue backpressure, bounded audit retention, richer protocol
ownership, and live Qt flow controls remain future work.

Documentation: [BUILD.md](BUILD.md) · [LINUX.md](LINUX.md) ·
[Phase 1 runbook](PHASE1_RUNBOOK.md) ·
[CLI cheatsheet](docs/ghostline_cli_cheatsheet.md) ·
[Field Capture](docs/GHOSTLINE-FIELD-CAPTURE.md)
