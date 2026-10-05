# Build and run Ghostline

This page describes the current source tree. Commands run from the repository
root. The binaries are built locally; no install step is required.

## Requirements

- CMake 3.16 or newer
- A C++17 compiler and platform development headers
- Python 3.9 or newer for `tools/resolve_rules.py` and the Python tests
- `lsof` for live PID/socket discovery
- Qt Widgets 5 or 6 only if building `ghostline_qt`

The TCP relay, serial bridge, `gl`, and `ghostline_shell` use POSIX APIs.
The current CMake targets are intended for macOS and Linux. The Qt interface
is optional; the build can proceed without Qt.

## Standard build

```bash
cmake -S . -B build-local
cmake --build build-local -j
ctest --test-dir build-local --output-on-failure
```

Outputs:

| Target | Path | Role |
| --- | --- | --- |
| `gl` | `build-local/gl` | Short relay CLI |
| `ghostline_cli` | `build-local/ghostline_cli` | Full relay CLI |
| `ghostline_shell` | `build-local/ghostline_shell` | Terminal audit console |
| `ghostline_tests` | `build-local/ghostline_tests` | C++ test executable |
| `ghostline_qt` | `build-local/ghostline_qt` | Qt window and ShadowBoxing HUD, when Qt is found |

`gl` and `ghostline_cli` are built from the same source entry point. The
terminal shell is a separate process that reads Ghostline's audit and action
logs. It does not start the relay for you.

## Build without Qt

```bash
cmake -S . -B build-cli -DGHOSTLINE_BUILD_QT=OFF
cmake --build build-cli -j
ctest --test-dir build-cli --output-on-failure
```

This is the simplest build for a headless machine.

## Select Qt

`GHOSTLINE_QT_MAJOR=AUTO` prefers Qt 6, then Qt 5. Choose one explicitly
when both are installed:

```bash
cmake -S . -B build-qt5 -DGHOSTLINE_BUILD_QT=ON -DGHOSTLINE_QT_MAJOR=5
cmake --build build-qt5 -j
```

```bash
cmake -S . -B build-qt6 -DGHOSTLINE_BUILD_QT=ON -DGHOSTLINE_QT_MAJOR=6
cmake --build build-qt6 -j
```

If CMake cannot find a Qt installation, point `CMAKE_PREFIX_PATH` at that
installation's CMake prefix. On the Apple Silicon Homebrew layout, for
example:

```bash
cmake -S . -B build-qt5 -DGHOSTLINE_QT_MAJOR=5 \
  -DCMAKE_PREFIX_PATH=/opt/homebrew/opt/qt@5
```

Forcing version 5 or 6 makes configuration fail clearly when that version is
missing. With `AUTO`, CMake prints a warning and omits `ghostline_qt`
when neither version is found. Use a fresh build directory when changing Qt
major versions so cached package paths do not select the earlier installation.

## Start the interfaces

```bash
./build-local/gl --help
./build-local/ghostline_shell
./build-local/ghostline_qt
./build-local/ghostline_qt --mode=ShadowBoxing
```

In ShadowBoxing, click the HUD, type a command without visible input, and
press Enter. `gl --search-port 1883 --listen-only` runs Ghostline. The form
`gl | pwd & ls` runs terminal programs in sequence. Output is condensed to
the small readout. The HUD looks for `ghostline_cli` beside its own binary,
so build the CLI and Qt target into the same directory.

## Verify the relay

```bash
ctest --test-dir build-local --output-on-failure
MODE=raw ./sim.bash
MODE=mqtt ./sim.bash
```

CTest covers plugin logic, rules loading, and a localhost trace test in both
observation and cutoff modes. The integration test binds loopback sockets;
the sandbox or CI runner must permit that. `sim.bash` builds in
`build-local`, launches local fixture processes, and writes under
`sim-output/`.

The byte-window simulation's expectation is currently stale: its size-changing
candidate falls back to original bytes, while the reused fixture expects a
mutation. Keep that case out of the passing quick path until the fixture is
updated to assert the fallback.

## Common checks

```bash
./build-local/gl --search-port 1883 --listen-only
./build-local/ghostline_shell --snapshot --no-state
./build-local/gl --help-rules
```

PID/socket discovery invokes `lsof`. A missing `lsof` affects discovery
commands, while the relay and parser tests can still build. The shell needs a
terminal in interactive mode; `--snapshot` works with redirected output.

The current `.gitignore` excludes local CMake trees and runtime logs. Use
`git status --short` before staging; this repository has previously tracked
a `build/` tree, so its deletion is a separate source-control change.
