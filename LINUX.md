# Linux build notes — next phase

Linux is the next native validation target. The current source has a portable
`poll()` TCP relay and a POSIX `termios` serial bridge, but the full current
tree has been built and exercised on macOS. Treat Linux behavior as pending
until the checks below pass on a named distribution and architecture.

## Build on a Linux host

Install a C++17 compiler, CMake 3.16 or newer, Python 3.9 or newer, and
`lsof` with the distribution's package manager. Qt 5 or Qt 6 Widgets is
optional. Then use a clean checkout and a fresh build directory:

```bash
cmake -S . -B build-linux -DGHOSTLINE_BUILD_QT=OFF
cmake --build build-linux -j
ctest --test-dir build-linux --output-on-failure
```

For the Qt window and ShadowBoxing HUD, install the chosen Qt Widgets
development package and configure with either `-DGHOSTLINE_QT_MAJOR=5`
or `-DGHOSTLINE_QT_MAJOR=6`. The executable must be started inside a
graphical desktop session; `ghostline_shell` works in a terminal.

## Validation sequence

Record distribution, kernel, CPU architecture, compiler, CMake, Python, and Qt
versions with the result. Then verify:

1. `ctest` passes, including the loopback trace observation/cutoff test.
2. `MODE=raw ./sim.bash` and `MODE=mqtt ./sim.bash` pass with local fixture
   traffic. The harness starts and stops its own local processes.
3. `./build-linux/ghostline_shell --snapshot --no-state` prints a clean view.
4. `./build-linux/gl --search-port 1883 --listen-only` works with `lsof`
   installed and appropriate process visibility.
5. A controlled TCP client traverses the relay in each direction, including
   partial reads and a half-close.
6. Observation mode emits `trace-match` without cutting the flow. An
   explicitly enabled test rule emits `containment-stream-cut` and closes
   both directions after a split signature.
7. If serial hardware or a virtual pair is available, validate baud/framing,
   both directions, and bounded GLCAP1/PCAP capture. Serial is observe only.
8. If Qt is present, open both the full window and
   `ghostline_qt --mode=ShadowBoxing`; verify geometry, opacity, click-to-arm,
   blind input, compact result/error, and stop/quit behavior under the chosen
   window manager.

Use a disposable local upstream for the relay checks. A client must connect
through Ghostline's listener; merely observing a host process through
`--search-pid` does not reroute that process's traffic.

## Linux-specific implementation notes

- `src/transport_core.cpp` uses `poll()`, nonblocking POSIX sockets, and
  `getaddrinfo()`. The active CMake target does not compile
  `src/linux_epoll_proxy.cpp`; that file is an older separate prototype.
- `src/serial_bridge.cpp` uses `termios`, `poll()`, and device paths. A
  normal Linux deployment needs access to the selected `/dev/tty*` device.
- `src/pid_search.cpp` parses `lsof` output. Process discovery depends on
  the privileges and visibility of the account running it.
- GLCAP1 and DLT_USER0 PCAP hold application-stream bytes. They are not
  Ethernet/IP/TCP packet captures.
- End-to-end encrypted payloads remain opaque to content matching unless
  plaintext is deliberately presented at this relay boundary.

## Exit criteria for calling Linux supported

- A clean build and all CTest suites pass on the documented host.
- Raw and MQTT end-to-end simulations pass.
- A bounded soak demonstrates no unbounded output-queue growth with a slow
  receiver. The current relay has a plugin buffer ceiling but no aggregate
  queued-output backpressure; this is a required next-phase hardening item.
- Audit and capture retention limits are documented and tested for long
  sessions. Capture has a payload ceiling; audit logs can still grow.
- Serial and Qt claims are labeled with the hardware and desktop environments
  actually tested.

Record failures and fixes here with exact host and command details before
updating the README's support statement. Windows remains a separate backend
effort; the current Win32 serial path reports that it is unavailable.
