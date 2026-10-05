#!/usr/bin/env python3

import pathlib
import socket
import subprocess
import sys
import tempfile
import threading
import time


def free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def run_case(binary: str, enforce: bool) -> None:
    listen_port = free_port()
    upstream_port = free_port()
    received = bytearray()
    ready = threading.Event()

    def upstream() -> None:
        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", upstream_port))
        listener.listen(1)
        ready.set()
        connection, _ = listener.accept()
        connection.settimeout(2)
        try:
            while True:
                try:
                    chunk = connection.recv(4096)
                except (ConnectionResetError, socket.timeout):
                    break
                if not chunk:
                    break
                received.extend(chunk)
        finally:
            connection.close()
            listener.close()

    thread = threading.Thread(target=upstream, daemon=True)
    thread.start()
    assert ready.wait(2), "upstream listener did not start"

    with tempfile.TemporaryDirectory(prefix="ghostline-trace-") as directory:
        root = pathlib.Path(directory)
        audit = root / "audit.log"
        command = [
            binary,
            str(listen_port),
            "127.0.0.1",
            str(upstream_port),
            "--trace-text",
            "MAGIC",
            "--trace-direction",
            "c2s",
            "--audit-log",
            str(audit),
            "--action-log",
            str(root / "actions.log"),
            "--review-queue-dir",
            str(root / "reviews"),
        ]
        if enforce:
            command.append("--cut-on-trace")
        relay = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 3
            while True:
                client = socket.socket()
                try:
                    client.connect(("127.0.0.1", listen_port))
                    break
                except ConnectionRefusedError:
                    client.close()
                    if time.monotonic() >= deadline:
                        raise AssertionError("relay listener did not start")
                    time.sleep(0.02)
            client.settimeout(2)
            client.sendall(b"abcMA")
            time.sleep(0.1)
            client.sendall(b"GICxyz")
            try:
                client.shutdown(socket.SHUT_WR)
                while client.recv(1024):
                    pass
            except (BrokenPipeError, ConnectionResetError, socket.timeout):
                pass
            client.close()
            thread.join(3)
        finally:
            relay.terminate()
            try:
                relay.wait(timeout=2)
            except subprocess.TimeoutExpired:
                relay.kill()
                relay.wait(timeout=2)

        audit_text = audit.read_text() if audit.exists() else ""
        if enforce:
            assert b"GICxyz" not in received, received
            assert "containment-stream-cut" in audit_text, audit_text
        else:
            assert bytes(received) == b"abcMAGICxyz", received
            assert "trace-match" in audit_text, audit_text


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: test_trace_containment.py <ghostline_cli>")
    run_case(sys.argv[1], enforce=False)
    run_case(sys.argv[1], enforce=True)
    print("trace observation and containment tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
