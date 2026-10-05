# Ghostline Field Capture

## Purpose

Field Capture is a small, bounded diagnostic layer for operating when ordinary
network tooling, package repositories, or graphical analyzers are unavailable.
It captures only bytes that already traverse a Ghostline relay. It does not put
a NIC into promiscuous mode, require root, scan a subnet, recover full IP/TCP
headers, or inspect traffic belonging to another process.

Use it only with equipment and traffic you own or are authorized to service.

## Observe-only TCP capture

```sh
ghostline_cli 17777 192.0.2.10 1883 \
  --observe-only \
  --protocol-hint mqtt \
  --expect-connack \
  --capture state/field.glcap \
  --capture-pcap state/field.pcap \
  --capture-max-bytes 4194304 \
  --capture-snaplen 1024
```

Point the authorized client at `127.0.0.1:17777`. Ghostline records stream
reads before plugin decisions and forwards original bytes. The capture files
are truncated at process start so a forgotten field session cannot accumulate
across restarts. The payload ceiling applies per run.

Render the last records without Wireshark:

```sh
ghostline_cli --read-capture state/field.glcap --capture-tail 24
```

`--capture-hex` prints the same offset/hex/ASCII view live.

## MQTT CONNACK

With `--protocol-hint mqtt` or `--expect-connack`, a complete MQTT control
packet receives a compact summary. For CONNACK this includes direction,
Remaining Length, Session Present, and the reason code. The original packet is
still captured and forwarded.

MQTT over TLS remains encrypted. Ghostline does not break or silently terminate
TLS. A CONNACK can only be decoded when the application deliberately places an
authorized plaintext MQTT connection through the relay.

The OASIS MQTT 5.0 standard defines CONNACK as server-to-client packet type 2,
with Connect Acknowledge Flags and a Reason Code in its variable header:
<https://docs.oasis-open.org/mqtt/mqtt/v5.0/mqtt-v5.0.html#_Toc3901078>

## Serial and vCOM

TCP-to-serial exposes one serial device to a local TCP client:

```sh
ghostline_cli \
  --serial-device /dev/ttyWK0 \
  --baud 115200 \
  --listen-host 127.0.0.1 \
  --listen-port 17777 \
  --capture state/uart.glcap \
  --capture-pcap state/uart.pcap
```

Serial-to-serial relays a virtual/ingress port to a physical/upstream port:

```sh
ghostline_cli \
  --serial-ingress /dev/ttyVIRTUAL0 \
  --ingress-baud 57600 \
  --serial-device /dev/ttyUSB0 \
  --baud 115200 \
  --data-bits 8 --parity none --stop-bits 1 \
  --capture state/serial-pair.glcap
```

Serial relays are always observe-only. Ghostline does not apply mutation
plugins to them.

The seeded `com0com-serial-pair.json` uses `COM5` and `COM6` placeholders.
com0com creates paired Windows virtual ports; its companion tools can bridge
COM and TCP or distribute one serial source. See the official project:
<https://com0com.sourceforge.net/>.

The profile schema is ready for com0com, including two port names and independent
baud metadata. Ghostline's active serial runtime is currently macOS/Linux; the
Win32 execution backend remains pending and reports that honestly.

## Capture formats

### GLCAP1

GLCAP1 is tab-separated recovery text:

```text
GLCAP1  unix_ns  flow  direction  transport  original_bytes  summary  hex  ascii
```

It can be inspected with Ghostline, `less`, `awk`, a text editor, or another
machine after storage recovery.

### PCAP / DLT_USER0

The optional PCAP uses `DLT_USER0` (`LINKTYPE_USER0`, value 147). Each record is
a Ghostline header followed by captured application-stream bytes:

```text
GLC1 | version | transport | direction | reserved | flow-id-be | payload
```

Wireshark opens the file and provides packet ordering, timestamps, lengths, and
hex inspection. Because Ghostline is an application relay, this is user data,
not a fabricated Ethernet/IP/TCP packet. Wireshark documents configurable user
DLTs in its user guide:
<https://www.wireshark.org/docs/wsug_html_chunked/ChCustProtocolDissectionSection.html>.

## Target profiles

Runtime profiles now preserve:

- TCP listen and upstream endpoints;
- `tcp`, `tcp-serial`, or `serial-pair` transport;
- serial ingress/upstream names;
- ingress and upstream baud;
- data bits, parity, stop bits, and flow control;
- protocol hint and MQTT CONNACK expectation;
- observe-only state;
- GLCAP/PCAP paths, total payload budget, and snap length.

```sh
ghostline_cli --seed-target-profiles state/profiles
ghostline_cli --show-target-profile state/profiles/com0com-serial-pair.json
ghostline_cli --run-target-profile state/profiles/field-serial-console.json
```

## End-of-world operating checklist

1. Photograph or write down connector pinouts before power is applied.
2. Confirm voltage level and isolation; UART, RS-232, RS-485, CAN, USB, and
   Ethernet are not electrically interchangeable.
3. Search the offline manual and record the exact device model.
4. Start in observe-only mode with a small capture budget.
5. Verify both directions using a harmless known command or loopback fixture.
6. Preserve the GLCAP file first; PCAP is the convenience derivative.
7. Record baud/framing, timestamps, wiring, and results in the field journal.
8. Stop the relay when finished. Captures may contain credentials or private
   operational data; protect them like a journal or key material.
