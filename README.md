# netsniff

A simple, ethical-by-design network packet sniffer built on [scapy](https://scapy.net/).
Capture packets on a chosen interface, filter them with BPF syntax, and print
human-readable summaries — or stream them to structured JSON and raw PCAP files.

## Features

- Live packet capture on any interface, with an up-front privilege check
- BPF capture filters (`-f "tcp port 443"`) plus convenience filters:
  `-p {tcp,udp,icmp,arp,dns,http}`, `--host`, `--port`
- Human-readable output: timestamp, source/destination IP + port, protocol,
  TCP flags, payload length, and a hex/ASCII payload preview
- `-o capture.pcap` writes raw packets via scapy's `PcapWriter`
- `--json log.jsonl` writes one structured JSON object per packet
- Colorized console output (auto-detected; disable with `--no-color`)
- Graceful permission errors that suggest `sudo` or `setcap`
- Type-hinted, documented code; tested with `pytest`; linted with `ruff`

## Requirements

- Python 3.10+
- [scapy](https://scapy.net/) (the only runtime dependency)
- Root privileges or `CAP_NET_RAW` to capture (see below)

## Installation

```bash
git clone https://github.com/example/netsniff.git
cd netsniff
pip install -e .
```

For development (pytest + ruff):

```bash
pip install -e ".[dev]"
```

## Usage

> **You must be root** (or hold `CAP_NET_RAW`) to capture packets:

```bash
sudo netsniff -i eth0
```

Without root, netsniff exits with a helpful message suggesting `sudo` or:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))
```

(note: `setcap` on the Python binary applies to *every* Python program on the system).

### Examples

```bash
# Capture 10 packets on the default interface
sudo netsniff -c 10

# TCP traffic only, on a specific interface
sudo netsniff -i wlan0 -p tcp

# All traffic to/from one host, any protocol
sudo netsniff --host 192.168.1.20

# DNS queries, saved as structured JSON
sudo netsniff -p dns --json dns-log.jsonl

# Raw BPF filter + PCAP recording + JSON logging at once
sudo netsniff -f "tcp port 443" -o tls.pcap --json tls.jsonl

# List available interfaces (no privileges needed)
netsniff --list-interfaces
```

### CLI options

| Option | Description |
| --- | --- |
| `-i`, `--interface` | Network interface to capture on (default: system default) |
| `-f`, `--filter` | Raw BPF capture filter, e.g. `tcp port 443` |
| `-p`, `--protocol` | Filter by protocol: `tcp`, `udp`, `icmp`, `arp`, `dns`, `http` |
| `--host` | Filter by host IP address |
| `--port` | Filter by port number |
| `-c`, `--count` | Number of packets to capture (default: `0` = unlimited) |
| `-o`, `--output` | Write raw packets to a PCAP file |
| `--json` | Write structured logs to a JSON Lines file |
| `--no-color` | Disable colored console output |
| `--list-interfaces` | List available interfaces and exit |

### Sample output

See [`examples/sample_output.txt`](examples/sample_output.txt):

```
12:04:31.104218  TCP   192.168.1.10:51544    -> 192.168.1.20:443       [S]        0B
12:04:31.104771  TCP   192.168.1.20:443      -> 192.168.1.10:51544     [SA]       0B
12:04:31.105310  TCP   192.168.1.10:51544    -> 192.168.1.20:443       [PA]     517B
                                16 03 01 02 00 01 00 01 fc 03 03 1a 2b 3c 4d 5e | ...........+<M^ …
```

## Development

```bash
pip install -e ".[dev]"
ruff check .     # lint
pytest           # unit tests (crafted packets; no root or live traffic needed)
```

Continuous integration (GitHub Actions) runs `ruff check` and `pytest` on
Python 3.10–3.13 for every push and pull request to `main`.

## How it works

- `netsniff/sniffer.py` — argparse CLI; builds BPF filters and wires everything together
- `netsniff/capture.py` — scapy `sniff` loop dispatching packets to all outputs
- `netsniff/parsers.py` — protocol detection (TCP/UDP/ICMP/ARP/DNS/HTTP) and record building
- `netsniff/output.py` — console formatter, JSON Lines logger, PCAP writer
- `netsniff/utils.py` — privilege checks and interface helpers

## Legal and ethical use

**Only sniff networks you own or have explicit permission to monitor.**
Capturing traffic on networks without authorization is illegal in most
jurisdictions (e.g., under wiretap and computer-misuse laws) and may violate
privacy regulations such as the GDPR. Even on your own network, inform the
people whose traffic you may capture, minimize what you collect, and handle
captured data securely. The authors accept no liability for misuse of this
software.

## License

MIT — see [LICENSE](LICENSE).
