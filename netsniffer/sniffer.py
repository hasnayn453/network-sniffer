"""Command-line interface for the netsniff packet sniffer."""

from __future__ import annotations

import argparse
import sys

from netsniff.capture import PacketCapture
from netsniff.output import ConsoleFormatter, JsonLogger, PcapLogger
from netsniff.utils import (
    PermissionDeniedError,
    ensure_privileges,
    list_interfaces,
    resolve_interface,
)

PROTOCOL_TO_BPF: dict[str, str] = {
    "tcp": "tcp",
    "udp": "udp",
    "icmp": "icmp",
    "arp": "arp",
    "dns": "port 53",
    "http": "tcp port 80",
}


def build_parser() -> argparse.ArgumentParser:
    """Build the argparse parser for the netsniff CLI."""
    parser = argparse.ArgumentParser(
        prog="netsniff",
        description="Capture and analyze network traffic (requires root / CAP_NET_RAW).",
        epilog="Ethical use: only sniff networks you own or have explicit permission to monitor.",
    )
    parser.add_argument(
        "-i", "--interface", help="network interface to capture on (default: system default)"
    )
    parser.add_argument(
        "-f", "--filter", dest="bpf_filter", help="BPF capture filter, e.g. 'tcp port 443'"
    )
    parser.add_argument(
        "-p",
        "--protocol",
        choices=sorted(PROTOCOL_TO_BPF),
        help="filter by protocol (tcp, udp, icmp, arp, dns, http)",
    )
    parser.add_argument("--host", help="filter by host IP address")
    parser.add_argument("--port", type=int, help="filter by port number")
    parser.add_argument(
        "-c", "--count", type=int, default=0, help="packets to capture (0 = unlimited)"
    )
    parser.add_argument(
        "-o", "--output", metavar="FILE.pcap", help="write raw packets to a PCAP file"
    )
    parser.add_argument(
        "--json", metavar="FILE.jsonl", help="write structured JSON logs (JSON Lines)"
    )
    parser.add_argument("--no-color", action="store_true", help="disable colored output")
    parser.add_argument(
        "--list-interfaces", action="store_true", help="list available interfaces and exit"
    )
    return parser


def build_bpf_filter(args: argparse.Namespace) -> str | None:
    """Combine --filter / --protocol / --host / --port into one BPF string."""
    if args.bpf_filter:
        return args.bpf_filter
    parts: list[str] = []
    if args.protocol:
        parts.append(PROTOCOL_TO_BPF[args.protocol])
    if args.host:
        parts.append(f"host {args.host}")
    if args.port:
        parts.append(f"port {args.port}")
    return " and ".join(parts) if parts else None


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns a process exit code."""
    args = build_parser().parse_args(argv)

    if args.list_interfaces:
        for iface in list_interfaces():
            print(iface)
        return 0

    try:
        iface = resolve_interface(args.interface)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    try:
        ensure_privileges()
    except PermissionDeniedError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    bpf = build_bpf_filter(args)

    formatter = ConsoleFormatter(use_color=not args.no_color and sys.stdout.isatty())
    json_logger = JsonLogger(args.json) if args.json else None
    pcap_logger = PcapLogger(args.output) if args.output else None

    capture = PacketCapture(
        interface=iface,
        bpf_filter=bpf,
        formatter=formatter,
        json_logger=json_logger,
        pcap_logger=pcap_logger,
        packet_count=args.count,
    )

    filter_note = f" | filter: {bpf}" if bpf else ""
    print(f"[*] netsniff listening on {iface}{filter_note}", file=sys.stderr)
    try:
        capture.start()
    except KeyboardInterrupt:
        print("\n[*] capture stopped by user", file=sys.stderr)
    except PermissionError as exc:
        print(f"error: permission denied opening raw socket: {exc}", file=sys.stderr)
        return 1
    finally:
        if json_logger is not None:
            json_logger.close()
        if pcap_logger is not None:
            pcap_logger.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
