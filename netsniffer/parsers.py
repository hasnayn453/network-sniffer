"""Protocol-aware parsing of captured scapy packets."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP
from scapy.packet import Packet, Raw

try:  # scapy >= 2.4.3 ships the HTTP layer
    from scapy.layers.http import HTTPRequest, HTTPResponse
except ImportError:  # pragma: no cover - very old scapy
    HTTPRequest = None  # type: ignore[assignment]
    HTTPResponse = None  # type: ignore[assignment]

_PREVIEW_LENGTH = 32


def detect_protocol(packet: Packet) -> str:
    """Identify the highest-level protocol present in a packet.

    Order matters: ARP and ICMP are link/network diagnostics, DNS rides on
    UDP/TCP, and HTTP is inferred from the TCP ports or the parsed HTTP layer.
    """
    if packet.haslayer(ARP):
        return "ARP"
    if packet.haslayer(ICMP):
        return "ICMP"
    if packet.haslayer("DNS"):
        return "DNS"
    if packet.haslayer(TCP):
        if HTTPRequest is not None and (
            packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse)
        ):
            return "HTTP"
        sport, dport = int(packet[TCP].sport), int(packet[TCP].dport)
        if sport in (80, 8080) or dport in (80, 8080):
            return "HTTP"
        return "TCP"
    if packet.haslayer(UDP):
        return "UDP"
    return "OTHER"


def _payload(packet: Packet) -> bytes:
    """Return the raw payload bytes of the last layer, if any."""
    if packet.haslayer(Raw):
        return bytes(packet[Raw].load)
    return b""


def _preview(data: bytes, limit: int) -> str:
    """Build a compact ``hex | ascii`` preview of payload bytes."""
    if not data:
        return ""
    chunk = data[:limit]
    hex_part = chunk.hex(" ")
    ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
    suffix = " …" if len(data) > limit else ""
    return f"{hex_part} | {ascii_part}{suffix}"


def parse_packet(packet: Packet, max_preview: int = _PREVIEW_LENGTH) -> dict[str, Any]:
    """Convert a scapy packet into a structured, JSON-serialisable record.

    Args:
        packet: The captured scapy packet.
        max_preview: Maximum number of payload bytes shown in the preview.

    Returns:
        A dict with keys: timestamp, protocol, src, dst, sport, dport,
        flags, length, payload_preview, info.
    """
    protocol = detect_protocol(packet)
    payload = _payload(packet)

    record: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="microseconds"),
        "protocol": protocol,
        "src": None,
        "dst": None,
        "sport": None,
        "dport": None,
        "flags": "",
        "length": len(payload),
        "payload_preview": _preview(payload, max_preview) if payload else "",
        "info": "",
    }

    if packet.haslayer(IP):
        record["src"] = packet[IP].src
        record["dst"] = packet[IP].dst
    elif packet.haslayer(ARP):
        record["src"] = packet[ARP].psrc
        record["dst"] = packet[ARP].pdst

    if packet.haslayer(TCP):
        record["sport"] = int(packet[TCP].sport)
        record["dport"] = int(packet[TCP].dport)
        record["flags"] = str(packet[TCP].flags)
    elif packet.haslayer(UDP):
        record["sport"] = int(packet[UDP].sport)
        record["dport"] = int(packet[UDP].dport)

    if packet.haslayer("DNS"):
        qd = packet["DNS"].qd  # PacketListField in scapy >= 2.6
        if qd:
            record["info"] = f"query {qd[0].qname.decode(errors='replace')}"
    elif packet.haslayer(ARP):
        if int(packet[ARP].op) == 1:
            record["info"] = f"who-has {packet[ARP].pdst} tell {packet[ARP].psrc}"
        else:
            record["info"] = f"reply {packet[ARP].psrc}"

    return record
