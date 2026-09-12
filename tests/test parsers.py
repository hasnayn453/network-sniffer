"""Unit tests for protocol parsers using scapy-crafted packets."""

from __future__ import annotations

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.http import HTTPRequest
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

from netsniff.parsers import detect_protocol, parse_packet


def tcp_syn_packet() -> Ether:
    """A crafted Ethernet/IPv4/TCP SYN with a small payload."""
    return (
        Ether()
        / IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=51000, dport=443, flags="S")
        / Raw(b"hello")
    )


def test_detect_tcp_syn() -> None:
    assert detect_protocol(tcp_syn_packet()) == "TCP"


def test_parse_tcp_syn() -> None:
    rec = parse_packet(tcp_syn_packet())
    assert rec["protocol"] == "TCP"
    assert rec["src"] == "192.168.1.10"
    assert rec["dst"] == "192.168.1.20"
    assert rec["sport"] == 51000
    assert rec["dport"] == 443
    assert "S" in rec["flags"]
    assert rec["length"] == 5
    assert "hello" in rec["payload_preview"]


def test_parse_udp() -> None:
    pkt = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=12345, dport=5353)
    rec = parse_packet(pkt)
    assert rec["protocol"] == "UDP"
    assert rec["sport"] == 12345
    assert rec["dport"] == 5353
    assert rec["length"] == 0
    assert rec["payload_preview"] == ""


def test_parse_dns_query() -> None:
    pkt = IP(src="10.0.0.5", dst="1.1.1.1") / UDP(sport=40000, dport=53) / DNS(
        qd=DNSQR(qname="example.com")
    )
    rec = parse_packet(pkt)
    assert rec["protocol"] == "DNS"
    assert rec["dport"] == 53
    assert "example.com" in rec["info"]


def test_parse_icmp_echo() -> None:
    pkt = IP(src="1.1.1.1", dst="2.2.2.2") / ICMP(type=8)
    rec = parse_packet(pkt)
    assert rec["protocol"] == "ICMP"
    assert rec["src"] == "1.1.1.1"
    assert rec["dst"] == "2.2.2.2"


def test_parse_arp_who_has() -> None:
    pkt = Ether() / ARP(psrc="192.168.1.1", pdst="192.168.1.50", op=1)
    rec = parse_packet(pkt)
    assert rec["protocol"] == "ARP"
    assert rec["src"] == "192.168.1.1"
    assert rec["dst"] == "192.168.1.50"
    assert "who-has" in rec["info"]


def test_parse_arp_reply() -> None:
    pkt = Ether() / ARP(psrc="192.168.1.50", pdst="192.168.1.1", op=2)
    rec = parse_packet(pkt)
    assert "reply" in rec["info"]


def test_detect_http_by_port() -> None:
    pkt = IP() / TCP(sport=80, dport=51111, flags="PA") / Raw(b"HTTP/1.1 200 OK\r\n")
    assert detect_protocol(pkt) == "HTTP"


def test_detect_http_by_layer() -> None:
    pkt = (
        Ether()
        / IP()
        / TCP(dport=80)
        / HTTPRequest(Method=b"GET", Path=b"/", Http_Version=b"HTTP/1.1")
    )
    assert detect_protocol(pkt) == "HTTP"


def test_detect_other() -> None:
    assert detect_protocol(Ether()) == "OTHER"


def test_payload_preview_truncates() -> None:
    big = bytes(range(256)) * 4
    pkt = IP() / TCP(flags="PA") / Raw(big)
    rec = parse_packet(pkt)
    assert rec["length"] == len(big)
    assert rec["payload_preview"].endswith("…")


def test_record_is_json_serialisable() -> None:
    import json

    rec = parse_packet(tcp_syn_packet())
    json.dumps(rec)  # raises if not serialisable
    assert rec["timestamp"].endswith("+00:00")
