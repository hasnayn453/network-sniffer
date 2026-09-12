"""Unit tests for output formatters and loggers."""

from __future__ import annotations

import json

from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from scapy.utils import PcapReader

from netsniff.output import ConsoleFormatter, JsonLogger, PcapLogger
from netsniff.parsers import parse_packet


def make_record() -> dict:
    """A parsed TCP record with a small payload."""
    pkt = (
        IP(src="192.168.0.2", dst="192.168.0.1")
        / TCP(sport=443, dport=50000, flags="PA")
        / Raw(b"data")
    )
    return parse_packet(pkt)


def test_console_formatter_plain() -> None:
    line = ConsoleFormatter(use_color=False).format(make_record())
    assert "TCP" in line
    assert "192.168.0.2:443" in line
    assert "192.168.0.1:50000" in line
    assert "[PA]" in line
    assert "4B" in line
    assert "data" in line


def test_console_formatter_color() -> None:
    line = ConsoleFormatter(use_color=True).format(make_record())
    assert "\033[" in line


def test_console_formatter_handles_no_ports() -> None:
    rec = {
        "timestamp": "2026-09-11T12:00:00.000000+00:00",
        "protocol": "OTHER",
        "src": None,
        "dst": None,
        "sport": None,
        "dport": None,
        "flags": "",
        "length": 0,
        "payload_preview": "",
        "info": "",
    }
    line = ConsoleFormatter(use_color=False).format(rec)
    assert "OTHER" in line
    assert "0B" in line


def test_json_logger_roundtrip(tmp_path) -> None:
    path = tmp_path / "out.jsonl"
    logger = JsonLogger(path)
    logger.log(make_record())
    logger.close()

    lines = path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["protocol"] == "TCP"


def test_json_logger_appends(tmp_path) -> None:
    path = tmp_path / "out.jsonl"
    logger = JsonLogger(path)
    logger.log(make_record())
    logger.close()
    logger2 = JsonLogger(path)
    logger2.log(make_record())
    logger2.close()

    lines = path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2


def test_pcap_logger_roundtrip(tmp_path) -> None:
    path = tmp_path / "out.pcap"
    pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(dport=80, flags="S")

    logger = PcapLogger(path)
    logger.write(pkt)
    logger.close()

    read_back = list(PcapReader(str(path)))
    assert len(read_back) == 1
    assert read_back[0][TCP].dport == 80
    assert read_back[0][IP].src == "10.0.0.1"
