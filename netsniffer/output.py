"""Output formatters for netsniff: console, JSON Lines, and PCAP."""

from __future__ import annotations

import json
from pathlib import Path
from typing import IO, Any

from scapy.packet import Packet
from scapy.utils import PcapWriter

_RESET = "\033[0m"
_COLORS = {
    "TCP": "\033[96m",  # cyan
    "UDP": "\033[92m",  # green
    "ICMP": "\033[93m",  # yellow
    "ARP": "\033[95m",  # magenta
    "DNS": "\033[94m",  # blue
    "HTTP": "\033[91m",  # red
}


class ConsoleFormatter:
    """Render parsed packet records as one human-readable line each."""

    def __init__(self, use_color: bool = True) -> None:
        self.use_color = use_color

    @staticmethod
    def _endpoint(host: Any, port: Any) -> str:
        return f"{host}:{port}" if port is not None else str(host)

    def format(self, record: dict[str, Any]) -> str:
        """Format a single parsed packet record for terminal display."""
        proto = str(record.get("protocol", "OTHER"))
        ts = str(record.get("timestamp", ""))[11:26]  # HH:MM:SS.ffffff
        src = self._endpoint(record.get("src"), record.get("sport"))
        dst = self._endpoint(record.get("dst"), record.get("dport"))
        flags = f"[{record['flags']}]" if record.get("flags") else ""
        length = f"{record.get('length', 0)}B"

        if self.use_color:
            proto_field = f"{_COLORS.get(proto, '')}{proto:<5}{_RESET}"
        else:
            proto_field = f"{proto:<5}"

        line = f"{ts}  {proto_field} {src:<21} -> {dst:<21} {flags:<6} {length:>7}"
        if record.get("info"):
            line += f"  {record['info']}"
        if record.get("payload_preview"):
            line += f"\n{'':32}{record['payload_preview']}"
        return line


class JsonLogger:
    """Append parsed packet records to a JSON Lines (JSONL) file."""

    def __init__(self, path: str | Path) -> None:
        self._fh: IO[str] = open(path, "a", encoding="utf-8")

    def log(self, record: dict[str, Any]) -> None:
        """Write one record as a single JSON line."""
        self._fh.write(json.dumps(record) + "\n")
        self._fh.flush()

    def close(self) -> None:
        """Flush and close the underlying file handle."""
        self._fh.close()


class PcapLogger:
    """Write raw packets to a PCAP file using scapy's PcapWriter."""

    def __init__(self, path: str | Path) -> None:
        self._writer = PcapWriter(str(path), append=True, sync=True)

    def write(self, packet: Packet) -> None:
        """Append a raw packet to the PCAP file."""
        self._writer.write(packet)

    def close(self) -> None:
        """Flush and close the underlying PCAP writer."""
        self._writer.close()
