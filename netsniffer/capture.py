"""Packet capture engine built on scapy's sniff loop."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from scapy.sendrecv import sniff

from netsniff.output import ConsoleFormatter, JsonLogger, PcapLogger
from netsniff.parsers import parse_packet


class PacketCapture:
    """Capture packets on an interface and dispatch them to the outputs.

    Attributes:
        interface: Interface name to capture on.
        bpf_filter: Berkeley Packet Filter expression, or None.
        formatter: Console line formatter.
        json_logger: Optional JSON Lines logger.
        pcap_logger: Optional raw-PCAP logger.
        packet_count: Packets to capture (0 = unlimited).
        on_packet: Optional callback receiving each parsed record.
    """

    def __init__(
        self,
        interface: str,
        bpf_filter: str | None,
        formatter: ConsoleFormatter,
        json_logger: JsonLogger | None = None,
        pcap_logger: PcapLogger | None = None,
        packet_count: int = 0,
        on_packet: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.formatter = formatter
        self.json_logger = json_logger
        self.pcap_logger = pcap_logger
        self.packet_count = packet_count
        self.on_packet = on_packet
        self.packets_seen = 0

    def handle_packet(self, packet: Any) -> None:
        """Process one captured packet: log raw, parse, print, JSON-log."""
        self.packets_seen += 1
        if self.pcap_logger is not None:
            self.pcap_logger.write(packet)
        record = parse_packet(packet)
        print(self.formatter.format(record), flush=True)
        if self.json_logger is not None:
            self.json_logger.log(record)
        if self.on_packet is not None:
            self.on_packet(record)

    def start(self) -> None:
        """Start capturing; blocks until count is reached or interrupted."""
        sniff(
            iface=self.interface,
            filter=self.bpf_filter,
            prn=self.handle_packet,
            count=self.packet_count or 0,
            store=False,
        )
