"""netsniff — a simple, ethical-by-design network packet sniffer.

Built on scapy. Capture packets on a chosen interface, filter with BPF
syntax, and print human-readable, JSON, or PCAP output.
"""

from netsniff.parsers import detect_protocol, parse_packet

__all__ = ["detect_protocol", "parse_packet"]
__version__ = "0.1.0"
