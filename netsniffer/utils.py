"""Privilege and interface helpers for netsniff."""

from __future__ import annotations

import os
from functools import lru_cache


class PermissionDeniedError(PermissionError):
    """Raised when packet-capture privileges are missing."""


def is_root() -> bool:
    """Return True if the process runs with root privileges (POSIX only)."""
    geteuid = getattr(os, "geteuid", None)
    return geteuid() == 0 if geteuid is not None else True


def ensure_privileges() -> None:
    """Verify the process can open a raw socket.

    Raises:
        PermissionDeniedError: with actionable advice (sudo / setcap) when
            the process lacks root privileges.
    """
    if is_root():
        return
    raise PermissionDeniedError(
        "packet capture requires root privileges or CAP_NET_RAW.\n"
        "  - run again with sudo:  sudo netsniff ...\n"
        "  - or grant the capability to your Python binary:\n"
        "      sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))\n"
        "    (note: this applies to every Python program on the system)"
    )


@lru_cache(maxsize=1)
def list_interfaces() -> list[str]:
    """Return the names of all network interfaces known to the system."""
    from scapy.arch import get_if_list  # deferred: scapy import is slow

    return sorted(get_if_list())


def resolve_interface(name: str | None) -> str:
    """Validate a user-supplied interface, or pick the system default.

    Args:
        name: Interface name, or None to use scapy's default interface.

    Returns:
        The interface name to capture on.

    Raises:
        ValueError: If the named interface does not exist.
    """
    if name is None:
        from scapy.config import conf  # deferred: scapy import is slow

        return str(conf.iface)
    available = list_interfaces()
    if name not in available:
        raise ValueError(
            f"interface {name!r} not found; available: {', '.join(available) or '(none)'}"
        )
    return name
