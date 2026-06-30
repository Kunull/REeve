"""Navigation tools — cursor, segment listing, address lookup."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Optional

from reeve.tools.base import tool

if TYPE_CHECKING:
    from reeve.host.base import HostBridge


def make_navigation_tools(host: "HostBridge"):
    @tool(category="navigation", readonly=True)
    def get_entry_point() -> str:
        """Return the binary entry point address."""
        return hex(host.get_entry_point())

    @tool(category="navigation", readonly=True)
    def get_binary_info() -> str:
        """Return binary format, architecture, and path."""
        return f"path={host.get_binary_path()} arch={host.get_arch()} format={host.get_format()}"

    @tool(category="navigation", readonly=True)
    def read_bytes(
        address: Annotated[int, "Start address (hex ok, e.g. 0x401000)"],
        count: Annotated[int, "Number of bytes to read"],
    ) -> str:
        """Read raw bytes from the binary at the given address."""
        data = host.read_bytes(address, count)
        return data.hex()

    return [
        get_entry_point._tool_definition,
        get_binary_info._tool_definition,
        read_bytes._tool_definition,
    ]
