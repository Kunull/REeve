"""Decompiler and disassembly tools."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated

from reeve.tools.base import tool

if TYPE_CHECKING:
    from reeve.host.base import HostBridge


def make_decompiler_tools(host: "HostBridge"):
    @tool(category="decompiler", readonly=True, requires_decompiler=True)
    def decompile_function(address: Annotated[int, "Function start address"]) -> str:
        """Decompile a function and return the pseudocode."""
        return host.decompile(address)

    @tool(category="disassembly", readonly=True)
    def read_disassembly(
        address: Annotated[int, "Function start address"],
        max_lines: Annotated[int, "Maximum instruction lines to return"] = 50,
    ) -> str:
        """Return raw disassembly for a function."""
        return host.get_disassembly(address, max_lines)

    return [
        decompile_function._tool_definition,
        read_disassembly._tool_definition,
    ]
