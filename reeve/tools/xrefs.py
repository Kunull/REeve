"""Cross-reference tools."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Annotated

from reeve.tools.base import tool

if TYPE_CHECKING:
    from reeve.host.base import HostBridge


def make_xref_tools(host: "HostBridge"):
    @tool(category="xrefs", readonly=True)
    def xrefs_to(address: Annotated[int, "Target address"]) -> str:
        """List all cross-references to the given address."""
        refs = host.xrefs_to(address)
        return json.dumps([{"from": hex(r.from_address), "kind": r.kind} for r in refs], indent=2)

    @tool(category="xrefs", readonly=True)
    def xrefs_from(address: Annotated[int, "Source address"]) -> str:
        """List all cross-references from the given address."""
        refs = host.xrefs_from(address)
        return json.dumps([{"to": hex(r.to_address), "kind": r.kind} for r in refs], indent=2)

    return [
        xrefs_to._tool_definition,
        xrefs_from._tool_definition,
    ]
