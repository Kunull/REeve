"""Function listing and lookup tools."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Annotated, Optional

from reeve.tools.base import tool

if TYPE_CHECKING:
    from reeve.core.knowledge_graph import KnowledgeGraph
    from reeve.host.base import HostBridge


def make_function_tools(host: "HostBridge", graph: "KnowledgeGraph"):
    @tool(category="functions", readonly=True)
    def list_functions(limit: Annotated[int, "Max functions to return"] = 50) -> str:
        """List all functions in the binary with address, name, and size."""
        fns = graph.all_functions()[:limit]
        rows = [
            {"address": hex(f.address), "name": f.display_name,
             "size_class": f.size_class.value, "confidence": round(f.name.confidence, 2)}
            for f in fns
        ]
        return json.dumps(rows, indent=2)

    @tool(category="functions", readonly=True)
    def get_function_info(address: Annotated[int, "Function address"]) -> str:
        """Get detailed info about a specific function."""
        fn = graph.get_function(address)
        if fn is None:
            return json.dumps({"error": f"No function at 0x{address:x}"})
        callees = [{"address": hex(c.address), "name": c.display_name} for c in graph.callees_of(address)]
        callers = [{"address": hex(c.address), "name": c.display_name} for c in graph.callers_of(address)]
        return json.dumps({
            "address": hex(fn.address),
            "name": fn.display_name,
            "raw_name": fn.raw_name,
            "confidence": fn.name.confidence,
            "size_class": fn.size_class.value,
            "source_lang": fn.source_lang.value,
            "obfuscated": fn.obfuscated,
            "is_resolved": fn.is_resolved,
            "comment": fn.comment,
            "prototype": fn.prototype.value,
            "callees": callees,
            "callers": callers,
        }, indent=2)

    @tool(category="functions", readonly=True)
    def search_functions(query: Annotated[str, "Partial name to search for"]) -> str:
        """Search functions by partial name match."""
        q = query.lower()
        matches = [
            f for f in graph.all_functions()
            if q in f.display_name.lower() or q in f.raw_name.lower()
        ]
        rows = [{"address": hex(f.address), "name": f.display_name} for f in matches[:20]]
        return json.dumps(rows, indent=2)

    @tool(category="functions", readonly=True)
    def list_unresolved(limit: Annotated[int, "Max to return"] = 30) -> str:
        """List functions that haven't been named yet."""
        fns = graph.find_functions(unresolved_only=True)[:limit]
        rows = [{"address": hex(f.address), "raw_name": f.raw_name,
                 "size_class": f.size_class.value} for f in fns]
        return json.dumps(rows, indent=2)

    return [
        list_functions._tool_definition,
        get_function_info._tool_definition,
        search_functions._tool_definition,
        list_unresolved._tool_definition,
    ]
