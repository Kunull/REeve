"""String listing and search tools."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Annotated

from reeve.tools.base import tool

if TYPE_CHECKING:
    from reeve.core.knowledge_graph import KnowledgeGraph
    from reeve.host.base import HostBridge


def make_string_tools(host: "HostBridge", graph: "KnowledgeGraph"):
    @tool(category="strings", readonly=True)
    def list_strings(limit: Annotated[int, "Max strings to return"] = 50) -> str:
        """List strings found in the binary."""
        strings = graph.all_strings()[:limit]
        rows = [{"address": hex(s.address), "value": s.value, "category": s.category}
                for s in strings]
        return json.dumps(rows, indent=2)

    @tool(category="strings", readonly=True)
    def search_strings(query: Annotated[str, "Substring to search for in string values"]) -> str:
        """Search for strings containing the given substring."""
        q = query.lower()
        matches = [s for s in graph.all_strings() if q in s.value.lower()][:20]
        rows = [{"address": hex(s.address), "value": s.value, "category": s.category}
                for s in matches]
        return json.dumps(rows, indent=2)

    @tool(category="strings", readonly=True)
    def strings_by_category(category: Annotated[str, "Category: url/path/error/format/uuid/crypto/unknown"]) -> str:
        """List strings in a specific category."""
        strings = graph.strings_by_category(category)[:30]
        rows = [{"address": hex(s.address), "value": s.value} for s in strings]
        return json.dumps(rows, indent=2)

    @tool(category="strings", readonly=True)
    def strings_for_function(address: Annotated[int, "Function address"]) -> str:
        """List strings referenced by a specific function."""
        strings = graph.strings_referenced_by(address)
        rows = [{"address": hex(s.address), "value": s.value, "category": s.category}
                for s in strings]
        return json.dumps(rows, indent=2)

    return [
        list_strings._tool_definition,
        search_strings._tool_definition,
        strings_by_category._tool_definition,
        strings_for_function._tool_definition,
    ]
