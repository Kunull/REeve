"""Import/export listing tools."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Annotated

from reeve.tools.base import tool

if TYPE_CHECKING:
    from reeve.core.knowledge_graph import KnowledgeGraph
    from reeve.host.base import HostBridge


def make_database_tools(host: "HostBridge", graph: "KnowledgeGraph"):
    @tool(category="database", readonly=True)
    def list_imports(category: Annotated[str, "Filter by category (network/crypto/filesystem/process/memory/all)"] = "all") -> str:
        """List imported symbols, optionally filtered by behavioral category."""
        if category == "all":
            imports = graph.all_imports()
        else:
            imports = graph.imports_by_category(category)
        rows = [
            {"name": i.name, "library": i.library,
             "address": hex(i.resolved_address) if i.resolved_address else None,
             "categories": i.categories}
            for i in imports
        ]
        return json.dumps(rows, indent=2)

    @tool(category="database", readonly=True)
    def list_exports() -> str:
        """List exported symbols from the binary."""
        exports = host.list_exports()
        return json.dumps(exports, indent=2)

    @tool(category="database", readonly=True)
    def knowledge_graph_stats() -> str:
        """Return statistics about the current knowledge graph."""
        return json.dumps(graph.stats, indent=2)

    return [
        list_imports._tool_definition,
        list_exports._tool_definition,
        knowledge_graph_stats._tool_definition,
    ]
