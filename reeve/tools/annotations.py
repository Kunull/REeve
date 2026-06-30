"""Annotation tools — rename, comment, set prototype."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated

from reeve.core.knowledge_graph import Fact, FactSource
from reeve.tools.base import tool

if TYPE_CHECKING:
    from reeve.core.knowledge_graph import KnowledgeGraph
    from reeve.host.base import HostBridge


def make_annotation_tools(host: "HostBridge", graph: "KnowledgeGraph"):
    @tool(category="annotations", readonly=False, mutating=True)
    def rename_function(
        address: Annotated[int, "Function address"],
        name: Annotated[str, "New function name (snake_case)"],
    ) -> str:
        """Rename a function in the disassembler and update the knowledge graph."""
        host.rename_function(address, name)
        graph.update_function_name(
            address, name, confidence=1.0,
            source=FactSource.ANALYST, evidence=[f"manually renamed to {name}"],
        )
        fn = graph.get_function(address)
        if fn:
            fn.is_resolved = True
        return f"Renamed 0x{address:x} → {name}"

    @tool(category="annotations", readonly=False, mutating=True)
    def set_comment(
        address: Annotated[int, "Function or instruction address"],
        comment: Annotated[str, "Comment text"],
    ) -> str:
        """Add or update a comment at the given address."""
        host.set_comment(address, comment)
        fn = graph.get_function(address)
        if fn:
            fn.comment = comment
        return f"Comment set at 0x{address:x}"

    @tool(category="annotations", readonly=False, mutating=True)
    def set_prototype(
        address: Annotated[int, "Function address"],
        prototype: Annotated[str, "C function prototype, e.g. 'int foo(char* buf, int len)'"],
    ) -> str:
        """Set the type/prototype for a function."""
        host.set_function_prototype(address, prototype)
        fn = graph.get_function(address)
        if fn:
            fn.prototype.update(prototype, 1.0, FactSource.ANALYST, [f"manually typed: {prototype}"])
        return f"Prototype set for 0x{address:x}: {prototype}"

    return [
        rename_function._tool_definition,
        set_comment._tool_definition,
        set_prototype._tool_definition,
    ]
