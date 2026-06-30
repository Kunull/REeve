"""
ToolGateway — executes tools, tracks mutations, enforces approval gates.
All disassembler interactions from the LLM loop go through here.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional

from reeve.core.events import EventKind, bus
from reeve.tools.base import ToolDefinition

if TYPE_CHECKING:
    from reeve.core.session import Session

logger = logging.getLogger(__name__)


class ApprovalRequired(Exception):
    """Raised when a mutation requires analyst approval that hasn't been given."""


class ToolGateway:
    def __init__(self, session: "Session", auto_approve: bool = False) -> None:
        self._session = session
        self._auto_approve = auto_approve
        self._tools: Dict[str, ToolDefinition] = {}

    def register(self, tool_def: ToolDefinition) -> None:
        self._tools[tool_def.name] = tool_def

    def register_all(self, tool_defs: List[ToolDefinition]) -> None:
        for t in tool_defs:
            self.register(t)

    def all_schemas(self) -> List[dict]:
        return [t.to_anthropic_schema() for t in self._tools.values()]

    def execute(self, tool_name: str, args: Dict[str, Any]) -> Any:
        tool = self._tools.get(tool_name)
        if tool is None:
            raise ValueError(f"Unknown tool: {tool_name}")

        if tool.requires_approval and not self._auto_approve:
            raise ApprovalRequired(
                f"Tool '{tool_name}' requires analyst approval. "
                "Call approve_and_execute() or enable auto_approve."
            )

        bus.emit(
            EventKind.TOOL_CALL_START,
            session_id=self._session.id,
            tool_name=tool_name,
            args=args,
        )

        if tool.mutating:
            pre_state = self._capture_pre_state(tool_name, args)

        try:
            result = tool.handler(**args)
        except Exception as exc:
            logger.error("Tool %s failed: %s", tool_name, exc)
            raise

        if tool.mutating:
            post_state = self._capture_post_state(tool_name, args, result)
            self._session.record_mutation(
                tool_name=tool_name,
                address=args.get("address", 0),
                pre_state=pre_state,
                post_state=post_state,
                description=f"{tool_name}({args})",
            )
            bus.emit(
                EventKind.MUTATION_RECORDED,
                session_id=self._session.id,
                tool_name=tool_name,
                address=args.get("address", 0),
            )

        bus.emit(
            EventKind.TOOL_CALL_RESULT,
            session_id=self._session.id,
            tool_name=tool_name,
            success=True,
        )
        return result

    def approve_and_execute(self, tool_name: str, args: Dict[str, Any]) -> Any:
        """Execute a requires_approval tool without raising ApprovalRequired."""
        old = self._auto_approve
        self._auto_approve = True
        try:
            return self.execute(tool_name, args)
        finally:
            self._auto_approve = old

    def _capture_pre_state(self, tool_name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        address = args.get("address", 0)
        state: Dict[str, Any] = {"address": address}
        host = self._session.host
        try:
            if tool_name in ("rename_function",):
                fn = self._session.graph.get_function(address)
                state["name"] = fn.display_name if fn else ""
            elif tool_name in ("write_bytes", "patch_branch"):
                count = len(args.get("hex_bytes", "")) // 2 if "hex_bytes" in args else 1
                state["bytes"] = host.read_bytes(address, max(count, 4)).hex()
        except Exception:
            pass
        return state

    def _capture_post_state(self, tool_name: str, args: Dict[str, Any], result: Any) -> Dict[str, Any]:
        return {"args": {k: str(v) for k, v in args.items()}}

    def undo_last(self, n: int = 1) -> int:
        records = self._session.undo(n)
        reverted = 0
        host = self._session.host
        for record in records:
            try:
                if record.tool_name == "rename_function":
                    old_name = record.pre_state.get("name", "")
                    if old_name:
                        host.rename_function(record.address, old_name)
                        reverted += 1
                elif record.tool_name in ("write_bytes", "patch_branch"):
                    old_bytes = bytes.fromhex(record.pre_state.get("bytes", ""))
                    if old_bytes:
                        host.write_bytes(record.address, old_bytes)
                        reverted += 1
            except Exception as exc:
                logger.warning("Failed to undo %s: %s", record.tool_name, exc)
        return reverted
