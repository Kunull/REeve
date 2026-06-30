"""
Session — unified state for an analysis run.
Tracks the binary, goal, mode, task graph, knowledge graph, mutations, and cost.
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Literal, Optional

from reeve.core.events import EventBus, bus as global_bus
from reeve.core.hypothesis import HypothesisEngine
from reeve.core.knowledge_graph import KnowledgeGraph
from reeve.llm.usage import CostTracker

if TYPE_CHECKING:
    from reeve.host.base import HostBridge
    from reeve.planning.tasks import Task

logger = logging.getLogger(__name__)

Mode = Literal["autonomous", "interactive", "paused"]


@dataclass
class MutationRecord:
    tool_name: str
    address: int
    pre_state: Dict[str, Any]
    post_state: Dict[str, Any]
    description: str


class Session:
    def __init__(
        self,
        goal: str,
        binary_path: str,
        host: "HostBridge",
        budget_usd: float = float("inf"),
        session_id: Optional[str] = None,
    ) -> None:
        self.id: str = session_id or str(uuid.uuid4())[:8]
        self.goal = goal
        self.binary_path = binary_path
        self.host = host
        self.mode: Mode = "autonomous"

        self.graph = KnowledgeGraph()
        self.cost_tracker = CostTracker()
        self.cost_tracker.set_ceiling(budget_usd)
        self.hypothesis_engine = HypothesisEngine(self.graph, session_id=self.id)

        self.mutation_log: List[MutationRecord] = []
        self.conversation: List[Dict[str, str]] = []
        self.report: Optional[str] = None

        # Task graph is managed by the executor
        self._tasks: Dict[str, "Task"] = {}

        # Per-session event bus (wraps global bus)
        self.bus = global_bus

        self.cost_tracker.set_ceiling(budget_usd)
        logger.info("Session %s started: goal=%r binary=%s", self.id, goal, binary_path)

    def pause(self) -> None:
        self.mode = "paused"
        logger.info("Session %s paused", self.id)

    def resume(self) -> None:
        self.mode = "autonomous"
        logger.info("Session %s resumed", self.id)

    def enter_interactive(self) -> None:
        self.mode = "interactive"

    def record_mutation(
        self,
        tool_name: str,
        address: int,
        pre_state: Dict[str, Any],
        post_state: Dict[str, Any],
        description: str,
    ) -> MutationRecord:
        record = MutationRecord(
            tool_name=tool_name,
            address=address,
            pre_state=pre_state,
            post_state=post_state,
            description=description,
        )
        self.mutation_log.append(record)
        return record

    def undo(self, n: int = 1) -> List[MutationRecord]:
        """Reverse the last n mutations. Caller must actually apply the reversals."""
        to_undo = self.mutation_log[-n:]
        self.mutation_log = self.mutation_log[:-n]
        return list(reversed(to_undo))

    def save(self, path: Optional[Path] = None) -> Path:
        if path is None:
            path = Path(self.binary_path).with_suffix(".reeve.json")
        functions = [
            {
                "address": f"0x{fn.address:x}",
                "raw_name": fn.raw_name,
                "name": fn.name.value if fn.name else fn.raw_name,
                "confidence": fn.name.confidence if fn.name else 0.0,
                "prototype": fn.prototype.value if fn.prototype else None,
                "comment": fn.comment,
                "component_id": fn.component_id,
            }
            for fn in self.graph.all_functions()
        ]
        hypotheses = [
            {
                "id": h.id,
                "claim": h.claim,
                "confidence": h.confidence,
                "status": h.status.value if hasattr(h.status, "value") else str(h.status),
            }
            for h in self.graph._hypotheses.values()
        ]
        state = {
            "session_id": self.id,
            "goal": self.goal,
            "binary_path": self.binary_path,
            "stats": self.graph.stats,
            "report": self.report,
            "cost_summary": self.cost_tracker.summary(),
            "mutations": len(self.mutation_log),
            "functions": functions,
            "hypotheses": hypotheses,
        }
        path.write_text(json.dumps(state, indent=2))
        logger.info("Session saved to %s", path)
        return path

    def save_report(self, path: Optional[Path] = None, fmt: str = "md") -> Optional[Path]:
        if not self.report:
            return None
        base = Path(self.binary_path).stem
        out_dir = Path(self.binary_path).parent
        if path is None:
            path = out_dir / f"{base}.report.{fmt}"
        content = _render_report(self.report, fmt)
        path.write_text(content, encoding="utf-8")
        logger.info("Report saved to %s", path)
        return path

    def print_status(self) -> None:
        stats = self.graph.stats
        cost = self.cost_tracker.total_cost_usd
        print(f"\nSession {self.id} | {self.goal}")
        print(f"  Functions: {stats['functions']} total, {stats['named']} named, {stats['resolved']} resolved")
        print(f"  Components: {stats['components']}  Hypotheses: {stats['hypotheses']}")
        print(f"  Cost: ${cost:.4f}  Mutations: {len(self.mutation_log)}")


def _render_report(report_md: str, fmt: str) -> str:
    if fmt == "md":
        return report_md
    if fmt == "txt":
        import re
        text = re.sub(r"^#{1,6}\s+", "", report_md, flags=re.MULTILINE)
        text = re.sub(r"\*\*(.+?)\*\*", r"\1", text)
        text = re.sub(r"\*(.+?)\*", r"\1", text)
        text = re.sub(r"`(.+?)`", r"\1", text)
        text = re.sub(r"\[(.+?)\]\(.+?\)", r"\1", text)
        return text
    if fmt == "html":
        import re
        html = report_md
        # Headings
        html = re.sub(r"^### (.+)$", r"<h3>\1</h3>", html, flags=re.MULTILINE)
        html = re.sub(r"^## (.+)$", r"<h2>\1</h2>", html, flags=re.MULTILINE)
        html = re.sub(r"^# (.+)$", r"<h1>\1</h1>", html, flags=re.MULTILINE)
        # Inline
        html = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", html)
        html = re.sub(r"\*(.+?)\*", r"<em>\1</em>", html)
        html = re.sub(r"`(.+?)`", r"<code>\1</code>", html)
        # Wrap non-heading lines in paragraphs
        out_lines = []
        in_p = False
        for line in html.splitlines():
            if line.startswith("<h"):
                if in_p:
                    out_lines.append("</p>")
                    in_p = False
                out_lines.append(line)
            elif line.strip() == "":
                if in_p:
                    out_lines.append("</p>")
                    in_p = False
            else:
                if not in_p:
                    out_lines.append("<p>")
                    in_p = True
                out_lines.append(line)
        if in_p:
            out_lines.append("</p>")
        return "<html><body>\n" + "\n".join(out_lines) + "\n</body></html>"
    if fmt == "json":
        sections: Dict[str, str] = {}
        import re
        current_heading = "overview"
        current_lines: List[str] = []
        for line in report_md.splitlines():
            m = re.match(r"^#{1,3}\s+(.+)$", line)
            if m:
                sections[current_heading] = "\n".join(current_lines).strip()
                current_heading = m.group(1).lower().replace(" ", "_").replace("/", "_")
                current_lines = []
            else:
                current_lines.append(line)
        sections[current_heading] = "\n".join(current_lines).strip()
        return json.dumps(sections, indent=2)
    return report_md
