"""
Textual TUI — live progress view for autonomous analysis runs.
Shows task feed, cost tracker, and knowledge graph stats.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, ScrollableContainer, Vertical
from textual.reactive import reactive
from textual.widgets import Footer, Header, Label, Log, ProgressBar, RichLog, Static

if TYPE_CHECKING:
    from reeve.core.session import Session


class StatsPanel(Static):
    """Live knowledge graph statistics panel."""

    stats_text: reactive[str] = reactive("Loading...")

    def render(self) -> str:
        return self.stats_text

    def update_stats(self, session: "Session") -> None:
        stats = session.graph.stats
        cost = session.cost_tracker.total_cost_usd
        self.stats_text = (
            f"Functions: {stats['functions']} total  {stats['named']} named  "
            f"{stats['resolved']} resolved\n"
            f"Components: {stats['components']}  Hypotheses: {stats['hypotheses']}\n"
            f"Imports: {stats['imports']}  Strings: {stats['strings']}\n"
            f"Cost: ${cost:.4f}  Mutations: {len(session.mutation_log)}"
        )


class AnalysisApp(App):
    CSS = """
    Screen {
        layout: grid;
        grid-size: 2;
        grid-rows: 1fr;
    }
    #task-feed {
        border: solid $primary;
        height: 100%;
        padding: 0 1;
    }
    #stats-panel {
        border: solid $accent;
        padding: 1;
        height: 1fr;
    }
    #cost-label {
        color: $warning;
        padding: 0 1;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("p", "pause", "Pause/Resume"),
        Binding("s", "save", "Save session"),
    ]

    def __init__(self, session: "Session") -> None:
        super().__init__()
        self._session = session
        self._task_log: list[str] = []

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal():
            with ScrollableContainer(id="task-feed"):
                yield RichLog(id="task-log", highlight=True, markup=True)
            with Vertical():
                yield StatsPanel(id="stats-panel")
                yield Label("", id="cost-label")
        yield Footer()

    def on_mount(self) -> None:
        self.title = f"ai-re | {self._session.goal[:50]}"
        from reeve.core.events import EventKind, bus
        bus.subscribe(EventKind.TASK_COMPLETED, self._on_task_event)
        bus.subscribe(EventKind.TASK_STARTED, self._on_task_event)
        bus.subscribe(EventKind.TASK_FAILED, self._on_task_event)
        bus.subscribe(EventKind.FUNCTION_ANALYZED, self._on_function_analyzed)
        bus.subscribe(EventKind.HYPOTHESIS_UPDATED, self._on_hypothesis)
        self.set_interval(2.0, self._refresh_stats)

    def _on_task_event(self, event) -> None:
        kind_str = event.data.get("kind", "?")
        status = event.kind.value.replace("task_", "")
        color = {"started": "yellow", "completed": "green", "failed": "red"}.get(status, "white")
        self.call_from_thread(self._log_message, f"[{color}]{status.upper()}[/] {kind_str}")

    def _on_function_analyzed(self, event) -> None:
        name = event.data.get("name", "?")
        conf = event.data.get("confidence", 0.0)
        self.call_from_thread(self._log_message, f"[blue]named[/] {name} ({conf:.2f})")

    def _on_hypothesis(self, event) -> None:
        status = event.data.get("status", "?")
        conf = event.data.get("confidence", 0.0)
        color = {"confirmed": "green", "refuted": "red", "open": "yellow"}.get(status, "white")
        self.call_from_thread(self._log_message, f"[{color}]hyp:{status}[/] conf={conf:.2f}")

    def _log_message(self, msg: str) -> None:
        log = self.query_one("#task-log", RichLog)
        log.write(msg)

    def _refresh_stats(self) -> None:
        panel = self.query_one("#stats-panel", StatsPanel)
        panel.update_stats(self._session)

    def action_pause(self) -> None:
        if self._session.mode == "autonomous":
            self._session.pause()
            self._log_message("[yellow]Session paused[/]")
        else:
            self._session.resume()
            self._log_message("[green]Session resumed[/]")

    def action_save(self) -> None:
        path = self._session.save()
        self._log_message(f"[green]Saved → {path}[/]")
