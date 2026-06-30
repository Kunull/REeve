"""
CLI entry point — `re` command.
  re analyze <binary> --goal <goal> [--budget N]
  re chat <binary>
  re ask <binary> <question>
  re eval <analysis.json> <ground_truth.json>
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.text import Text

console = Console()
logger = logging.getLogger("reeve")


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s  %(message)s",
        datefmt="%H:%M:%S",
    )


def _open_host(binary_path: str):
    """
    Return an initialized GhidraHost context manager.
    The caller must use it as a context manager (or call __enter__/__exit__).
    """
    try:
        from reeve.host.ghidra import GhidraHost
        return GhidraHost(binary_path)
    except ImportError:
        raise click.ClickException(
            "PyGhidra not available. Install it with: pip install pyghidra\n"
            "Also set GHIDRA_INSTALL_DIR to your Ghidra installation directory."
        )


def _run_analysis(binary_path: str, goal: str, budget: float, tui: bool, verbose: bool, kb: bool = False) -> None:
    import reeve.planning.handlers  # noqa: F401 — registers all handlers
    from reeve.core.session import Session
    from reeve.planning.executor import TaskExecutor
    from reeve.planning.planner import GoalPlanner

    try:
        host_ctx = _open_host(binary_path)
        host = host_ctx.__enter__()
    except Exception as exc:
        raise click.ClickException(f"Failed to open binary in Ghidra: {exc}")

    try:
        session = Session(goal=goal, binary_path=binary_path, host=host, budget_usd=budget)

        planner = GoalPlanner()
        tasks = planner.decompose(goal, binary_path)

        executor = TaskExecutor(session, max_workers=4)
        executor.submit_all(tasks)

        if tui:
            from reeve.ui.tui.app import AnalysisApp
            app = AnalysisApp(session)
            import threading
            exec_thread = threading.Thread(target=executor.run, daemon=True)
            exec_thread.start()
            app.run()
            exec_thread.join(timeout=5)
        else:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                task_id = progress.add_task("Analyzing...", total=None)

                def _update(event):
                    task_kind = event.data.get("task_kind", "")
                    progress.update(task_id, description=f"[cyan]{task_kind}[/cyan]")

                from reeve.core.events import EventKind, bus
                bus.subscribe(EventKind.TASK_STARTED, _update)
                executor.run()

        session.print_status()
        if session.report:
            console.print(Panel(session.report, title="Analysis Report", border_style="green"))

        summary_path = session.save()
        console.print(f"[green]Session saved → {summary_path}[/green]")

        report_path = session.save_report(fmt="md")
        if report_path:
            console.print(f"[green]Report saved  → {report_path}[/green]")

        if kb:
            from reeve.knowledge_base import KnowledgeBaseBuilder
            builder = KnowledgeBaseBuilder()
            kb_path = builder.build(session, decompile_fn=host.decompile)
            console.print(f"[green]Knowledge base → {kb_path}[/green]")
    finally:
        host_ctx.__exit__(None, None, None)


@click.group()
@click.option("--verbose", "-v", is_flag=True, help="Enable debug logging")
@click.pass_context
def cli(ctx: click.Context, verbose: bool) -> None:
    """AI-powered binary reverse engineering engine."""
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    _setup_logging(verbose)


@cli.command()
@click.argument("binary", type=click.Path(exists=True))
@click.option("--goal", "-g", default="full analysis", show_default=True, help="Analysis objective")
@click.option("--budget", "-b", type=float, default=float("inf"), help="Cost ceiling in USD")
@click.option("--tui/--no-tui", default=False, help="Launch Textual TUI")
@click.option("--kb/--no-kb", default=False, help="Build Obsidian knowledge base after analysis")
@click.pass_context
def analyze(ctx: click.Context, binary: str, goal: str, budget: float, tui: bool, kb: bool) -> None:
    """Run autonomous analysis on a binary."""
    console.print(f"[bold]reeve analyze[/bold]  binary={binary}  goal={goal!r}  budget=${budget}")
    _run_analysis(binary, goal, budget, tui, ctx.obj["verbose"], kb=kb)


@cli.command()
@click.argument("session_json", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), default=None, help="Output vault directory")
@click.pass_context
def kb(ctx: click.Context, session_json: str, output: Optional[str]) -> None:
    """Build an Obsidian knowledge base from a saved session JSON."""
    import json as _json
    from reeve.core.knowledge_graph import (
        Fact, FactSource, FunctionNode, KnowledgeGraph, SizeClass,
        ComponentNode, HypothesisNode, HypothesisStatus, ImportNode, StringNode,
    )
    from reeve.core.session import Session
    from reeve.core.hypothesis import HypothesisEngine
    from reeve.llm.usage import CostTracker
    from reeve.knowledge_base import KnowledgeBaseBuilder

    data = _json.loads(Path(session_json).read_text())

    # Reconstruct a lightweight session from the saved JSON
    graph = KnowledgeGraph()

    for entry in data.get("functions", []):
        address = entry.get("address", 0)
        if isinstance(address, str):
            address = int(address, 16)
        fn = FunctionNode.unanalyzed(address, entry.get("raw_name", f"sub_{address:x}"))
        fn.name = Fact(
            value=entry.get("name", fn.raw_name),
            confidence=entry.get("confidence", 0.5),
            source=FactSource.LLM,
        )
        fn.prototype = Fact(
            value=entry.get("prototype"),
            confidence=entry.get("confidence", 0.5),
            source=FactSource.LLM,
        )
        fn.comment = entry.get("comment")
        fn.component_id = entry.get("component_id")
        graph.add_function(fn)

    for c_data in data.get("components", []):
        comp = ComponentNode(
            id=c_data.get("id", ""),
            name=c_data.get("name"),
            purpose=c_data.get("purpose"),
            confidence=float(c_data.get("confidence", 0.0)),
        )
        graph._components[comp.id] = comp

    for h_data in data.get("hypotheses", []):
        h = HypothesisNode(
            id=h_data.get("id", ""),
            claim=h_data.get("claim", ""),
            confidence=float(h_data.get("confidence", 0.0)),
        )
        graph.add_hypothesis(h)

    class _FakeHost:
        binary_path = data.get("binary_path", session_json)

    class _FakeSession:
        id = data.get("session_id", "unknown")
        goal = data.get("goal", "")
        binary_path = data.get("binary_path", session_json)
        report = data.get("report")
        cost_tracker = CostTracker()

    fake = _FakeSession()
    fake.graph = graph

    out = Path(output) if output else None
    builder = KnowledgeBaseBuilder()
    kb_path = builder.build(fake, output_dir=out)
    console.print(f"[green]Knowledge base → {kb_path}[/green]")


@cli.command()
@click.argument("binary", type=click.Path(exists=True))
@click.pass_context
def chat(ctx: click.Context, binary: str) -> None:
    """Interactive chat over a binary — ask questions, rename functions."""
    import reeve.planning.handlers  # noqa: F401
    from reeve.core.session import Session
    from reeve.planning.executor import TaskExecutor
    from reeve.planning.planner import GoalPlanner

    host_ctx = _open_host(binary)
    try:
        host = host_ctx.__enter__()
        session = Session(goal="interactive", binary_path=binary, host=host)
        session.enter_interactive()

        # Run foundation static tasks first
        planner = GoalPlanner()
        foundation = planner._static_foundation()
        executor = TaskExecutor(session, max_workers=2)
        executor.submit_all(foundation)

        console.print("[yellow]Running static analysis foundation...[/yellow]")
        executor.run()

        stats = session.graph.stats
        console.print(
            f"[green]Ready.[/green] {stats['functions']} functions, "
            f"{stats['imports']} imports, {stats['strings']} strings"
        )
        console.print("[dim]Type your question, or 'quit' to exit.[/dim]\n")

        from reeve.llm.anthropic_client import AnthropicClient
        from reeve.llm.reasoner import LLMReasoner
        from reeve.llm.router import SONNET

        client = AnthropicClient(model=SONNET)
        reasoner = LLMReasoner(client, session.graph, session.cost_tracker)

        while True:
            try:
                question = click.prompt("you", prompt_suffix=" > ")
            except (EOFError, KeyboardInterrupt):
                break

            if question.lower() in ("quit", "exit", "q"):
                break

            context = session.graph.serialize_context_block(max_functions=100)
            answer = reasoner.answer_question(question, context)
            console.print(Panel(answer, border_style="blue"))
            console.print(f"[dim]Cost so far: ${session.cost_tracker.total_cost_usd:.4f}[/dim]")

        session.print_status()
    finally:
        host_ctx.__exit__(None, None, None)


@cli.command()
@click.argument("binary", type=click.Path(exists=True))
@click.argument("question")
@click.pass_context
def ask(ctx: click.Context, binary: str, question: str) -> None:
    """Ask a single question about a binary (no disassembler required for string search)."""
    import reeve.planning.handlers  # noqa: F401
    from reeve.core.session import Session
    from reeve.planning.executor import TaskExecutor
    from reeve.planning.planner import GoalPlanner

    host_ctx = _open_host(binary)
    try:
        host = host_ctx.__enter__()
        session = Session(goal=question, binary_path=binary, host=host)

        planner = GoalPlanner()
        tasks = planner.decompose(question, binary)

        executor = TaskExecutor(session)
        executor.submit_all(tasks)
        executor.run()

        answer_task_result = next(
            (t.result for t in executor._tasks.values()
             if t.result and "answer" in t.result.data),
            None,
        )

        if answer_task_result:
            console.print(Panel(answer_task_result.data["answer"], title=question, border_style="green"))
        else:
            console.print("[red]No answer produced.[/red]")
            session.print_status()
    finally:
        host_ctx.__exit__(None, None, None)


@cli.command()
@click.argument("session_json", type=click.Path(exists=True))
@click.option(
    "--format", "-f", "fmt",
    type=click.Choice(["md", "txt", "html", "json"]),
    default="md",
    show_default=True,
    help="Output format",
)
@click.option("--output", "-o", type=click.Path(), default=None, help="Output file (default: stdout)")
@click.pass_context
def report(ctx: click.Context, session_json: str, fmt: str, output: Optional[str]) -> None:
    """Export or display the analysis report from a saved session JSON."""
    import json as _json
    from reeve.core.session import _render_report

    data = _json.loads(Path(session_json).read_text())
    raw_report = data.get("report")
    if not raw_report:
        raise click.ClickException("No report found in session JSON. Re-run `re analyze` to generate one.")

    rendered = _render_report(raw_report, fmt)

    if output:
        Path(output).write_text(rendered, encoding="utf-8")
        console.print(f"[green]Report written to {output}[/green]")
    else:
        if fmt == "md":
            console.print(Panel(rendered, title="Analysis Report", border_style="green"))
        else:
            console.print(rendered)


@cli.command()
@click.argument("analysis_json", type=click.Path(exists=True))
@click.argument("ground_truth_json", type=click.Path(exists=True))
@click.pass_context
def eval(ctx: click.Context, analysis_json: str, ground_truth_json: str) -> None:
    """Evaluate analysis output against a ground truth JSON file."""
    import json as _json

    from reeve.core.knowledge_graph import (
        Fact, FactSource, FunctionNode, KnowledgeGraph, SizeClass,
    )
    from reeve.evals.harness import EvalHarness

    # Reconstruct a minimal graph from the analysis JSON for eval
    data = _json.loads(Path(analysis_json).read_text())
    graph = KnowledgeGraph()
    for entry in data.get("functions", []):
        address = entry.get("address", 0)
        if isinstance(address, str):
            address = int(address, 16)
        fn = FunctionNode.unanalyzed(address, entry.get("raw_name", f"sub_{address:x}"))
        fn.name = Fact(
            value=entry.get("name", fn.raw_name),
            confidence=entry.get("confidence", 0.5),
            source=FactSource.LLM,
        )
        fn.prototype = Fact(
            value=entry.get("prototype"),
            confidence=entry.get("confidence", 0.5),
            source=FactSource.LLM,
        )
        graph.add_function(fn)

    harness = EvalHarness()
    result = harness.run(graph, Path(ground_truth_json))
    result.print_summary()


def main() -> None:
    cli(obj={})


if __name__ == "__main__":
    main()
