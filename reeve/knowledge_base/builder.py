"""
KnowledgeBaseBuilder — turns a completed analysis Session into an Obsidian vault.

Vault layout:
  <binary>_kb/
    index.md                   ← Map of Content (entry point)
    overview.md                ← full analysis report
    functions/
      <name>.md                ← one note per function
    components/
      <name>.md                ← one note per component
    hypotheses/
      <claim_slug>.md          ← one note per hypothesis
    strings.md                 ← notable strings grouped by category
    imports.md                 ← resolved imports with categories

Each note uses:
  - YAML frontmatter (tags, address, confidence, …)
  - [[Wikilinks]] to related notes
  - #tags for filtering in Obsidian
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Dict, List, Optional

if TYPE_CHECKING:
    from reeve.core.session import Session
    from reeve.core.knowledge_graph import FunctionNode, KnowledgeGraph

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _slug(text: str) -> str:
    """Convert text to a filesystem-safe slug."""
    text = text.splitlines()[0].strip().lower()
    text = re.sub(r"[^\w\s-]", "", text)
    text = re.sub(r"[\s_]+", "_", text)
    text = text.strip("_")
    return text[:80] or "unknown"


def _fn_link(fn: "FunctionNode") -> str:
    name = fn.display_name
    return f"[[functions/{_slug(name)}|{name}]]"


def _conf_bar(conf: float) -> str:
    filled = int(conf * 10)
    return "█" * filled + "░" * (10 - filled) + f" {conf:.0%}"


def _yaml_tags(tags: List[str]) -> str:
    return "tags:\n" + "\n".join(f"  - {t}" for t in tags)


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------

class KnowledgeBaseBuilder:
    """
    Builds an Obsidian-compatible vault from a completed analysis session.

    Usage:
        builder = KnowledgeBaseBuilder()
        vault_path = builder.build(session, output_dir)
    """

    def build(
        self,
        session: "Session",
        output_dir: Optional[Path] = None,
        decompile_fn: Optional[Callable[[int], str]] = None,
    ) -> Path:
        binary_stem = Path(session.binary_path).stem
        if output_dir is None:
            output_dir = Path(session.binary_path).parent / f"{binary_stem}_kb"

        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "functions").mkdir(exist_ok=True)
        (output_dir / "components").mkdir(exist_ok=True)
        (output_dir / "hypotheses").mkdir(exist_ok=True)

        graph = session.graph

        self._write_functions(graph, output_dir, decompile_fn)
        self._write_components(graph, output_dir)
        self._write_hypotheses(graph, output_dir)
        self._write_strings(graph, output_dir)
        self._write_imports(graph, output_dir)
        self._write_overview(session, output_dir)
        self._write_index(session, graph, output_dir, binary_stem)

        logger.info("Knowledge base written to %s", output_dir)
        return output_dir

    # ------------------------------------------------------------------
    # Functions
    # ------------------------------------------------------------------

    def _write_functions(
        self,
        graph: "KnowledgeGraph",
        vault: Path,
        decompile_fn: Optional[Callable[[int], str]],
    ) -> None:
        fns = graph.all_functions()
        for fn in fns:
            tags = self._fn_tags(fn, graph)
            callees = graph.callees_of(fn.address)
            callers = graph.callers_of(fn.address)
            strings = graph.strings_referenced_by(fn.address)

            lines = [
                "---",
                _yaml_tags(tags),
                f'address: "0x{fn.address:x}"',
                f"confidence: {fn.name.confidence:.2f}",
                f"size: {fn.size_class.value}",
                f"resolved: {fn.is_resolved}",
                f"obfuscated: {fn.obfuscated}",
            ]
            if fn.component_id:
                comp = graph.get_component(fn.component_id)
                comp_label = (comp.name if comp else None) or fn.component_id
                lines.append(f'component: "{comp_label}"')
            lines += ["---", ""]

            lines.append(f"# {fn.display_name}")
            lines.append("")

            if fn.prototype.value:
                lines += [f"```c\n{fn.prototype.value}\n```", ""]

            if fn.comment:
                lines += [f"> {fn.comment}", ""]

            lines.append(f"**Confidence:** {_conf_bar(fn.name.confidence)}")
            lines.append("")

            if fn.component_id:
                comp = graph.get_component(fn.component_id)
                comp_label = (comp.name if comp else None) or fn.component_id
                comp_name = _slug(comp_label)
                lines.append(f"**Component:** [[components/{comp_name}]]")
                lines.append("")

            if callees:
                lines.append("## Calls")
                for c in callees[:20]:
                    lines.append(f"- {_fn_link(c)}")
                lines.append("")

            if callers:
                lines.append("## Called by")
                for c in callers[:20]:
                    lines.append(f"- {_fn_link(c)}")
                lines.append("")

            if strings:
                lines.append("## Referenced strings")
                for s in strings[:15]:
                    lines.append(f"- `{s.value[:120]}` `#{s.category}`")
                lines.append("")

            if fn.obfuscated and fn.obfuscation_patterns:
                lines.append("## Obfuscation patterns")
                for p in fn.obfuscation_patterns:
                    lines.append(f"- {p}")
                lines.append("")

            if decompile_fn:
                try:
                    decomp = decompile_fn(fn.address)
                    if decomp:
                        lines += ["## Decompilation", "", "```c", decomp.strip(), "```", ""]
                except Exception:
                    pass

            slug = _slug(fn.display_name)
            (vault / "functions" / f"{slug}.md").write_text(
                "\n".join(lines), encoding="utf-8"
            )

    def _fn_tags(self, fn: "FunctionNode", graph: "KnowledgeGraph") -> List[str]:
        tags = ["function"]
        tags.append(f"size/{fn.size_class.value}")
        if fn.is_resolved:
            tags.append("resolved")
        if fn.obfuscated:
            tags.append("obfuscated")
        if fn.source_lang.value != "unknown":
            tags.append(f"lang/{fn.source_lang.value}")
        if fn.component_id:
            comp = graph.get_component(fn.component_id)
            if comp:
                tags.append(f"component/{_slug(comp.name or fn.component_id)}")
        # Infer semantic tags from name
        name_lower = fn.display_name.lower()
        for keyword, tag in [
            ("win", "ctf/target"), ("flag", "ctf/flag"), ("vuln", "vulnerability"),
            ("heap", "heap"), ("malloc", "heap"), ("free", "heap"),
            ("stack", "stack"), ("overflow", "vulnerability/overflow"),
            ("encrypt", "crypto"), ("decrypt", "crypto"), ("hash", "crypto"),
            ("socket", "network"), ("recv", "network"), ("send", "network"),
            ("exec", "code-exec"), ("shell", "code-exec"), ("system", "code-exec"),
            ("parse", "parser"), ("read", "io"), ("write", "io"),
        ]:
            if keyword in name_lower:
                tags.append(tag)
        return sorted(set(tags))

    # ------------------------------------------------------------------
    # Components
    # ------------------------------------------------------------------

    def _write_components(self, graph: "KnowledgeGraph", vault: Path) -> None:
        for comp in graph.all_components():
            fns = graph.functions_in_component(comp.id)
            slug = _slug((comp.name or comp.id))
            tags = ["component"]
            lines = [
                "---",
                _yaml_tags(tags),
                f'component_id: "{comp.id}"',
                f"confidence: {comp.confidence:.2f}",
                f"functions: {len(fns)}",
                "---",
                "",
                f"# Component: {comp.name or comp.id}",
                "",
            ]
            if comp.purpose:
                lines += [f"> {comp.purpose}", ""]

            if fns:
                lines.append("## Functions")
                for fn in sorted(fns, key=lambda f: f.name.confidence, reverse=True):
                    lines.append(f"- {_fn_link(fn)} — {fn.comment or ''}")
                lines.append("")

            (vault / "components" / f"{slug}.md").write_text(
                "\n".join(lines), encoding="utf-8"
            )

    # ------------------------------------------------------------------
    # Hypotheses
    # ------------------------------------------------------------------

    def _write_hypotheses(self, graph: "KnowledgeGraph", vault: Path) -> None:
        for h in graph._hypotheses.values():
            slug = _slug(h.claim[:60])
            status_tag = f"hypothesis/{h.status.value if hasattr(h.status, 'value') else h.status}"
            tags = ["hypothesis", status_tag]
            lines = [
                "---",
                _yaml_tags(tags),
                f'hypothesis_id: "{h.id}"',
                f"confidence: {h.confidence:.2f}",
                f'status: "{h.status.value if hasattr(h.status, "value") else h.status}"',
                "---",
                "",
                f"# {h.claim}",
                "",
                f"**Confidence:** {_conf_bar(h.confidence)}",
                "",
            ]
            if h.evidence_for:
                lines.append("## Evidence for")
                for e in h.evidence_for:
                    lines.append(f"- {e}")
                lines.append("")
            if h.evidence_against:
                lines.append("## Evidence against")
                for e in h.evidence_against:
                    lines.append(f"- {e}")
                lines.append("")

            (vault / "hypotheses" / f"{slug}.md").write_text(
                "\n".join(lines), encoding="utf-8"
            )

    # ------------------------------------------------------------------
    # Strings
    # ------------------------------------------------------------------

    def _write_strings(self, graph: "KnowledgeGraph", vault: Path) -> None:
        all_strings = graph.all_strings()
        if not all_strings:
            return

        by_category: Dict[str, list] = {}
        for s in all_strings:
            by_category.setdefault(s.category, []).append(s)

        lines = [
            "---",
            _yaml_tags(["strings", "reference"]),
            f"total: {len(all_strings)}",
            "---",
            "",
            "# Strings",
            "",
            f"**Total:** {len(all_strings)} strings across {len(by_category)} categories",
            "",
        ]

        for category, strings in sorted(by_category.items()):
            lines.append(f"## {category.capitalize()}")
            for s in sorted(strings, key=lambda x: len(x.value), reverse=True)[:30]:
                lines.append(f"- `0x{s.address:x}` — `{s.value[:120]}`")
            lines.append("")

        (vault / "strings.md").write_text("\n".join(lines), encoding="utf-8")

    # ------------------------------------------------------------------
    # Imports
    # ------------------------------------------------------------------

    def _write_imports(self, graph: "KnowledgeGraph", vault: Path) -> None:
        imports = graph.all_imports()
        if not imports:
            return

        by_category: Dict[str, list] = {}
        for imp in imports:
            for cat in (imp.categories or ["uncategorized"]):
                by_category.setdefault(cat, []).append(imp)

        lines = [
            "---",
            _yaml_tags(["imports", "reference"]),
            f"total: {len(imports)}",
            "---",
            "",
            "# Imports",
            "",
            f"**Total:** {len(imports)} imported symbols",
            "",
        ]

        for category, imps in sorted(by_category.items()):
            lines.append(f"## {category.capitalize()}")
            for imp in sorted(imps, key=lambda x: x.name):
                lib = f" ({imp.library})" if imp.library else ""
                lines.append(f"- `{imp.name}`{lib}")
            lines.append("")

        (vault / "imports.md").write_text("\n".join(lines), encoding="utf-8")

    # ------------------------------------------------------------------
    # Overview (full report)
    # ------------------------------------------------------------------

    def _write_overview(self, session: "Session", vault: Path) -> None:
        lines = [
            "---",
            _yaml_tags(["overview", "report"]),
            f'binary: "{Path(session.binary_path).name}"',
            f'goal: "{session.goal}"',
            f'session_id: "{session.id}"',
            "---",
            "",
        ]
        if session.report:
            lines.append(session.report)
        else:
            lines.append("*Report not yet generated.*")

        (vault / "overview.md").write_text("\n".join(lines), encoding="utf-8")

    # ------------------------------------------------------------------
    # Index / Map of Content
    # ------------------------------------------------------------------

    def _write_index(
        self,
        session: "Session",
        graph: "KnowledgeGraph",
        vault: Path,
        binary_stem: str,
    ) -> None:
        stats = graph.stats
        cost = session.cost_tracker.total_cost_usd

        # Top functions by confidence
        top_fns = sorted(
            graph.all_functions(),
            key=lambda f: f.name.confidence,
            reverse=True,
        )[:15]

        # Key imports by category
        network_imps = graph.imports_by_category("network")
        crypto_imps = graph.imports_by_category("crypto")

        lines = [
            "---",
            _yaml_tags(["moc", "index", "analysis"]),
            f'binary: "{Path(session.binary_path).name}"',
            f'goal: "{session.goal}"',
            f'session_id: "{session.id}"',
            "---",
            "",
            f"# {binary_stem}",
            "",
            f"> **Goal:** {session.goal}",
            "",
            "## Stats",
            "",
            f"| | |",
            f"|---|---|",
            f"| Functions | {stats['functions']} total · {stats['named']} named · {stats['resolved']} resolved |",
            f"| Components | {stats['components']} |",
            f"| Hypotheses | {stats['hypotheses']} |",
            f"| Analysis cost | ${cost:.4f} |",
            "",
            "## Navigation",
            "",
            "- [[overview]] — full analysis report",
            "- [[strings]] — extracted strings by category",
            "- [[imports]] — resolved imports by category",
            "",
        ]

        # Components
        components = graph.all_components()
        if components:
            lines.append("## Components")
            for comp in components:
                slug = _slug(comp.name or comp.id)
                fns = graph.functions_in_component(comp.id)
                lines.append(f"- [[components/{slug}|{comp.name or comp.id}]] — {len(fns)} functions")
                if comp.purpose:
                    lines.append(f"  > {comp.purpose[:120]}")
            lines.append("")

        # Hypotheses
        hypotheses = list(graph._hypotheses.values())
        if hypotheses:
            lines.append("## Hypotheses")
            for h in hypotheses:
                slug = _slug(h.claim[:60])
                display = h.claim.splitlines()[0][:80]
                status = h.status.value if hasattr(h.status, "value") else str(h.status)
                lines.append(f"- [[hypotheses/{slug}|{display}]] `{status}` {_conf_bar(h.confidence)}")
            lines.append("")

        # Top functions
        if top_fns:
            lines.append("## Key Functions")
            for fn in top_fns:
                fn_slug = _slug(fn.display_name)
                conf = f"{fn.name.confidence:.0%}"
                comment = f" — {fn.comment}" if fn.comment else ""
                lines.append(f"- [[functions/{fn_slug}|{fn.display_name}]] `{conf}`{comment}")
            lines.append("")

        # Notable imports
        if network_imps:
            lines.append("## Network imports")
            for imp in network_imps[:10]:
                lines.append(f"- `{imp.name}`")
            lines.append("")

        if crypto_imps:
            lines.append("## Crypto imports")
            for imp in crypto_imps[:10]:
                lines.append(f"- `{imp.name}`")
            lines.append("")

        lines += [
            "---",
            "*Generated by [[REeve]]*",
        ]

        (vault / "index.md").write_text("\n".join(lines), encoding="utf-8")
