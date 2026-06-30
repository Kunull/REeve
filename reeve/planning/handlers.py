"""
Task handlers — registered implementations for each TaskKind.
Each handler receives the live Session and a Task, runs its analysis,
and returns a TaskResult (possibly spawning follow-on tasks).
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from reeve.analysis.cfg import ObfuscationDetector
from reeve.analysis.components import ComponentClusterer
from reeve.analysis.imports import ImportResolver
from reeve.analysis.signatures import SignatureMatcher
from reeve.analysis.strings import StringAnalyzer
from reeve.analysis.types import TypeInferencer
from reeve.core.knowledge_graph import (
    Fact, FactSource, FunctionNode, SizeClass, SourceLang,
)
from reeve.llm.reasoner import AnalysisRequest, LLMReasoner, StringCluster
from reeve.planning.executor import register_handler
from reeve.planning.tasks import Task, TaskKind, TaskResult

if TYPE_CHECKING:
    from reeve.core.session import Session

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Static analysis handlers (no LLM)
# ---------------------------------------------------------------------------

@register_handler(TaskKind.RESOLVE_IMPORTS)
def handle_resolve_imports(session: "Session", task: Task) -> TaskResult:
    resolver = ImportResolver()
    count = resolver.resolve(session.host, session.graph)
    return TaskResult(task_id=task.id, success=True, data={"resolved": count})


@register_handler(TaskKind.ANALYZE_STRINGS)
def handle_analyze_strings(session: "Session", task: Task) -> TaskResult:
    analyzer = StringAnalyzer()
    analyzer.analyze(session.host, session.graph)
    count = len(session.graph.all_strings())
    return TaskResult(task_id=task.id, success=True, data={"strings": count})


@register_handler(TaskKind.BUILD_CALL_GRAPH)
def handle_build_call_graph(session: "Session", task: Task) -> TaskResult:
    host = session.host
    graph = session.graph

    fn_infos = host.list_functions()
    for info in fn_infos:
        fn = graph.get_function(info.address)
        if fn is None:
            # Size classification by block count
            if info.block_count <= 5:
                size_class = SizeClass.TRIVIAL
            elif info.block_count <= 20:
                size_class = SizeClass.SMALL
            elif info.block_count <= 100:
                size_class = SizeClass.MEDIUM
            else:
                size_class = SizeClass.LARGE

            fn = FunctionNode.unanalyzed(info.address, info.name)
            fn.size_class = size_class
            graph.add_function(fn)

    # Build call edges via xrefs
    for fn in graph.all_functions():
        try:
            for xref in host.xrefs_from(fn.address):
                if xref.kind == "call" and graph.get_function(xref.to_address):
                    graph.add_call(fn.address, xref.to_address)
        except Exception as exc:
            logger.debug("xrefs_from 0x%x failed: %s", fn.address, exc)

    return TaskResult(
        task_id=task.id,
        success=True,
        data={"functions": len(graph.all_functions()), "edges": graph.stats["call_edges"]},
    )


@register_handler(TaskKind.CLASSIFY_FUNCTIONS)
def handle_classify_functions(session: "Session", task: Task) -> TaskResult:
    # Block count already sets size_class in BUILD_CALL_GRAPH.
    # This pass does source language detection heuristics.
    graph = session.graph
    classified = 0
    for fn in graph.all_functions():
        if fn.source_lang == SourceLang.UNKNOWN:
            # Heuristic: Go binaries have runtime.* or syscall.* prefix in names
            name = fn.raw_name.lower()
            if "runtime." in name or "syscall." in name:
                fn.source_lang = SourceLang.GO
            elif "std::" in name or "_ZN" in name or "_ZS" in name:
                fn.source_lang = SourceLang.CPP
            classified += 1
    return TaskResult(task_id=task.id, success=True, data={"classified": classified})


@register_handler(TaskKind.MATCH_SIGNATURES)
def handle_match_signatures(session: "Session", task: Task) -> TaskResult:
    matcher = SignatureMatcher()
    matched = matcher.match(session.host, session.graph)
    return TaskResult(task_id=task.id, success=True, data={"matched": matched})


@register_handler(TaskKind.INFER_TYPES)
def handle_infer_types(session: "Session", task: Task) -> TaskResult:
    inferencer = TypeInferencer()
    count = inferencer.infer(session.graph)
    return TaskResult(task_id=task.id, success=True, data={"inferences": count})


@register_handler(TaskKind.ANALYZE_CFG)
def handle_analyze_cfg(session: "Session", task: Task) -> TaskResult:
    detector = ObfuscationDetector()
    flagged = 0
    for fn in session.graph.all_functions():
        try:
            decomp = session.host.decompile(fn.address)
        except Exception:
            continue
        patterns = detector.detect(fn, decomp)
        if patterns:
            fn.obfuscated = True
            fn.obfuscation_patterns = patterns
            flagged += 1
    return TaskResult(task_id=task.id, success=True, data={"obfuscated": flagged})


@register_handler(TaskKind.CLUSTER_COMPONENTS)
def handle_cluster_components(session: "Session", task: Task) -> TaskResult:
    clusterer = ComponentClusterer()
    count = clusterer.cluster(session.graph)
    return TaskResult(task_id=task.id, success=True, data={"components": count})


@register_handler(TaskKind.PROPAGATE_NAMES)
def handle_propagate_names(session: "Session", task: Task) -> TaskResult:
    graph = session.graph
    dirty = graph.dirty_functions()
    # Dirty functions get re-queued as ANALYZE_FUNCTION tasks
    spawned = []
    for fn in dirty:
        fn.name.dirty = False
        from reeve.planning.tasks import Task as T
        spawned.append(T(
            kind=TaskKind.ANALYZE_FUNCTION,
            params={"address": fn.address, "scope": "single"},
            depends_on=[task.id],
        ))
    return TaskResult(
        task_id=task.id,
        success=True,
        data={"dirty_count": len(dirty)},
        spawned_tasks=spawned,
    )


# ---------------------------------------------------------------------------
# LLM handlers
# ---------------------------------------------------------------------------

def _get_reasoner(session: "Session") -> LLMReasoner:
    from reeve.llm.anthropic_client import AnthropicClient
    from reeve.llm.router import model_for_task
    model = model_for_task(TaskKind.ANALYZE_FUNCTION)
    client = AnthropicClient(model=model)
    return LLMReasoner(client, session.graph, session.cost_tracker)


@register_handler(TaskKind.ANALYZE_FUNCTION)
def handle_analyze_function(session: "Session", task: Task) -> TaskResult:
    graph = session.graph
    scope = task.params.get("scope", "all")
    address = task.params.get("address")
    focus = task.params.get("focus")

    if scope == "single" and address is not None:
        targets = [fn for fn in [graph.get_function(address)] if fn]
    else:
        targets = [fn for fn in graph.bfs_bottom_up() if not fn.is_resolved]

    if not targets:
        return TaskResult(task_id=task.id, success=True, data={"analyzed": 0})

    from reeve.analysis.types import TypeInferencer
    type_inf = TypeInferencer()
    reasoner = _get_reasoner(session)

    analyzed = 0
    for fn in targets:
        if session.cost_tracker.over_budget():
            logger.warning("Budget exhausted — stopping function analysis")
            break

        callees = graph.callees_of(fn.address)
        imports_called = [
            graph.get_import(c.raw_name)
            for c in callees
            if graph.get_import(c.raw_name)
        ]
        strings = graph.strings_referenced_by(fn.address)
        clusters: list[StringCluster] = []
        by_cat: dict[str, list[str]] = {}
        for s in strings:
            by_cat.setdefault(s.category, []).append(s.value)
        for cat, vals in by_cat.items():
            clusters.append(StringCluster(category=cat, samples=vals[:5]))

        type_annotations = type_inf.get_type_annotations(graph, fn)

        component_hyp = None
        if fn.component_id:
            comp = graph.get_component(fn.component_id)
            if comp and comp.purpose:
                component_hyp = comp.purpose

        request = AnalysisRequest(
            function=fn,
            decompilation="",
            known_callees=[c for c in callees if c.name.confidence >= 0.5],
            type_inferences=type_annotations,
            string_clusters=clusters,
            component_hypothesis=component_hyp,
            import_context=imports_called,
            obfuscation_notes=fn.obfuscation_patterns,
            focus=focus,
        )

        response = reasoner.analyze_function(
            request,
            host_decompile_fn=session.host.decompile,
        )

        graph.update_function_name(
            fn.address,
            response.name,
            response.confidence,
            FactSource.LLM,
            [response.evidence_summary],
        )
        if response.prototype:
            fn.prototype.update(
                response.prototype, response.confidence, FactSource.LLM, [response.evidence_summary]
            )
        if response.comment:
            fn.comment = response.comment

        analyzed += 1

    return TaskResult(task_id=task.id, success=True, data={"analyzed": analyzed})


@register_handler(TaskKind.FORM_HYPOTHESIS)
def handle_form_hypothesis(session: "Session", task: Task) -> TaskResult:
    claim_template = task.params.get("claim_template", "component purpose")
    scope = task.params.get("scope", "components")

    from reeve.llm.anthropic_client import AnthropicClient
    from reeve.llm.router import model_for_task
    client = AnthropicClient(model=model_for_task(TaskKind.FORM_HYPOTHESIS))
    reasoner = LLMReasoner(client, session.graph, session.cost_tracker)

    hyp_ids = []
    for comp in session.graph.all_components():
        fns = session.graph.functions_in_component(comp.id)
        summary = f"Component {comp.id}: {len(fns)} functions\n"
        summary += "\n".join(f"  {f.display_name}" for f in fns[:10])
        claim = reasoner.form_hypothesis(summary, claim_template)
        h = session.hypothesis_engine.form(claim)
        hyp_ids.append(h.id)

    return TaskResult(task_id=task.id, success=True, data={"hypotheses": len(hyp_ids)})


@register_handler(TaskKind.TEST_HYPOTHESIS)
def handle_test_hypothesis(session: "Session", task: Task) -> TaskResult:
    graph = session.graph
    tested = 0
    for h in graph.open_hypotheses():
        # Simple evidence: check if network imports support hypothesis
        claim_lower = h.claim.lower()
        if "network" in claim_lower or "c2" in claim_lower or "http" in claim_lower:
            network_imports = graph.imports_by_category("network")
            if network_imports:
                session.hypothesis_engine.add_evidence_for(
                    h.id,
                    f"Binary has {len(network_imports)} network imports",
                    weight=0.2,
                )
            else:
                session.hypothesis_engine.add_evidence_against(
                    h.id,
                    "No network imports found",
                    weight=0.3,
                )
        if "crypto" in claim_lower or "encrypt" in claim_lower:
            crypto_imports = graph.imports_by_category("crypto")
            if crypto_imports:
                session.hypothesis_engine.add_evidence_for(
                    h.id,
                    f"Binary has {len(crypto_imports)} crypto imports",
                    weight=0.2,
                )
        if "persist" in claim_lower or "registry" in claim_lower:
            reg_imports = graph.imports_by_category("registry")
            persist_imports = graph.imports_by_category("persistence")
            if reg_imports or persist_imports:
                session.hypothesis_engine.add_evidence_for(
                    h.id,
                    f"Binary has {len(reg_imports) + len(persist_imports)} persistence-related imports",
                    weight=0.25,
                )
        tested += 1

    return TaskResult(task_id=task.id, success=True, data={"tested": tested})


@register_handler(TaskKind.SYNTHESIZE_COMPONENT)
def handle_synthesize_component(session: "Session", task: Task) -> TaskResult:
    from reeve.llm.anthropic_client import AnthropicClient
    from reeve.llm.router import model_for_task
    client = AnthropicClient(model=model_for_task(TaskKind.SYNTHESIZE_COMPONENT))
    reasoner = LLMReasoner(client, session.graph, session.cost_tracker)

    synthesized = 0
    for comp in session.graph.all_components():
        if comp.purpose:
            continue
        fns = session.graph.functions_in_component(comp.id)
        if not fns:
            continue
        summary = "\n".join(f"  {f.display_name} (conf={f.name.confidence:.2f})" for f in fns[:20])
        comp.purpose = reasoner.form_hypothesis(
            f"Component functions:\n{summary}",
            "overall purpose of this component",
        )
        synthesized += 1

    return TaskResult(task_id=task.id, success=True, data={"synthesized": synthesized})


@register_handler(TaskKind.GLOBAL_SYNTHESIS)
def handle_global_synthesis(session: "Session", task: Task) -> TaskResult:
    from reeve.llm.anthropic_client import AnthropicClient
    from reeve.llm.router import OPUS
    client = AnthropicClient(model=OPUS)
    reasoner = LLMReasoner(client, session.graph, session.cost_tracker)

    summary = session.graph.serialize_context_block(max_functions=200)
    result_text = reasoner.global_synthesis(summary)
    return TaskResult(task_id=task.id, success=True, data={"synthesis": result_text})


@register_handler(TaskKind.GENERATE_REPORT)
def handle_generate_report(session: "Session", task: Task) -> TaskResult:
    from reeve.llm.anthropic_client import AnthropicClient
    from reeve.llm.router import OPUS
    client = AnthropicClient(model=OPUS)
    reasoner = LLMReasoner(client, session.graph, session.cost_tracker)

    summary = session.graph.serialize_context_block(max_functions=200)
    focus = task.params.get("focus", "")
    goal = session.goal + (f" (focus: {focus})" if focus else "")
    report = reasoner.generate_report(goal, summary)
    session.report = report
    return TaskResult(task_id=task.id, success=True, data={"report_length": len(report)})


@register_handler(TaskKind.ANSWER_QUESTION)
def handle_answer_question(session: "Session", task: Task) -> TaskResult:
    from reeve.llm.anthropic_client import AnthropicClient
    from reeve.llm.router import model_for_task
    client = AnthropicClient(model=model_for_task(TaskKind.ANSWER_QUESTION))
    reasoner = LLMReasoner(client, session.graph, session.cost_tracker)

    goal = task.params.get("goal", "")
    address = task.params.get("address")

    context = session.graph.serialize_context_block(max_functions=50)
    if address:
        fn = session.graph.get_function(address)
        if fn:
            context += f"\n\nFocus function: 0x{fn.address:x} {fn.display_name}\n"
            context += f"  Prototype: {fn.prototype.value}\n"
            context += f"  Comment: {fn.comment}\n"

    answer = reasoner.answer_question(goal, context)
    return TaskResult(task_id=task.id, success=True, data={"answer": answer})
