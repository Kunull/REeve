"""
GoalPlanner — decomposes a natural-language goal into an ordered task DAG.
Each goal maps to a canonical sequence of analysis tasks; the executor
runs them with dependency ordering.
"""

from __future__ import annotations

import re
from typing import List, Optional

from reeve.planning.tasks import Task, TaskKind


class GoalPlanner:
    """
    Maps a goal string to an initial task list.
    Tasks know their dependencies; the executor enforces ordering.
    """

    def decompose(self, goal: str, binary_path: str) -> List[Task]:
        g = goal.lower()

        if _is_function_question(g):
            return self._single_function_plan(goal)

        if any(w in g for w in ("malware", "threat", "c2", "persistence", "inject")):
            return self._malware_analysis_plan()

        if any(w in g for w in ("vulnerability", "vuln", "overflow", "uaf", "exploit")):
            return self._vulnerability_plan()

        if any(w in g for w in ("symbol", "name", "recover", "rename", "full")):
            return self._full_symbol_recovery_plan()

        # Default: full analysis
        return self._full_analysis_plan()

    # ------------------------------------------------------------------
    # Plan templates
    # ------------------------------------------------------------------

    def _static_foundation(self) -> List[Task]:
        """The static analysis pipeline that every goal starts with."""
        t_imports   = Task(kind=TaskKind.RESOLVE_IMPORTS)
        t_strings   = Task(kind=TaskKind.ANALYZE_STRINGS, depends_on=[])
        t_callgraph = Task(kind=TaskKind.BUILD_CALL_GRAPH,   depends_on=[t_imports.id])
        t_sigs      = Task(kind=TaskKind.MATCH_SIGNATURES,   depends_on=[t_callgraph.id])
        t_classify  = Task(kind=TaskKind.CLASSIFY_FUNCTIONS, depends_on=[t_callgraph.id])
        t_cfg       = Task(kind=TaskKind.ANALYZE_CFG,        depends_on=[t_callgraph.id])
        t_types     = Task(kind=TaskKind.INFER_TYPES,        depends_on=[t_sigs.id, t_callgraph.id])
        t_cluster   = Task(kind=TaskKind.CLUSTER_COMPONENTS, depends_on=[t_callgraph.id, t_strings.id])
        return [t_imports, t_strings, t_callgraph, t_sigs, t_classify, t_cfg, t_types, t_cluster]

    def _full_analysis_plan(self) -> List[Task]:
        base = self._static_foundation()
        last_static = base[-1]  # cluster_components
        sigs_task = next(t for t in base if t.kind == TaskKind.MATCH_SIGNATURES)

        t_analyze = Task(
            kind=TaskKind.ANALYZE_FUNCTION,
            params={"scope": "all"},
            depends_on=[sigs_task.id, last_static.id],
        )
        t_propagate = Task(
            kind=TaskKind.PROPAGATE_NAMES,
            depends_on=[t_analyze.id],
        )
        t_hypothesis = Task(
            kind=TaskKind.FORM_HYPOTHESIS,
            params={"scope": "components"},
            depends_on=[t_propagate.id],
        )
        t_synthesize = Task(
            kind=TaskKind.SYNTHESIZE_COMPONENT,
            params={"scope": "all"},
            depends_on=[t_hypothesis.id],
        )
        t_global = Task(kind=TaskKind.GLOBAL_SYNTHESIS, depends_on=[t_synthesize.id])
        t_report = Task(kind=TaskKind.GENERATE_REPORT,  depends_on=[t_global.id])

        return base + [t_analyze, t_propagate, t_hypothesis, t_synthesize, t_global, t_report]

    def _malware_analysis_plan(self) -> List[Task]:
        base = self._static_foundation()
        last_static = base[-1]
        sigs_task = next(t for t in base if t.kind == TaskKind.MATCH_SIGNATURES)

        t_analyze = Task(
            kind=TaskKind.ANALYZE_FUNCTION,
            params={"scope": "all", "focus": "malware"},
            depends_on=[sigs_task.id, last_static.id],
        )
        t_propagate = Task(kind=TaskKind.PROPAGATE_NAMES, depends_on=[t_analyze.id])
        t_hyp_network = Task(
            kind=TaskKind.FORM_HYPOTHESIS,
            params={"claim_template": "C2 communication mechanism"},
            depends_on=[t_propagate.id],
        )
        t_hyp_persist = Task(
            kind=TaskKind.FORM_HYPOTHESIS,
            params={"claim_template": "persistence mechanism"},
            depends_on=[t_propagate.id],
        )
        t_test_net = Task(
            kind=TaskKind.TEST_HYPOTHESIS,
            depends_on=[t_hyp_network.id],
        )
        t_test_per = Task(
            kind=TaskKind.TEST_HYPOTHESIS,
            depends_on=[t_hyp_persist.id],
        )
        t_report = Task(
            kind=TaskKind.GENERATE_REPORT,
            params={"focus": "malware"},
            depends_on=[t_test_net.id, t_test_per.id],
        )
        return base + [t_analyze, t_propagate, t_hyp_network, t_hyp_persist,
                       t_test_net, t_test_per, t_report]

    def _vulnerability_plan(self) -> List[Task]:
        base = self._static_foundation()
        last_static = base[-1]
        sigs_task = next(t for t in base if t.kind == TaskKind.MATCH_SIGNATURES)

        t_analyze = Task(
            kind=TaskKind.ANALYZE_FUNCTION,
            params={"scope": "all", "focus": "vulnerability"},
            depends_on=[sigs_task.id, last_static.id],
        )
        t_propagate = Task(kind=TaskKind.PROPAGATE_NAMES, depends_on=[t_analyze.id])
        t_hyp = Task(
            kind=TaskKind.FORM_HYPOTHESIS,
            params={"claim_template": "input validation weakness"},
            depends_on=[t_propagate.id],
        )
        t_test = Task(kind=TaskKind.TEST_HYPOTHESIS, depends_on=[t_hyp.id])
        t_report = Task(
            kind=TaskKind.GENERATE_REPORT,
            params={"focus": "vulnerability"},
            depends_on=[t_test.id],
        )
        return base + [t_analyze, t_propagate, t_hyp, t_test, t_report]

    def _full_symbol_recovery_plan(self) -> List[Task]:
        base = self._static_foundation()
        last_static = base[-1]
        sigs_task = next(t for t in base if t.kind == TaskKind.MATCH_SIGNATURES)

        t_analyze = Task(
            kind=TaskKind.ANALYZE_FUNCTION,
            params={"scope": "all"},
            depends_on=[sigs_task.id, last_static.id],
        )
        t_propagate = Task(kind=TaskKind.PROPAGATE_NAMES, depends_on=[t_analyze.id])
        t_global = Task(kind=TaskKind.GLOBAL_SYNTHESIS, depends_on=[t_propagate.id])
        t_report = Task(kind=TaskKind.GENERATE_REPORT, depends_on=[t_global.id])
        return base + [t_analyze, t_propagate, t_global, t_report]

    def _single_function_plan(self, goal: str) -> List[Task]:
        """For questions about a specific function address or name."""
        address = _extract_address(goal)
        params: dict = {"scope": "single"}
        if address is not None:
            params["address"] = address

        t_imports  = Task(kind=TaskKind.RESOLVE_IMPORTS)
        t_callgraph = Task(kind=TaskKind.BUILD_CALL_GRAPH, depends_on=[t_imports.id])
        t_sigs     = Task(kind=TaskKind.MATCH_SIGNATURES, depends_on=[t_callgraph.id])
        t_strings  = Task(kind=TaskKind.ANALYZE_STRINGS)
        t_cfg      = Task(kind=TaskKind.ANALYZE_CFG, depends_on=[t_callgraph.id])
        t_analyze  = Task(
            kind=TaskKind.ANALYZE_FUNCTION,
            params=params,
            depends_on=[t_sigs.id, t_strings.id, t_cfg.id],
        )
        t_answer   = Task(
            kind=TaskKind.ANSWER_QUESTION,
            params={"goal": goal},
            depends_on=[t_analyze.id],
        )
        return [t_imports, t_callgraph, t_sigs, t_strings, t_cfg, t_analyze, t_answer]


def _extract_address(text: str) -> Optional[int]:
    m = re.search(r"0x([0-9a-fA-F]+)", text)
    if m:
        return int(m.group(1), 16)
    m = re.search(r"\b(sub_|fn_|loc_)?([0-9a-fA-F]{4,8})\b", text)
    if m:
        try:
            return int(m.group(2), 16)
        except ValueError:
            pass
    return None


def _is_function_question(goal: str) -> bool:
    patterns = [
        r"0x[0-9a-fA-F]+",
        r"sub_[0-9a-fA-F]+",
        r"what (is|does) .*(function|sub_|0x)",
        r"analyze function",
        r"what does .* do",
    ]
    return any(re.search(p, goal) for p in patterns)
