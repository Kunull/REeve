"""
Task dataclasses for the goal-driven planner.
Each task type maps to a specific analysis pass; LLM tasks are flagged explicitly.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class TaskKind(Enum):
    # Static analysis — no LLM
    RESOLVE_IMPORTS       = "resolve_imports"
    BUILD_CALL_GRAPH      = "build_call_graph"
    CLASSIFY_FUNCTIONS    = "classify_functions"
    MATCH_SIGNATURES      = "match_signatures"
    INFER_TYPES           = "infer_types"
    PROPAGATE_NAMES       = "propagate_names"
    CLUSTER_COMPONENTS    = "cluster_components"
    ANALYZE_STRINGS       = "analyze_strings"
    ANALYZE_CFG           = "analyze_cfg"

    # LLM tasks
    ANALYZE_FUNCTION      = "analyze_function"
    FORM_HYPOTHESIS       = "form_hypothesis"
    TEST_HYPOTHESIS       = "test_hypothesis"
    SYNTHESIZE_COMPONENT  = "synthesize_component"
    GLOBAL_SYNTHESIS      = "global_synthesis"
    DEOBFUSCATE_FUNCTION  = "deobfuscate_function"
    GENERATE_REPORT       = "generate_report"

    # Interactive
    ANSWER_QUESTION       = "answer_question"


LLM_TASKS = {
    TaskKind.ANALYZE_FUNCTION,
    TaskKind.FORM_HYPOTHESIS,
    TaskKind.TEST_HYPOTHESIS,
    TaskKind.SYNTHESIZE_COMPONENT,
    TaskKind.GLOBAL_SYNTHESIS,
    TaskKind.GENERATE_REPORT,
    TaskKind.ANSWER_QUESTION,
}

MIXED_TASKS = {
    TaskKind.DEOBFUSCATE_FUNCTION,
    TaskKind.TEST_HYPOTHESIS,
}


class TaskStatus(Enum):
    PENDING   = "pending"
    RUNNING   = "running"
    COMPLETED = "completed"
    FAILED    = "failed"
    SKIPPED   = "skipped"


@dataclass
class Task:
    kind: TaskKind
    params: Dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    status: TaskStatus = TaskStatus.PENDING
    depends_on: List[str] = field(default_factory=list)  # task ids
    error: Optional[str] = None
    result: Optional["TaskResult"] = None
    priority: int = 0  # higher = runs first when queue depth permits

    @property
    def requires_llm(self) -> bool:
        return self.kind in LLM_TASKS

    @property
    def label(self) -> str:
        if self.kind == TaskKind.ANALYZE_FUNCTION:
            addr = self.params.get("address", 0)
            return f"analyze_function(0x{addr:x})"
        return self.kind.value


@dataclass
class TaskResult:
    task_id: str
    success: bool
    data: Dict[str, Any] = field(default_factory=dict)
    spawned_tasks: List[Task] = field(default_factory=list)
    error: Optional[str] = None
