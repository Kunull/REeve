"""
Tiered model routing — selects the right Claude model based on task type.
Haiku for cheap classification, Sonnet for analysis, Opus for synthesis.
"""

from __future__ import annotations

from reeve.planning.tasks import TaskKind


# Model IDs
HAIKU  = "claude-haiku-4-5-20251001"
SONNET = "claude-sonnet-4-6"
OPUS   = "claude-opus-4-8"

_TASK_MODEL: dict[TaskKind, str] = {
    TaskKind.CLASSIFY_FUNCTIONS:   HAIKU,
    TaskKind.ANALYZE_FUNCTION:     SONNET,
    TaskKind.FORM_HYPOTHESIS:      SONNET,
    TaskKind.TEST_HYPOTHESIS:      SONNET,
    TaskKind.SYNTHESIZE_COMPONENT: SONNET,
    TaskKind.DEOBFUSCATE_FUNCTION: SONNET,
    TaskKind.GLOBAL_SYNTHESIS:     OPUS,
    TaskKind.GENERATE_REPORT:      OPUS,
    TaskKind.ANSWER_QUESTION:      SONNET,
}


def model_for_task(kind: TaskKind) -> str:
    return _TASK_MODEL.get(kind, SONNET)


def downgrade(model_id: str) -> str:
    """Return the next cheaper model tier."""
    if model_id == OPUS:
        return SONNET
    if model_id == SONNET:
        return HAIKU
    return HAIKU
