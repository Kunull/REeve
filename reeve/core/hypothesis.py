"""
HypothesisEngine — forms, tracks, and resolves claims about binary components.
Each hypothesis has explicit evidence chains and a lifecycle: open → confirmed/refuted.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from reeve.core.events import EventKind, bus
from reeve.core.knowledge_graph import (
    HypothesisNode, HypothesisStatus, KnowledgeGraph,
)

logger = logging.getLogger(__name__)

CONFIRM_THRESHOLD = 0.85
REFUTE_THRESHOLD  = 0.15


class HypothesisEngine:
    def __init__(self, graph: KnowledgeGraph, session_id: Optional[str] = None) -> None:
        self._graph = graph
        self._session_id = session_id

    def form(self, claim: str, initial_confidence: float = 0.3) -> HypothesisNode:
        h = HypothesisNode.new(claim)
        h.confidence = initial_confidence
        self._graph.add_hypothesis(h)
        logger.info("Hypothesis formed: [%s] %s (conf=%.2f)", h.id, claim, initial_confidence)
        bus.emit(EventKind.HYPOTHESIS_UPDATED, session_id=self._session_id,
                 hypothesis_id=h.id, claim=claim, status=h.status.value)
        return h

    def add_evidence_for(
        self,
        hypothesis_id: str,
        evidence: str,
        weight: float = 0.15,
    ) -> Optional[HypothesisNode]:
        h = self._graph.get_hypothesis(hypothesis_id)
        if h is None:
            logger.warning("Hypothesis %s not found", hypothesis_id)
            return None
        h.add_evidence_for(evidence, weight)
        self._resolve(h)
        bus.emit(EventKind.HYPOTHESIS_UPDATED, session_id=self._session_id,
                 hypothesis_id=h.id, status=h.status.value, confidence=h.confidence)
        return h

    def add_evidence_against(
        self,
        hypothesis_id: str,
        evidence: str,
        weight: float = 0.15,
    ) -> Optional[HypothesisNode]:
        h = self._graph.get_hypothesis(hypothesis_id)
        if h is None:
            return None
        h.add_evidence_against(evidence, weight)
        self._resolve(h)
        bus.emit(EventKind.HYPOTHESIS_UPDATED, session_id=self._session_id,
                 hypothesis_id=h.id, status=h.status.value, confidence=h.confidence)
        return h

    def _resolve(self, h: HypothesisNode) -> None:
        if h.status not in (HypothesisStatus.OPEN,):
            return
        if h.confidence >= CONFIRM_THRESHOLD:
            h.status = HypothesisStatus.CONFIRMED
            logger.info("Hypothesis confirmed: [%s] %s", h.id, h.claim)
        elif h.confidence <= REFUTE_THRESHOLD:
            h.status = HypothesisStatus.REFUTED
            logger.info("Hypothesis refuted: [%s] %s", h.id, h.claim)

    def defer_open(self) -> List[HypothesisNode]:
        """Mark remaining open hypotheses as deferred (analyst review)."""
        deferred = []
        for h in self._graph.open_hypotheses():
            h.status = HypothesisStatus.DEFERRED
            deferred.append(h)
        return deferred

    def summary(self) -> str:
        lines = []
        for h in self._graph._hypotheses.values():
            lines.append(
                f"[{h.status.value.upper():9s}] conf={h.confidence:.2f}  {h.claim}"
            )
        return "\n".join(lines) if lines else "(no hypotheses)"
