"""
LLMReasoner — structured analysis of binary functions.
Receives rich static-analysis context; returns typed AnalysisResponse.
The LLM never sees raw pseudocode without structured facts alongside it.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from reeve.core.knowledge_graph import (
    FunctionNode, ImportNode, KnowledgeGraph, StringNode, TypeNode,
)
from reeve.llm.base import LLMClient, Message, TokenUsage
from reeve.llm.usage import CostTracker

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Request / Response types
# ---------------------------------------------------------------------------

@dataclass
class StringCluster:
    category: str
    samples: List[str]


@dataclass
class AnalysisRequest:
    function: FunctionNode
    decompilation: str
    known_callees: List[FunctionNode] = field(default_factory=list)
    type_inferences: List[str] = field(default_factory=list)
    string_clusters: List[StringCluster] = field(default_factory=list)
    component_hypothesis: Optional[str] = None
    import_context: List[ImportNode] = field(default_factory=list)
    obfuscation_notes: List[str] = field(default_factory=list)
    focus: Optional[str] = None  # "malware" / "vulnerability" / None


@dataclass
class ParamInfo:
    index: int
    name: str
    type_name: str
    description: str


@dataclass
class StructProposal:
    name: str
    fields: List[Dict[str, Any]]


@dataclass
class AnalysisResponse:
    name: str
    confidence: float
    prototype: str
    params: List[ParamInfo] = field(default_factory=list)
    comment: str = ""
    struct_proposals: List[StructProposal] = field(default_factory=list)
    evidence_summary: str = ""


# ---------------------------------------------------------------------------
# Reasoner
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are a binary reverse engineering assistant. You receive structured facts \
derived from static analysis of a binary function and must name and type it.

Your response MUST be valid JSON matching this schema exactly:
{
  "name": "<snake_case_function_name>",
  "confidence": <float 0.0-1.0>,
  "prototype": "<C function prototype>",
  "params": [{"index": 0, "name": "<name>", "type_name": "<type>", "description": "<desc>"}],
  "comment": "<one line — why this function, what it does>",
  "struct_proposals": [{"name": "<StructName>", "fields": [{"offset": 0, "name": "<f>", "type": "<t>"}]}],
  "evidence_summary": "<why you chose this name>"
}

Rules:
- Use evidence from the structured facts, not guesswork.
- If confidence < 0.5, prefix name with "likely_".
- comment must be one line maximum.
- struct_proposals only if a new struct is evident from usage patterns.
- Never return prose outside the JSON object.
"""


class LLMReasoner:
    def __init__(
        self,
        client: LLMClient,
        graph: KnowledgeGraph,
        cost_tracker: CostTracker,
    ) -> None:
        self._client = client
        self._graph = graph
        self._cost_tracker = cost_tracker

    def analyze_function(
        self,
        request: AnalysisRequest,
        host_decompile_fn=None,
    ) -> AnalysisResponse:
        decompilation = request.decompilation
        if not decompilation and host_decompile_fn:
            try:
                decompilation = host_decompile_fn(request.function.address)
            except Exception as exc:
                decompilation = f"[decompilation unavailable: {exc}]"

        user_content = _build_user_message(request, decompilation)
        messages = [Message(role="user", content=user_content)]

        try:
            response = self._client.chat(
                messages=messages,
                tools=[],
                system=_SYSTEM_PROMPT,
                max_tokens=1024,
                temperature=0.0,
            )
        except Exception as exc:
            logger.error("LLM call failed for 0x%x: %s", request.function.address, exc)
            return AnalysisResponse(
                name=f"unknown_{request.function.address:x}",
                confidence=0.0,
                prototype="void unknown(void)",
                evidence_summary=f"LLM call failed: {exc}",
            )

        return _parse_response(response.content, request.function.address)

    def answer_question(self, question: str, context: str) -> str:
        messages = [Message(role="user", content=f"Context:\n{context}\n\nQuestion: {question}")]
        try:
            response = self._client.chat(
                messages=messages,
                tools=[],
                system="You are a binary reverse engineering assistant. Answer the question based on the analysis context provided.",
                max_tokens=2048,
            )
            return response.content
        except Exception as exc:
            return f"[Error: {exc}]"

    def global_synthesis(self, graph_summary: str) -> str:
        messages = [Message(
            role="user",
            content=f"Binary analysis summary:\n{graph_summary}\n\nProvide a unified analysis: unify naming conventions, identify the overall architecture, list key components, and summarize the binary's purpose.",
        )]
        try:
            response = self._client.chat(
                messages=messages,
                tools=[],
                system="You are a senior reverse engineer performing global synthesis of a full binary analysis.",
                max_tokens=4096,
            )
            return response.content
        except Exception as exc:
            return f"[Global synthesis failed: {exc}]"

    def generate_report(self, goal: str, graph_summary: str) -> str:
        system = """\
You are a senior binary reverse engineer writing a technical analysis report.

Output ONLY valid Markdown. Structure your report with these sections (include all that apply):

# Binary Analysis Report

## 1. Overview
One paragraph: binary type, format, architecture, overall purpose.

## 2. Key Functions
Markdown table: Function | Address | Role

## 3. Program Behavior
Numbered walkthrough of the execution flow.

## 4. Flag / Objective (CTF)
If this is a CTF binary: how the flag/objective is reached.

## 5. Vulnerability / Mechanism
Root cause, primitive, and why it is exploitable.

## 6. Exploitation Path
Numbered step-by-step exploit procedure.

## 7. Conclusion
Two-sentence summary: what the binary is and what the finding is.

Omit sections that are not applicable. Do not include placeholder text. \
Be specific — use function names and addresses from the provided analysis."""

        messages = [Message(
            role="user",
            content=f"Analysis goal: {goal}\n\n{graph_summary}\n\nWrite the full structured report now.",
        )]
        try:
            response = self._client.chat(
                messages=messages,
                tools=[],
                system=system,
                max_tokens=8192,
            )
            return response.content
        except Exception as exc:
            return f"[Report generation failed: {exc}]"

    def form_hypothesis(self, component_summary: str, claim_template: str) -> str:
        messages = [Message(
            role="user",
            content=f"Component analysis:\n{component_summary}\n\nForm a specific testable hypothesis about: {claim_template}",
        )]
        try:
            response = self._client.chat(
                messages=messages,
                tools=[],
                system="You are a reverse engineer forming testable hypotheses about binary components. Be specific and falsifiable.",
                max_tokens=512,
            )
            return response.content.strip()
        except Exception as exc:
            return claim_template


def _build_user_message(req: AnalysisRequest, decompilation: str) -> str:
    lines = [
        f"Function: 0x{req.function.address:x}  raw_name={req.function.raw_name}",
        f"Size: {req.function.size_class.value}",
        f"Obfuscated: {req.function.obfuscated}",
    ]

    if req.known_callees:
        callee_strs = [f"{c.display_name}(0x{c.address:x})" for c in req.known_callees[:10]]
        lines.append(f"Known callees: {', '.join(callee_strs)}")

    if req.import_context:
        imp_strs = [f"{i.name}[{','.join(i.categories)}]" for i in req.import_context[:8]]
        lines.append(f"Imports called: {', '.join(imp_strs)}")

    if req.type_inferences:
        lines.append(f"Type inferences: {'; '.join(req.type_inferences[:5])}")

    if req.string_clusters:
        for sc in req.string_clusters[:3]:
            lines.append(f"String cluster [{sc.category}]: {', '.join(repr(s) for s in sc.samples[:4])}")

    if req.component_hypothesis:
        lines.append(f"Component hypothesis: {req.component_hypothesis}")

    if req.obfuscation_notes:
        lines.append(f"Obfuscation: {'; '.join(req.obfuscation_notes)}")

    if req.focus:
        lines.append(f"Analysis focus: {req.focus}")

    lines += ["", "Decompilation:", decompilation or "(not available)"]
    lines.append("\nRespond with JSON only.")
    return "\n".join(lines)


def _parse_response(content: str, address: int) -> AnalysisResponse:
    try:
        # Find JSON object in response
        start = content.find("{")
        end = content.rfind("}") + 1
        if start == -1 or end == 0:
            raise ValueError("No JSON object found")
        data = json.loads(content[start:end])

        params = [
            ParamInfo(
                index=p.get("index", i),
                name=p.get("name", f"arg{i}"),
                type_name=p.get("type_name", "void*"),
                description=p.get("description", ""),
            )
            for i, p in enumerate(data.get("params", []))
        ]

        struct_proposals = [
            StructProposal(name=s["name"], fields=s.get("fields", []))
            for s in data.get("struct_proposals", [])
        ]

        return AnalysisResponse(
            name=data.get("name", f"unknown_{address:x}"),
            confidence=float(data.get("confidence", 0.5)),
            prototype=data.get("prototype", "void unknown(void)"),
            params=params,
            comment=data.get("comment", ""),
            struct_proposals=struct_proposals,
            evidence_summary=data.get("evidence_summary", ""),
        )
    except Exception as exc:
        logger.warning("Failed to parse LLM response for 0x%x: %s", address, exc)
        return AnalysisResponse(
            name=f"unknown_{address:x}",
            confidence=0.0,
            prototype="void unknown(void)",
            evidence_summary=f"Parse error: {exc}",
        )
