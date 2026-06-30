"""
Central knowledge graph for all derived facts about a binary.
Every claim has a confidence score, source, and evidence chain.
Dirty-tracking propagates name/type updates through the call graph.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple

import networkx as nx


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class FactSource(Enum):
    STATIC_ANALYSIS = "static_analysis"
    SIGNATURE_MATCH  = "signature_match"
    LLM              = "llm"
    ANALYST          = "analyst"


class SizeClass(Enum):
    TRIVIAL = "trivial"   # ≤5 basic blocks
    SMALL   = "small"     # 6–20
    MEDIUM  = "medium"    # 21–100
    LARGE   = "large"     # 100+


class SourceLang(Enum):
    C       = "c"
    CPP     = "cpp"
    GO      = "go"
    RUST    = "rust"
    UNKNOWN = "unknown"


class EdgeKind(Enum):
    CALLS       = "CALLS"
    REFERENCES  = "REFERENCES"   # function → string/data
    USES_TYPE   = "USES_TYPE"
    MEMBER_OF   = "MEMBER_OF"    # function → component
    EVIDENCE_FOR = "EVIDENCE_FOR"


class HypothesisStatus(Enum):
    OPEN      = "open"
    CONFIRMED = "confirmed"
    REFUTED   = "refuted"
    DEFERRED  = "deferred"


# ---------------------------------------------------------------------------
# Fact wrapper
# ---------------------------------------------------------------------------

@dataclass
class Fact:
    """A single claim with confidence, provenance, and dirty state."""
    value: Any
    confidence: float
    source: FactSource
    evidence: List[str] = field(default_factory=list)
    dirty: bool = False

    def update(
        self,
        value: Any,
        confidence: float,
        source: FactSource,
        evidence: List[str],
    ) -> bool:
        """Return True if the update was accepted (higher confidence or analyst override)."""
        if source == FactSource.ANALYST or confidence > self.confidence:
            self.value = value
            self.confidence = confidence
            self.source = source
            self.evidence = evidence
            self.dirty = False
            return True
        return False

    def mark_dirty(self) -> None:
        self.dirty = True


# ---------------------------------------------------------------------------
# Node types
# ---------------------------------------------------------------------------

@dataclass
class FunctionNode:
    address: int
    raw_name: str                           # disassembler default, e.g. "sub_401000"
    name: Fact                              # recovered name
    prototype: Fact                         # e.g. "int parse_http_response(int sock)"
    size_class: SizeClass = SizeClass.SMALL
    source_lang: SourceLang = SourceLang.UNKNOWN
    component_id: Optional[str] = None
    obfuscated: bool = False
    obfuscation_patterns: List[str] = field(default_factory=list)
    is_resolved: bool = False               # True = auto-resolved (sig match / analyst)
    comment: Optional[str] = None

    @classmethod
    def unanalyzed(cls, address: int, raw_name: str) -> "FunctionNode":
        return cls(
            address=address,
            raw_name=raw_name,
            name=Fact(value=raw_name, confidence=0.0, source=FactSource.STATIC_ANALYSIS),
            prototype=Fact(value=None, confidence=0.0, source=FactSource.STATIC_ANALYSIS),
        )

    @property
    def display_name(self) -> str:
        return self.name.value or self.raw_name


@dataclass
class TypeNode:
    name: str
    kind: str                               # struct / enum / typedef / pointer
    fields: List[Dict[str, Any]] = field(default_factory=list)
    size: Optional[int] = None
    confidence: float = 0.0
    source: FactSource = FactSource.LLM


@dataclass
class StringNode:
    address: int
    value: str
    encoding: str = "utf-8"
    category: str = "unknown"               # url/path/error/format/uuid/crypto/unknown


@dataclass
class ImportNode:
    name: str
    library: str = ""
    resolved_address: Optional[int] = None
    categories: List[str] = field(default_factory=list)  # network/crypto/filesystem/…


@dataclass
class ComponentNode:
    id: str
    name: Optional[str] = None
    purpose: Optional[str] = None
    confidence: float = 0.0


@dataclass
class HypothesisNode:
    id: str
    claim: str
    confidence: float = 0.0
    status: HypothesisStatus = HypothesisStatus.OPEN
    evidence_for: List[str] = field(default_factory=list)
    evidence_against: List[str] = field(default_factory=list)
    verification_task_ids: List[str] = field(default_factory=list)

    @classmethod
    def new(cls, claim: str) -> "HypothesisNode":
        return cls(id=str(uuid.uuid4())[:8], claim=claim)

    def add_evidence_for(self, evidence: str, weight: float = 0.1) -> None:
        self.evidence_for.append(evidence)
        self.confidence = min(1.0, self.confidence + weight)
        if self.confidence >= 0.85:
            self.status = HypothesisStatus.CONFIRMED

    def add_evidence_against(self, evidence: str, weight: float = 0.1) -> None:
        self.evidence_against.append(evidence)
        self.confidence = max(0.0, self.confidence - weight)
        if self.confidence <= 0.15:
            self.status = HypothesisStatus.REFUTED


# ---------------------------------------------------------------------------
# Knowledge Graph
# ---------------------------------------------------------------------------

class KnowledgeGraph:
    """
    Queryable, evidence-scored graph of everything known about a binary.
    Nodes are looked up by address (functions, strings) or name (types, imports).
    Edges are stored in a DiGraph for graph algorithm access.
    """

    def __init__(self) -> None:
        self._graph: nx.DiGraph = nx.DiGraph()
        self._functions: Dict[int, FunctionNode] = {}
        self._types: Dict[str, TypeNode] = {}
        self._strings: Dict[int, StringNode] = {}
        self._imports: Dict[str, ImportNode] = {}
        self._components: Dict[str, ComponentNode] = {}
        self._hypotheses: Dict[str, HypothesisNode] = {}

    # ------------------------------------------------------------------
    # Functions
    # ------------------------------------------------------------------

    def add_function(self, fn: FunctionNode) -> None:
        self._functions[fn.address] = fn
        self._graph.add_node(fn.address, kind="function")

    def get_function(self, address: int) -> Optional[FunctionNode]:
        return self._functions.get(address)

    def get_function_by_name(self, name: str) -> Optional[FunctionNode]:
        for fn in self._functions.values():
            if fn.display_name == name or fn.raw_name == name:
                return fn
        return None

    def all_functions(self) -> List[FunctionNode]:
        return list(self._functions.values())

    def update_function_name(
        self,
        address: int,
        name: str,
        confidence: float,
        source: FactSource,
        evidence: List[str],
    ) -> bool:
        fn = self._functions.get(address)
        if fn is None:
            return False
        accepted = fn.name.update(name, confidence, source, evidence)
        if accepted:
            self._dirty_mark_callers(address)
        return accepted

    def find_functions(
        self,
        calls: Optional[str] = None,
        called_by: Optional[str] = None,
        component_id: Optional[str] = None,
        size_class: Optional[SizeClass] = None,
        min_confidence: float = 0.0,
        unresolved_only: bool = False,
        obfuscated_only: bool = False,
    ) -> List[FunctionNode]:
        results = list(self._functions.values())

        if calls is not None:
            callee_addrs = {
                fn.address
                for fn in self._functions.values()
                if fn.display_name == calls or fn.raw_name == calls
            }
            results = [
                fn for fn in results
                if any(
                    self._graph.has_edge(fn.address, ca)
                    for ca in callee_addrs
                )
            ]

        if called_by is not None:
            caller_fns = self.find_functions(calls=None)  # get all
            caller_addrs = {
                fn.address
                for fn in self._functions.values()
                if fn.display_name == called_by or fn.raw_name == called_by
            }
            results = [
                fn for fn in results
                if any(
                    self._graph.has_edge(ca, fn.address)
                    for ca in caller_addrs
                )
            ]

        if component_id is not None:
            results = [fn for fn in results if fn.component_id == component_id]

        if size_class is not None:
            results = [fn for fn in results if fn.size_class == size_class]

        if min_confidence > 0.0:
            results = [fn for fn in results if fn.name.confidence >= min_confidence]

        if unresolved_only:
            results = [fn for fn in results if not fn.is_resolved]

        if obfuscated_only:
            results = [fn for fn in results if fn.obfuscated]

        return results

    # ------------------------------------------------------------------
    # Call graph edges
    # ------------------------------------------------------------------

    def add_call(self, caller_addr: int, callee_addr: int) -> None:
        self._graph.add_edge(caller_addr, callee_addr, kind=EdgeKind.CALLS.value)

    def callees_of(self, address: int) -> List[FunctionNode]:
        return [
            self._functions[n]
            for n in self._graph.successors(address)
            if n in self._functions
        ]

    def callers_of(self, address: int) -> List[FunctionNode]:
        return [
            self._functions[n]
            for n in self._graph.predecessors(address)
            if n in self._functions
        ]

    def bfs_bottom_up(self) -> Iterator[FunctionNode]:
        """Yield functions leaf-first (BFS from leaves up), for call-graph-ordered analysis."""
        rev = self._graph.reverse()
        leaves = [n for n in rev.nodes if rev.in_degree(n) == 0 and n in self._functions]
        visited: Set[int] = set()
        queue = list(leaves)
        while queue:
            addr = queue.pop(0)
            if addr in visited:
                continue
            visited.add(addr)
            if addr in self._functions:
                yield self._functions[addr]
            for pred in self._graph.predecessors(addr):
                if pred not in visited:
                    queue.append(pred)

    def _dirty_mark_callers(self, address: int) -> None:
        """When a function's name changes, mark its callers' name facts dirty."""
        for caller in self.callers_of(address):
            caller.name.mark_dirty()
            caller.prototype.mark_dirty()

    def dirty_functions(self) -> List[FunctionNode]:
        return [fn for fn in self._functions.values() if fn.name.dirty]

    # ------------------------------------------------------------------
    # Imports
    # ------------------------------------------------------------------

    def add_import(self, imp: ImportNode) -> None:
        self._imports[imp.name] = imp

    def get_import(self, name: str) -> Optional[ImportNode]:
        return self._imports.get(name)

    def all_imports(self) -> List[ImportNode]:
        return list(self._imports.values())

    def imports_by_category(self, category: str) -> List[ImportNode]:
        return [i for i in self._imports.values() if category in i.categories]

    # ------------------------------------------------------------------
    # Strings
    # ------------------------------------------------------------------

    def add_string(self, s: StringNode) -> None:
        self._strings[s.address] = s
        self._graph.add_node(s.address, kind="string")

    def get_string(self, address: int) -> Optional[StringNode]:
        return self._strings.get(address)

    def all_strings(self) -> List[StringNode]:
        return list(self._strings.values())

    def strings_by_category(self, category: str) -> List[StringNode]:
        return [s for s in self._strings.values() if s.category == category]

    def add_string_ref(self, fn_address: int, string_address: int) -> None:
        self._graph.add_edge(fn_address, string_address, kind=EdgeKind.REFERENCES.value)

    def strings_referenced_by(self, fn_address: int) -> List[StringNode]:
        return [
            self._strings[n]
            for n in self._graph.successors(fn_address)
            if n in self._strings
        ]

    # ------------------------------------------------------------------
    # Types
    # ------------------------------------------------------------------

    def add_type(self, t: TypeNode) -> None:
        self._types[t.name] = t

    def get_type(self, name: str) -> Optional[TypeNode]:
        return self._types.get(name)

    def all_types(self) -> List[TypeNode]:
        return list(self._types.values())

    # ------------------------------------------------------------------
    # Components
    # ------------------------------------------------------------------

    def add_component(self, c: ComponentNode) -> None:
        self._components[c.id] = c

    def get_component(self, component_id: str) -> Optional[ComponentNode]:
        return self._components.get(component_id)

    def all_components(self) -> List[ComponentNode]:
        return list(self._components.values())

    def functions_in_component(self, component_id: str) -> List[FunctionNode]:
        return self.find_functions(component_id=component_id)

    # ------------------------------------------------------------------
    # Hypotheses
    # ------------------------------------------------------------------

    def add_hypothesis(self, h: HypothesisNode) -> None:
        self._hypotheses[h.id] = h

    def get_hypothesis(self, hypothesis_id: str) -> Optional[HypothesisNode]:
        return self._hypotheses.get(hypothesis_id)

    def open_hypotheses(self) -> List[HypothesisNode]:
        return [h for h in self._hypotheses.values() if h.status == HypothesisStatus.OPEN]

    def confirmed_hypotheses(self) -> List[HypothesisNode]:
        return [h for h in self._hypotheses.values() if h.status == HypothesisStatus.CONFIRMED]

    # ------------------------------------------------------------------
    # Stats / summary
    # ------------------------------------------------------------------

    @property
    def stats(self) -> Dict[str, int]:
        return {
            "functions": len(self._functions),
            "resolved": sum(1 for f in self._functions.values() if f.is_resolved),
            "named": sum(1 for f in self._functions.values() if f.name.confidence >= 0.5),
            "dirty": len(self.dirty_functions()),
            "imports": len(self._imports),
            "strings": len(self._strings),
            "types": len(self._types),
            "components": len(self._components),
            "hypotheses": len(self._hypotheses),
            "call_edges": sum(
                1 for _, _, d in self._graph.edges(data=True)
                if d.get("kind") == EdgeKind.CALLS.value
            ),
        }

    def top_functions_by_centrality(self, n: int = 50) -> List[FunctionNode]:
        """Most-connected functions by in-degree (most-called = most important)."""
        in_degrees = dict(self._graph.in_degree())
        ranked = sorted(
            [addr for addr in in_degrees if addr in self._functions],
            key=lambda a: in_degrees[a],
            reverse=True,
        )
        return [self._functions[a] for a in ranked[:n]]

    def serialize_context_block(self, max_functions: int = 100) -> str:
        """Compact summary for LLM system prompt caching."""
        lines = [
            f"Binary stats: {self.stats}",
            "",
            "Top functions:",
        ]
        for fn in self.top_functions_by_centrality(max_functions):
            callee_names = [c.display_name for c in self.callees_of(fn.address)[:5]]
            lines.append(
                f"  0x{fn.address:x}  {fn.display_name}  "
                f"[{fn.size_class.value}]  "
                f"conf={fn.name.confidence:.2f}  "
                f"calls={callee_names}"
            )
        if self._components:
            lines += ["", "Components:"]
            for c in self._components.values():
                lines.append(f"  {c.id}: {c.name or 'unnamed'} — {c.purpose or 'unknown'}")
        return "\n".join(lines)
