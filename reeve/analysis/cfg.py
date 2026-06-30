"""
Builds the call graph from xref data and detects obfuscation patterns
using heuristics on decompiler output.
"""

from __future__ import annotations

import logging
import re
from typing import List

from reeve.core.knowledge_graph import (
    FunctionNode,
    KnowledgeGraph,
    SizeClass,
)
from reeve.host.base import HostBridge

logger = logging.getLogger(__name__)


def _size_class(block_count: int) -> SizeClass:
    if block_count <= 3:
        return SizeClass.TRIVIAL
    if block_count <= 15:
        return SizeClass.SMALL
    if block_count <= 60:
        return SizeClass.MEDIUM
    return SizeClass.LARGE


class CallGraphBuilder:
    """
    Assigns size classes to FunctionNodes and builds CALLS edges
    in the KnowledgeGraph from xref data.
    """

    def build(self, host: HostBridge, graph: KnowledgeGraph) -> None:
        functions = host.list_functions()
        for fi in functions:
            fn = graph.get_function(fi.address)
            if fn is None:
                continue
            fn.size_class = _size_class(fi.block_count)

        call_count = 0
        for fi in functions:
            try:
                for xref in host.xrefs_from(fi.address):
                    if xref.kind == "call":
                        callee = graph.get_function(xref.to_address)
                        if callee is not None:
                            graph.add_call(fi.address, xref.to_address)
                            call_count += 1
            except Exception as e:
                logger.debug("xrefs_from 0x%x failed: %s", fi.address, e)

        logger.info(
            "CallGraphBuilder: %d functions, %d call edges",
            len(functions),
            call_count,
        )


class ObfuscationDetector:
    """
    Detects obfuscation patterns in decompiler output using
    structural heuristics. Returns a list of pattern names.
    """

    def detect(self, fn: FunctionNode, decompilation: str) -> List[str]:
        patterns: List[str] = []

        if self._has_cff(decompilation):
            patterns.append("control_flow_flattening")

        if self._has_opaque_predicates(decompilation):
            patterns.append("opaque_predicates")

        if self._has_string_encryption(decompilation):
            patterns.append("string_encryption")

        if self._has_dead_code(decompilation):
            patterns.append("dead_code")

        if self._has_mba(decompilation):
            patterns.append("mixed_boolean_arithmetic")

        return patterns

    # ------------------------------------------------------------------
    # Pattern detectors
    # ------------------------------------------------------------------

    def _has_cff(self, code: str) -> bool:
        """
        CFF signature: a large switch statement whose selector is a state
        variable that gets rewritten inside the cases (dispatcher pattern).
        """
        switch_matches = re.findall(r"\bswitch\s*\(", code)
        if not switch_matches:
            return False

        # Count case labels — CFF typically has many non-sequential ones
        cases = re.findall(r"\bcase\s+0x[0-9a-fA-F]+\s*:", code)
        if len(cases) >= 5:
            return True

        # Also check for a while(true)/for(;;) enclosing a switch
        has_infinite_loop = bool(
            re.search(r"\bwhile\s*\(\s*(?:true|1)\s*\)", code)
            or re.search(r"\bfor\s*\(\s*;;\s*\)", code)
        )
        normal_cases = re.findall(r"\bcase\s+\d+\s*:", code)
        return has_infinite_loop and len(normal_cases) >= 4

    def _has_opaque_predicates(self, code: str) -> bool:
        """
        Opaque predicates: conditions like `(x & 1) == 0` that always
        evaluate the same way, or constants used as conditions.
        """
        # Always-true/false arithmetic predicates
        patterns = [
            r"\(\s*\w+\s*\^\s*\w+\s*\)\s*==\s*0",      # (x ^ x) == 0
            r"\(\s*\w+\s*&\s*0\s*\)\s*==\s*0",           # (x & 0) == 0
            r"if\s*\(\s*\d+\s*\)",                        # if (1) / if (0)
            r"if\s*\(\s*0x[0-9a-fA-F]+\s*\)",            # if (0xDEAD)
            r"\(\s*\w+\s*\*\s*\w+\s*&\s*1\s*\)\s*==\s*0", # MBA pattern
        ]
        return any(re.search(p, code) for p in patterns)

    def _has_string_encryption(self, code: str) -> bool:
        """
        String encryption signature: XOR loop over a byte array with
        a key, typically followed by NUL termination.
        """
        # XOR loop with indexed array access
        xor_loop = bool(
            re.search(r"for\s*\(.*\)\s*\{[^}]*\w+\[\w+\]\s*=\s*\w+\[\w+\]\s*\^\s*\w+", code, re.DOTALL)
            or re.search(r"\w+\[\w+\]\s*\^=\s*\w+", code)
        )
        # Multiple XOR ops in sequence (unrolled)
        xor_count = len(re.findall(r"\^=\s*0x[0-9a-fA-F]{2}\b", code))
        return xor_loop or xor_count >= 4

    def _has_dead_code(self, code: str) -> bool:
        """Dead code: unreachable statements after goto/return/break."""
        return bool(
            re.search(r"\b(?:goto|return|break)\s*[^;]*;\s*\w+\s*=", code)
        )

    def _has_mba(self, code: str) -> bool:
        """
        Mixed boolean-arithmetic: combinations of +, -, &, |, ^, ~
        in a single expression that suggests obfuscated arithmetic.
        """
        # Look for expressions with 3+ distinct bitwise operators in one line
        for line in code.split("\n"):
            ops = set(re.findall(r"[&|^~]", line))
            if len(ops) >= 3 and "+" in line:
                return True
        return False
