"""
Eval metrics — symbol_accuracy and type_accuracy.
Both are computed against a ground truth list of {address, name, prototype}.
"""

from __future__ import annotations

from typing import Any, Dict, List

from reeve.core.knowledge_graph import KnowledgeGraph


def symbol_accuracy(graph: KnowledgeGraph, ground_truth: List[Dict[str, Any]]) -> float:
    """
    Fraction of ground-truth functions whose recovered name exactly matches
    OR is a reasonable prefix/suffix match (e.g. 'parse_http' in 'parse_http_response').
    """
    if not ground_truth:
        return 0.0

    correct = 0
    for entry in ground_truth:
        address = entry.get("address", 0)
        if isinstance(address, str):
            address = int(address, 16)
        expected = entry.get("name", "").lower()
        fn = graph.get_function(address)
        if fn is None:
            continue
        got = fn.display_name.lower()
        if got == expected or expected in got or got in expected:
            correct += 1

    return correct / len(ground_truth)


def type_accuracy(graph: KnowledgeGraph, ground_truth: List[Dict[str, Any]]) -> float:
    """
    Fraction of ground-truth functions whose prototype is recovered
    (exact match on the prototype string).
    """
    entries_with_proto = [e for e in ground_truth if e.get("prototype")]
    if not entries_with_proto:
        return 0.0

    correct = 0
    for entry in entries_with_proto:
        address = entry.get("address", 0)
        if isinstance(address, str):
            address = int(address, 16)
        expected = entry.get("prototype", "").strip()
        fn = graph.get_function(address)
        if fn is None or not fn.prototype.value:
            continue
        got = str(fn.prototype.value).strip()
        if got == expected:
            correct += 1

    return correct / len(entries_with_proto)
