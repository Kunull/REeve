"""
Eval harness — compares analysis output against ground truth.
Ground truth is a JSON file with known function names and types.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from reeve.core.knowledge_graph import KnowledgeGraph
from reeve.evals.metrics import symbol_accuracy, type_accuracy

logger = logging.getLogger(__name__)


@dataclass
class EvalResult:
    binary: str
    ground_truth_file: str
    total_functions: int
    matched_functions: int
    symbol_accuracy: float
    type_accuracy: float
    details: List[Dict[str, Any]] = field(default_factory=list)

    def print_summary(self) -> None:
        print(f"\nEval: {self.binary}")
        print(f"  Functions: {self.matched_functions}/{self.total_functions}")
        print(f"  Symbol accuracy: {self.symbol_accuracy:.1%}")
        print(f"  Type accuracy:   {self.type_accuracy:.1%}")
        if self.details:
            mismatches = [d for d in self.details if not d.get("name_match")]
            if mismatches:
                print(f"  Mismatches ({len(mismatches)} total):")
                for m in mismatches[:10]:
                    print(f"    0x{m['address']:x}: expected={m['expected']} got={m['got']}")


class EvalHarness:
    def run(self, graph: KnowledgeGraph, ground_truth_path: Path) -> EvalResult:
        gt_data = json.loads(ground_truth_path.read_text())
        binary = gt_data.get("binary", str(ground_truth_path))
        functions: List[Dict[str, Any]] = gt_data.get("functions", [])

        sym_acc = symbol_accuracy(graph, functions)
        type_acc = type_accuracy(graph, functions)

        details = []
        for entry in functions:
            address = entry.get("address", 0)
            if isinstance(address, str):
                address = int(address, 16)
            expected_name = entry.get("name", "")
            fn = graph.get_function(address)
            got_name = fn.display_name if fn else "(not found)"
            details.append({
                "address": address,
                "expected": expected_name,
                "got": got_name,
                "name_match": got_name == expected_name or (
                    fn is not None and expected_name in got_name
                ),
            })

        matched = sum(1 for d in details if d["name_match"])
        return EvalResult(
            binary=binary,
            ground_truth_file=str(ground_truth_path),
            total_functions=len(functions),
            matched_functions=matched,
            symbol_accuracy=sym_acc,
            type_accuracy=type_acc,
            details=details,
        )
