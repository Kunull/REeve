"""
Clusters functions into components via call graph connectivity
and dominant import categories.
"""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from typing import Dict, Set

import networkx as nx

from reeve.core.knowledge_graph import ComponentNode, KnowledgeGraph

logger = logging.getLogger(__name__)

_PURPOSE_HINTS: Dict[str, str] = {
    "network": "network communication", "http": "HTTP client/server",
    "tls": "TLS/SSL layer", "dns": "DNS resolution",
    "crypto": "cryptographic operations", "aes": "AES encryption",
    "rsa": "RSA encryption", "hash": "hashing / integrity",
    "filesystem": "file I/O", "registry": "registry access",
    "process": "process management", "injection": "process injection",
    "loader": "dynamic loading", "anti_analysis": "anti-analysis / evasion",
    "persistence": "persistence mechanism", "service": "Windows service",
}


class ComponentClusterer:
    def cluster(self, graph: KnowledgeGraph) -> int:
        fn_addrs: Set[int] = {fn.address for fn in graph.all_functions()}
        g = nx.DiGraph()
        g.add_nodes_from(fn_addrs)
        for fn in graph.all_functions():
            for callee in graph.callees_of(fn.address):
                if callee.address in fn_addrs:
                    g.add_edge(fn.address, callee.address)

        wcc = list(nx.weakly_connected_components(g))
        merged, singletons = [], []
        for c in wcc:
            (merged if len(c) >= 3 else singletons).append(c)

        merged_sets = [set(c) for c in merged]
        for addr in (a for s in singletons for a in s):
            best, best_score = None, -1
            for comp in merged_sets:
                score = sum(1 for c in comp if g.has_edge(addr, c) or g.has_edge(c, addr))
                if score > best_score:
                    best_score, best = score, comp
            (best if best is not None else merged_sets[0] if merged_sets else None) and best.add(addr) if best else merged_sets.append({addr})

        for comp_set in merged_sets:
            cid = str(uuid.uuid4())[:8]
            purpose = self._infer_purpose(comp_set, graph)
            graph.add_component(ComponentNode(id=cid, purpose=purpose, confidence=0.6 if purpose else 0.3))
            for addr in comp_set:
                fn = graph.get_function(addr)
                if fn:
                    fn.component_id = cid

        logger.info("ComponentClusterer: %d components", len(merged_sets))
        return len(merged_sets)

    def _infer_purpose(self, addrs: Set[int], graph: KnowledgeGraph) -> str:
        counts: Dict[str, int] = defaultdict(int)
        for addr in addrs:
            for callee in graph.callees_of(addr):
                imp = graph.get_import(callee.raw_name) or graph.get_import(callee.display_name)
                if imp:
                    for cat in imp.categories:
                        counts[cat] += 1
        if not counts:
            return ""
        for cat, _ in sorted(counts.items(), key=lambda x: x[1], reverse=True):
            if cat in _PURPOSE_HINTS:
                return _PURPOSE_HINTS[cat]
        return next(iter(sorted(counts, key=counts.__getitem__, reverse=True)), "")
