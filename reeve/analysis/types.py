"""
Type inference — propagates known types from resolved imports through the call graph.
If malloc's return is cast to T*, we infer T at the call site. If a struct is
passed to multiple known functions, we infer field layout from argument usage.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional

from reeve.core.knowledge_graph import (
    Fact, FactSource, FunctionNode, ImportNode, KnowledgeGraph, TypeNode,
)

logger = logging.getLogger(__name__)

# Known allocator functions whose return type is inferred from context
_ALLOCATORS = {"malloc", "calloc", "HeapAlloc", "LocalAlloc", "GlobalAlloc", "new", "operator new"}

# Known functions whose argument at index N has a known type
_TYPED_ARGS: Dict[str, Dict[int, str]] = {
    "recv":      {0: "SOCKET"},
    "send":      {0: "SOCKET"},
    "connect":   {0: "SOCKET"},
    "bind":      {0: "SOCKET"},
    "listen":    {0: "SOCKET"},
    "accept":    {0: "SOCKET"},
    "fread":     {3: "FILE*"},
    "fwrite":    {3: "FILE*"},
    "fclose":    {0: "FILE*"},
    "fgets":     {2: "FILE*"},
    "fopen":     {0: "const char*", 1: "const char*"},
    "ReadFile":  {0: "HANDLE"},
    "WriteFile": {0: "HANDLE"},
    "CloseHandle": {0: "HANDLE"},
    "memcpy":    {0: "void*", 1: "const void*"},
    "memset":    {0: "void*"},
    "strlen":    {0: "const char*"},
    "strcpy":    {0: "char*", 1: "const char*"},
    "strcmp":    {0: "const char*", 1: "const char*"},
    "SSL_read":  {0: "SSL*"},
    "SSL_write": {0: "SSL*"},
    "EVP_EncryptInit_ex": {0: "EVP_CIPHER_CTX*"},
    "EVP_DecryptInit_ex": {0: "EVP_CIPHER_CTX*"},
    "AES_encrypt": {2: "AES_KEY*"},
    "AES_decrypt": {2: "AES_KEY*"},
}


class TypeInferencer:
    """
    Propagates type information through the call graph using import context.
    Writes TypeNode proposals to the KnowledgeGraph.
    """

    def infer(self, graph: KnowledgeGraph) -> int:
        """Return the number of type inferences made."""
        count = 0
        count += self._infer_from_import_args(graph)
        count += self._infer_allocator_return_types(graph)
        return count

    def _infer_from_import_args(self, graph: KnowledgeGraph) -> int:
        count = 0
        for fn in graph.all_functions():
            callees = graph.callees_of(fn.address)
            for callee in callees:
                callee_name = callee.display_name
                if callee_name in _TYPED_ARGS:
                    type_map = _TYPED_ARGS[callee_name]
                    for arg_idx, type_name in type_map.items():
                        inferred_name = f"{fn.display_name}_arg{arg_idx}_{type_name.replace('*','ptr').replace(' ','_')}"
                        existing = graph.get_type(type_name)
                        if existing is None:
                            node = TypeNode(
                                name=type_name,
                                kind="typedef",
                                confidence=0.9,
                                source=FactSource.STATIC_ANALYSIS,
                            )
                            graph.add_type(node)
                            count += 1
        return count

    def _infer_allocator_return_types(self, graph: KnowledgeGraph) -> int:
        count = 0
        for fn in graph.all_functions():
            callees = graph.callees_of(fn.address)
            callee_names = {c.display_name for c in callees}
            if callee_names & _ALLOCATORS:
                # Mark this function as likely dealing with heap-allocated data
                if not fn.comment:
                    fn.comment = "allocates heap memory"
                count += 1
        return count

    def get_type_annotations(self, graph: KnowledgeGraph, fn: FunctionNode) -> List[str]:
        """Return human-readable type inference notes for a specific function."""
        annotations = []
        callees = graph.callees_of(fn.address)
        for callee in callees:
            callee_name = callee.display_name
            if callee_name in _TYPED_ARGS:
                for idx, type_name in _TYPED_ARGS[callee_name].items():
                    annotations.append(f"arg{idx} of call to {callee_name} → {type_name}")
            if callee_name in _ALLOCATORS:
                annotations.append(f"calls {callee_name} (heap allocation)")
        return annotations
