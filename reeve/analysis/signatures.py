"""
Matches functions against known stdlib and crypto signature databases.
Auto-resolves matched functions, skipping them from LLM analysis.
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass
from typing import List, Optional

from reeve.core.knowledge_graph import FactSource, KnowledgeGraph
from reeve.host.base import HostBridge

logger = logging.getLogger(__name__)

_SIGS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "signatures")


@dataclass
class SignatureEntry:
    name: str
    categories: List[str]
    byte_patterns: List[str]   # hex strings, "??" = wildcard byte
    import_aliases: List[str]  # exact name matches


def _load_db(filename: str) -> List[SignatureEntry]:
    path = os.path.join(_SIGS_DIR, filename)
    try:
        with open(path) as f:
            raw = json.load(f)
        return [
            SignatureEntry(
                name=e["name"],
                categories=e.get("categories", []),
                byte_patterns=e.get("byte_patterns", []),
                import_aliases=e.get("import_aliases", []),
            )
            for e in raw
        ]
    except Exception as e:
        logger.warning("Failed to load signature DB %s: %s", filename, e)
        return []


def _match_bytes(actual: bytes, pattern: str) -> bool:
    """Match bytes against a hex pattern; '??' matches any byte."""
    parts = pattern.split()
    if len(parts) > len(actual):
        return False
    for i, part in enumerate(parts):
        if part == "??":
            continue
        try:
            if actual[i] != int(part, 16):
                return False
        except (ValueError, IndexError):
            return False
    return True


class SignatureMatcher:
    """
    Matches functions against known signature databases.
    Matched functions are marked is_resolved=True and skip LLM analysis.
    """

    def __init__(self) -> None:
        self._db: List[SignatureEntry] = (
            _load_db("stdlib.json") + _load_db("crypto.json")
        )
        # Build alias lookup for O(1) name matching
        self._alias_map: dict[str, SignatureEntry] = {}
        for entry in self._db:
            for alias in entry.import_aliases:
                self._alias_map[alias] = entry
                self._alias_map[alias.lower()] = entry

        logger.debug("SignatureMatcher: loaded %d signature entries", len(self._db))

    def match(self, host: HostBridge, graph: KnowledgeGraph) -> int:
        """
        Attempt to match all unresolved functions.
        Returns the count of newly resolved functions.
        """
        resolved = 0
        unresolved = graph.find_functions(unresolved_only=True)

        for fn in unresolved:
            entry = self._match_function(fn.raw_name, fn.address, host)
            if entry is None:
                continue

            accepted = graph.update_function_name(
                address=fn.address,
                name=entry.name,
                confidence=1.0,
                source=FactSource.SIGNATURE_MATCH,
                evidence=[
                    f"Name alias match: '{fn.raw_name}' → '{entry.name}'",
                    f"Categories: {', '.join(entry.categories)}",
                ],
            )
            if accepted:
                fn.is_resolved = True
                resolved += 1
                logger.debug("Signature match: 0x%x → %s", fn.address, entry.name)

        logger.info("SignatureMatcher: resolved %d functions", resolved)
        return resolved

    def _match_function(
        self,
        raw_name: str,
        address: int,
        host: HostBridge,
    ) -> Optional[SignatureEntry]:
        # 1. Alias/name match (fastest, most common)
        entry = (
            self._alias_map.get(raw_name)
            or self._alias_map.get(raw_name.lower())
            or self._alias_map.get(raw_name.lstrip("_"))
            or self._alias_map.get(raw_name.lstrip("_").lower())
        )
        if entry:
            return entry

        # 2. Byte pattern match (only if patterns are populated)
        for sig_entry in self._db:
            if not sig_entry.byte_patterns:
                continue
            try:
                first_bytes = host.read_bytes(address, 16)
            except Exception:
                break
            for pattern in sig_entry.byte_patterns:
                if _match_bytes(first_bytes, pattern):
                    return sig_entry

        return None
