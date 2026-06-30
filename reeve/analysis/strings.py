"""
Categorizes strings and links them to the functions that reference them.
"""

from __future__ import annotations

import logging
import re

from reeve.core.knowledge_graph import KnowledgeGraph, StringNode
from reeve.host.base import HostBridge

logger = logging.getLogger(__name__)

_URL_RE      = re.compile(r"^(https?|ftp|ws)://", re.IGNORECASE)
_IP_RE       = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$")
_UUID_RE     = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_PATH_WIN_RE = re.compile(r"^[A-Za-z]:\\", re.IGNORECASE)
_PATH_NIX_RE = re.compile(r"^/[a-zA-Z]")
_REGISTRY_RE = re.compile(r"HKEY_|SOFTWARE\\|SYSTEM\\|CurrentVersion", re.IGNORECASE)
_FORMAT_RE   = re.compile(r"%[diouxXeEfgGcsSp%]")
_BASE64_RE   = re.compile(r"^[A-Za-z0-9+/]{20,}={0,2}$")
_HEX_KEY_RE  = re.compile(r"^[0-9a-fA-F]{16,}$")
_ERROR_RE    = re.compile(r"\b(error|fail|invalid|denied|unauthorized|forbidden|exception)\b", re.IGNORECASE)


def _categorize(value: str) -> str:
    if _URL_RE.match(value):
        return "url"
    if _IP_RE.match(value):
        return "ip"
    if _UUID_RE.match(value):
        return "uuid"
    if _REGISTRY_RE.search(value):
        return "registry"
    if _PATH_WIN_RE.match(value) or _PATH_NIX_RE.match(value):
        return "path"
    if _FORMAT_RE.search(value):
        return "format"
    if _ERROR_RE.search(value):
        return "error"
    if _HEX_KEY_RE.match(value) or _BASE64_RE.match(value):
        return "crypto_key"
    return "unknown"


class StringAnalyzer:
    def analyze(self, host: HostBridge, graph: KnowledgeGraph) -> None:
        raw_strings = host.list_strings()
        added = 0
        for s in raw_strings:
            address: int = s["address"]
            value: str = s.get("value", "")
            if not value or len(value) < 3:
                continue
            node = StringNode(address=address, value=value, category=_categorize(value))
            graph.add_string(node)
            added += 1
            for xref in host.xrefs_to(address):
                fn = graph.get_function(xref.from_address)
                if fn is not None:
                    graph.add_string_ref(fn.address, address)
        logger.info("StringAnalyzer: %d strings", added)
