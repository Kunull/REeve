"""
Resolves imported symbols and tags them with behavioral categories.
Adds ImportNodes to the KnowledgeGraph and wires up CALLS edges from
import-calling functions.
"""

from __future__ import annotations

import logging
from typing import Dict, List

from reeve.core.knowledge_graph import ImportNode, KnowledgeGraph
from reeve.host.base import HostBridge

logger = logging.getLogger(__name__)

# Normalized import name → list of category tags
_CATEGORY_MAP: Dict[str, List[str]] = {
    # network
    "socket": ["network"], "bind": ["network"], "listen": ["network"],
    "accept": ["network"], "connect": ["network"], "send": ["network"],
    "recv": ["network"], "sendto": ["network"], "recvfrom": ["network"],
    "WSAStartup": ["network"], "WSAConnect": ["network"],
    "WSASend": ["network"], "WSARecv": ["network"],
    "getaddrinfo": ["network", "dns"], "gethostbyname": ["network", "dns"],
    "gethostbyaddr": ["network", "dns"], "inet_addr": ["network"],
    "inet_ntoa": ["network"], "htons": ["network"], "ntohs": ["network"],
    "select": ["network"], "poll": ["network"], "epoll_create": ["network"],
    "curl_easy_init": ["network", "http"], "curl_easy_perform": ["network", "http"],
    "curl_easy_setopt": ["network", "http"],
    "SSL_connect": ["network", "tls"], "SSL_accept": ["network", "tls"],
    "SSL_read": ["network", "tls"], "SSL_write": ["network", "tls"],
    "SSL_CTX_new": ["network", "tls"], "TLS_client_method": ["network", "tls"],
    "HttpOpenRequest": ["network", "http"], "InternetOpenUrl": ["network", "http"],
    "WinHttpOpen": ["network", "http"], "WinHttpConnect": ["network", "http"],
    # crypto
    "AES_encrypt": ["crypto", "aes"], "AES_decrypt": ["crypto", "aes"],
    "AES_set_encrypt_key": ["crypto", "aes"], "AES_set_decrypt_key": ["crypto", "aes"],
    "EVP_EncryptInit": ["crypto"], "EVP_EncryptInit_ex": ["crypto"],
    "EVP_DecryptInit": ["crypto"], "EVP_DecryptInit_ex": ["crypto"],
    "EVP_DigestInit": ["crypto", "hash"], "EVP_DigestInit_ex": ["crypto", "hash"],
    "MD5_Init": ["crypto", "hash"], "SHA256_Init": ["crypto", "hash"],
    "SHA1_Init": ["crypto", "hash"], "SHA512_Init": ["crypto", "hash"],
    "RSA_public_encrypt": ["crypto", "rsa"], "RSA_private_decrypt": ["crypto", "rsa"],
    "CryptEncrypt": ["crypto"], "CryptDecrypt": ["crypto"],
    "BCryptEncrypt": ["crypto"], "BCryptDecrypt": ["crypto"],
    "BCryptGenerateSymmetricKey": ["crypto"], "BCryptGenRandom": ["crypto", "random"],
    "RAND_bytes": ["crypto", "random"],
    # filesystem
    "fopen": ["filesystem"], "fclose": ["filesystem"],
    "fread": ["filesystem"], "fwrite": ["filesystem"],
    "CreateFileA": ["filesystem"], "CreateFileW": ["filesystem"],
    "ReadFile": ["filesystem"], "WriteFile": ["filesystem"],
    "DeleteFileA": ["filesystem"], "DeleteFileW": ["filesystem"],
    "MoveFileA": ["filesystem"], "CopyFileA": ["filesystem"],
    "FindFirstFileA": ["filesystem"], "FindNextFileA": ["filesystem"],
    "GetTempPathA": ["filesystem"], "GetTempFileNameA": ["filesystem"],
    "open": ["filesystem"], "read": ["filesystem"], "write": ["filesystem"],
    "unlink": ["filesystem"], "rename": ["filesystem"],
    "RegOpenKeyEx": ["filesystem", "registry"], "RegOpenKeyExA": ["filesystem", "registry"],
    "RegCreateKeyEx": ["filesystem", "registry"],
    "RegQueryValueEx": ["filesystem", "registry"],
    "RegSetValueEx": ["filesystem", "registry"],
    "RegDeleteKey": ["filesystem", "registry"],
    # process / injection
    "CreateProcess": ["process"], "CreateProcessA": ["process"],
    "CreateProcessW": ["process"], "ShellExecute": ["process"],
    "WinExec": ["process"], "system": ["process"],
    "VirtualAlloc": ["memory", "process"], "VirtualAllocEx": ["memory", "process", "injection"],
    "VirtualProtect": ["memory", "process"],
    "WriteProcessMemory": ["process", "injection"],
    "ReadProcessMemory": ["process", "injection"],
    "CreateRemoteThread": ["process", "injection"],
    "OpenProcess": ["process"], "TerminateProcess": ["process"],
    "NtCreateThread": ["process", "injection"], "RtlCreateUserThread": ["process", "injection"],
    "LoadLibrary": ["process", "loader"], "LoadLibraryA": ["process", "loader"],
    "LoadLibraryW": ["process", "loader"], "LoadLibraryEx": ["process", "loader"],
    "GetProcAddress": ["process", "loader"], "FreeLibrary": ["process", "loader"],
    "NtMapViewOfSection": ["process", "injection"], "MapViewOfFile": ["memory"],
    # anti-analysis
    "IsDebuggerPresent": ["anti_analysis"], "CheckRemoteDebuggerPresent": ["anti_analysis"],
    "NtQueryInformationProcess": ["anti_analysis"], "OutputDebugString": ["anti_analysis"],
    "FindWindow": ["anti_analysis"], "GetTickCount": ["timing"],
    "QueryPerformanceCounter": ["timing"], "timeGetTime": ["timing"],
    # persistence
    "RegSetValue": ["persistence", "registry"],
    "SHGetSpecialFolderPath": ["persistence", "filesystem"],
    "CreateService": ["persistence", "service"], "OpenSCManager": ["persistence", "service"],
    # memory
    "malloc": ["memory"], "calloc": ["memory"], "realloc": ["memory"],
    "free": ["memory"], "HeapAlloc": ["memory"], "HeapFree": ["memory"],
    "LocalAlloc": ["memory"], "GlobalAlloc": ["memory"],
}


def _normalize_name(name: str) -> str:
    """Strip leading underscores and trailing A/W suffixes for matching."""
    name = name.lstrip("_")
    # Keep A/W suffix stripping only for known Win32 patterns
    if len(name) > 2 and name[-1] in ("A", "W") and name[-2].isupper():
        stripped = name[:-1]
        if stripped in _CATEGORY_MAP:
            return stripped
    return name


class ImportResolver:
    """
    Walks the import table, tags each import with behavioral categories,
    creates ImportNodes in the KnowledgeGraph, and adds CALLS edges
    from importing functions to their import stubs.
    """

    def resolve(self, host: HostBridge, graph: KnowledgeGraph) -> int:
        """Return the number of imports resolved."""
        imports = host.list_imports()
        resolved = 0

        for imp in imports:
            name: str = imp["name"]
            library: str = imp.get("library", "")
            address: int = imp.get("address", 0)

            normalized = _normalize_name(name)
            categories = (
                _CATEGORY_MAP.get(name)
                or _CATEGORY_MAP.get(normalized)
                or []
            )

            node = ImportNode(
                name=name,
                library=library,
                resolved_address=address if address else None,
                categories=list(categories),
            )
            graph.add_import(node)
            resolved += 1

            # Wire up CALLS edges: find functions that call this import stub
            if address:
                for xref in host.xrefs_to(address):
                    if xref.kind == "call":
                        caller_fn = graph.get_function(xref.from_address)
                        # The xref.from_address is inside the caller; find the function
                        if caller_fn is None:
                            # Try to find which function contains this address
                            for fn in graph.all_functions():
                                # Rough check: from_address is near function start
                                if abs(fn.address - xref.from_address) < 0x10000:
                                    graph.add_call(fn.address, address)
                                    break
                        else:
                            graph.add_call(caller_fn.address, address)

        logger.info("ImportResolver: resolved %d imports", resolved)
        return resolved
