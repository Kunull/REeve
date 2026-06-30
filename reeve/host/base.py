"""Abstract disassembler interface. All host-specific code lives in subclasses."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class FunctionInfo:
    address: int
    name: str
    size: int          # byte size of function body
    block_count: int   # number of basic blocks (approximation)
    is_thunk: bool
    is_external: bool


@dataclass
class XRef:
    from_address: int
    to_address: int
    kind: str          # "call" / "data" / "jump"


@dataclass
class Capabilities:
    has_decompiler: bool
    has_il: bool
    has_type_system: bool
    host_name: str     # "ghidra" / "ida" / "binja"


class HostBridge(ABC):
    """Disassembler-agnostic API. Tools call methods here; subclasses handle threading and APIs."""

    @property
    @abstractmethod
    def capabilities(self) -> Capabilities: ...

    @abstractmethod
    def list_functions(self) -> List[FunctionInfo]: ...

    @abstractmethod
    def decompile(self, address: int) -> str: ...

    @abstractmethod
    def get_disassembly(self, address: int, max_lines: int = 50) -> str: ...

    @abstractmethod
    def xrefs_to(self, address: int) -> List[XRef]: ...

    @abstractmethod
    def xrefs_from(self, address: int) -> List[XRef]: ...

    @abstractmethod
    def list_imports(self) -> List[dict]: ...  # [{name, library, address}]

    @abstractmethod
    def list_exports(self) -> List[dict]: ...  # [{name, address}]

    @abstractmethod
    def list_strings(self) -> List[dict]: ...  # [{address, value, length}]

    @abstractmethod
    def read_bytes(self, address: int, count: int) -> bytes: ...

    @abstractmethod
    def rename_function(self, address: int, name: str) -> None: ...

    @abstractmethod
    def set_comment(self, address: int, comment: str) -> None: ...

    @abstractmethod
    def get_comment(self, address: int) -> str: ...

    @abstractmethod
    def set_function_prototype(self, address: int, prototype: str) -> None: ...

    @abstractmethod
    def get_function_prototype(self, address: int) -> str: ...

    @abstractmethod
    def write_bytes(self, address: int, data: bytes) -> None: ...

    @abstractmethod
    def get_entry_point(self) -> int: ...

    @abstractmethod
    def get_binary_path(self) -> str: ...

    @abstractmethod
    def get_arch(self) -> str: ...

    @abstractmethod
    def get_format(self) -> str: ...  # "ELF" / "PE" / "Mach-O" / ...
