"""
GhidraHost — HostBridge implementation using PyGhidra + JPype.
Used by the CLI pipeline. Runs Ghidra in-process; no subprocess overhead.
"""

from __future__ import annotations

import logging
import os
from typing import List, Optional

from reeve.host.base import Capabilities, FunctionInfo, HostBridge, XRef

logger = logging.getLogger(__name__)


class GhidraHost(HostBridge):
    """
    Opens a binary in Ghidra, runs auto-analysis, and exposes the program
    database through HostBridge. Use as a context manager.

    Usage:
        with GhidraHost("./binary") as host:
            functions = host.list_functions()
    """

    def __init__(
        self,
        binary_path: str,
        ghidra_install_dir: Optional[str] = None,
        analyze: bool = True,
    ) -> None:
        self._binary_path = os.path.abspath(binary_path)
        self._ghidra_install_dir = ghidra_install_dir or os.environ.get("GHIDRA_INSTALL_DIR")
        self._analyze = analyze
        self._flat_api = None
        self._program = None
        self._listing = None
        self._addr_factory = None
        self._decompiler = None
        self._ctx = None

    def __enter__(self) -> "GhidraHost":
        import pathlib
        import pyghidra

        if self._ghidra_install_dir and not pyghidra.started():
            pyghidra.start(install_dir=pathlib.Path(self._ghidra_install_dir))

        self._ctx = pyghidra.open_program(self._binary_path, analyze=self._analyze)
        self._flat_api = self._ctx.__enter__()
        self._program = self._flat_api.getCurrentProgram()
        self._listing = self._program.getListing()
        self._addr_factory = self._program.getAddressFactory()

        from ghidra.app.decompiler import DecompInterface
        self._decompiler = DecompInterface()
        self._decompiler.openProgram(self._program)

        logger.info("Opened %s (%s)", os.path.basename(self._binary_path), self.get_arch())
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if self._decompiler is not None:
            try:
                self._decompiler.dispose()
            except Exception:
                pass
        if self._ctx is not None:
            self._ctx.__exit__(exc_type, exc_val, exc_tb)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _to_addr(self, address: int):
        return self._addr_factory.getDefaultAddressSpace().getAddress(address)

    def _get_func_at(self, address: int):
        return self._listing.getFunctionAt(self._to_addr(address))

    # ------------------------------------------------------------------
    # Capabilities
    # ------------------------------------------------------------------

    @property
    def capabilities(self) -> Capabilities:
        return Capabilities(
            has_decompiler=True,
            has_il=False,
            has_type_system=True,
            host_name="ghidra",
        )

    # ------------------------------------------------------------------
    # Functions
    # ------------------------------------------------------------------

    def list_functions(self) -> List[FunctionInfo]:
        results = []
        func_iter = self._listing.getFunctions(True)
        while func_iter.hasNext():
            func = func_iter.next()
            body = func.getBody()
            results.append(FunctionInfo(
                address=func.getEntryPoint().getOffset(),
                name=func.getName(),
                size=body.getNumAddresses(),
                block_count=body.getNumAddressRanges(),
                is_thunk=func.isThunk(),
                is_external=func.isExternal(),
            ))
        return results

    # ------------------------------------------------------------------
    # Decompiler
    # ------------------------------------------------------------------

    def decompile(self, address: int) -> str:
        func = self._get_func_at(address)
        if func is None:
            return ""
        try:
            result = self._decompiler.decompileFunction(func, 60, self._flat_api.monitor)
            if result.decompileCompleted():
                return result.getDecompiledFunction().getC()
        except Exception as e:
            logger.warning("Decompile failed at 0x%x: %s", address, e)
        return ""

    def get_disassembly(self, address: int, max_lines: int = 50) -> str:
        func = self._get_func_at(address)
        if func is None:
            return ""
        lines = []
        try:
            code_iter = self._listing.getCodeUnits(func.getBody(), True)
            count = 0
            while code_iter.hasNext() and count < max_lines:
                cu = code_iter.next()
                lines.append(f"0x{cu.getAddress().getOffset():x}  {cu}")
                count += 1
        except Exception as e:
            logger.warning("Disassembly failed at 0x%x: %s", address, e)
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # XRefs
    # ------------------------------------------------------------------

    def xrefs_to(self, address: int) -> List[XRef]:
        addr = self._to_addr(address)
        ref_manager = self._program.getReferenceManager()
        results = []
        try:
            for ref in ref_manager.getReferencesTo(addr):
                rt = str(ref.getReferenceType())
                kind = "call" if "CALL" in rt else ("data" if "DATA" in rt else "jump")
                results.append(XRef(
                    from_address=ref.getFromAddress().getOffset(),
                    to_address=address,
                    kind=kind,
                ))
        except Exception as e:
            logger.warning("xrefs_to 0x%x failed: %s", address, e)
        return results

    def xrefs_from(self, address: int) -> List[XRef]:
        addr = self._to_addr(address)
        ref_manager = self._program.getReferenceManager()
        results = []
        func = self._listing.getFunctionAt(addr)
        if func is None:
            return results
        try:
            for instr_addr in func.getBody().getAddresses(True):
                for ref in ref_manager.getReferencesFrom(instr_addr):
                    rt = str(ref.getReferenceType())
                    kind = "call" if "CALL" in rt else ("data" if "DATA" in rt else "jump")
                    results.append(XRef(
                        from_address=address,
                        to_address=ref.getToAddress().getOffset(),
                        kind=kind,
                    ))
        except Exception as e:
            logger.warning("xrefs_from 0x%x failed: %s", address, e)
        return results

    # ------------------------------------------------------------------
    # Imports / Exports / Strings
    # ------------------------------------------------------------------

    def list_imports(self) -> List[dict]:
        results = []
        try:
            symbol_table = self._program.getSymbolTable()
            ext_syms = symbol_table.getExternalSymbols()
            while ext_syms.hasNext():
                sym = ext_syms.next()
                ns = sym.getParentNamespace()
                library = ns.getName() if ns and not ns.isGlobal() else ""
                # Find the thunk address (where the import is actually called from)
                refs = list(sym.getReferences())
                addr = refs[0].getFromAddress().getOffset() if refs else 0
                results.append({
                    "name": sym.getName(),
                    "library": library,
                    "address": addr,
                })
        except Exception as e:
            logger.warning("list_imports failed: %s", e)
        return results

    def list_exports(self) -> List[dict]:
        results = []
        try:
            symbol_table = self._program.getSymbolTable()
            for sym in symbol_table.getAllSymbols(True):
                if sym.isExternalEntryPoint():
                    results.append({
                        "name": sym.getName(),
                        "address": sym.getAddress().getOffset(),
                    })
        except Exception as e:
            logger.warning("list_exports failed: %s", e)
        return results

    def list_strings(self) -> List[dict]:
        results = []
        try:
            from ghidra.program.util import DefinedDataIterator
            from ghidra.program.model.data import StringDataType, AbstractStringDataType

            # Walk all defined data looking for string types
            data_iter = self._listing.getDefinedData(True)
            while data_iter.hasNext():
                d = data_iter.next()
                dt = d.getDataType()
                if isinstance(dt, AbstractStringDataType):
                    try:
                        val = d.getValue()
                        if val and len(str(val)) >= 3:
                            results.append({
                                "address": d.getAddress().getOffset(),
                                "value": str(val),
                                "length": d.getLength(),
                            })
                    except Exception:
                        pass
        except Exception as e:
            logger.warning("list_strings failed: %s", e)

        # Fallback: use findStrings with the correct Ghidra 12 signature
        if not results:
            try:
                from ghidra.program.model.address import AddressSet
                addr_set = self._program.getMemory().getLoadedAndInitializedAddressSet()
                found = self._flat_api.findStrings(addr_set, 4, 1, True, True)
                memory = self._program.getMemory()
                for fs in found:
                    try:
                        results.append({
                            "address": fs.getAddress().getOffset(),
                            "value": str(fs.getString(memory)),
                            "length": fs.getLength(),
                        })
                    except Exception:
                        pass
            except Exception as e:
                logger.warning("list_strings fallback failed: %s", e)

        return results

    # ------------------------------------------------------------------
    # Raw memory
    # ------------------------------------------------------------------

    def read_bytes(self, address: int, count: int) -> bytes:
        addr = self._to_addr(address)
        buf = bytearray(count)
        try:
            self._program.getMemory().getBytes(addr, buf)
        except Exception as e:
            logger.warning("read_bytes 0x%x failed: %s", address, e)
        return bytes(buf)

    def write_bytes(self, address: int, data: bytes) -> None:
        addr = self._to_addr(address)
        tx = self._program.startTransaction("write_bytes")
        try:
            self._program.getMemory().setBytes(addr, bytearray(data))
            self._program.endTransaction(tx, True)
        except Exception as e:
            self._program.endTransaction(tx, False)
            raise RuntimeError(f"write_bytes at 0x{address:x} failed: {e}") from e

    # ------------------------------------------------------------------
    # Annotations
    # ------------------------------------------------------------------

    def rename_function(self, address: int, name: str) -> None:
        func = self._get_func_at(address)
        if func is None:
            raise ValueError(f"No function at 0x{address:x}")
        from ghidra.program.model.symbol import SourceType
        tx = self._program.startTransaction("rename_function")
        try:
            func.setName(name, SourceType.USER_DEFINED)
            self._program.endTransaction(tx, True)
        except Exception as e:
            self._program.endTransaction(tx, False)
            raise RuntimeError(f"rename_function at 0x{address:x} failed: {e}") from e

    def set_comment(self, address: int, comment: str) -> None:
        addr = self._to_addr(address)
        tx = self._program.startTransaction("set_comment")
        try:
            from ghidra.program.model.listing import CodeUnit
            cu = self._listing.getCodeUnitAt(addr)
            if cu:
                cu.setComment(CodeUnit.EOL_COMMENT, comment)
            self._program.endTransaction(tx, True)
        except Exception as e:
            self._program.endTransaction(tx, False)
            raise RuntimeError(f"set_comment at 0x{address:x} failed: {e}") from e

    def get_comment(self, address: int) -> str:
        addr = self._to_addr(address)
        try:
            from ghidra.program.model.listing import CodeUnit
            cu = self._listing.getCodeUnitAt(addr)
            if cu:
                return cu.getComment(CodeUnit.EOL_COMMENT) or ""
        except Exception:
            pass
        return ""

    def set_function_prototype(self, address: int, prototype: str) -> None:
        # Phase 1: store as plate comment until full type parsing is implemented
        func = self._get_func_at(address)
        if func is None:
            raise ValueError(f"No function at 0x{address:x}")
        tx = self._program.startTransaction("set_prototype")
        try:
            from ghidra.program.model.listing import CodeUnit
            cu = self._listing.getCodeUnitAt(self._to_addr(address))
            if cu:
                cu.setComment(CodeUnit.PLATE_COMMENT, prototype)
            self._program.endTransaction(tx, True)
        except Exception as e:
            self._program.endTransaction(tx, False)
            raise RuntimeError(f"set_function_prototype at 0x{address:x} failed: {e}") from e

    def get_function_prototype(self, address: int) -> str:
        addr = self._to_addr(address)
        try:
            from ghidra.program.model.listing import CodeUnit
            cu = self._listing.getCodeUnitAt(addr)
            if cu:
                return cu.getComment(CodeUnit.PLATE_COMMENT) or ""
        except Exception:
            pass
        return ""

    # ------------------------------------------------------------------
    # Binary metadata
    # ------------------------------------------------------------------

    def get_entry_point(self) -> int:
        return self._program.getImageBase().getOffset()

    def get_binary_path(self) -> str:
        return self._binary_path

    def get_arch(self) -> str:
        lang = self._program.getLanguage()
        desc = lang.getLanguageDescription()
        return f"{lang.getProcessor()}/{desc.getSize()}-bit/{desc.getEndian()}"

    def get_format(self) -> str:
        return self._program.getExecutableFormat() or "unknown"
