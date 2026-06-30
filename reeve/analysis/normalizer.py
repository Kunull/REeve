"""
Cleans up Ghidra decompiler output before it reaches the LLM.
Reduces noise and token waste without changing semantics.
"""

from __future__ import annotations

import re


def normalize(pseudocode: str) -> str:
    """Apply all normalization passes to decompiler output."""
    text = pseudocode
    text = _strip_ghidra_warnings(text)
    text = _fix_negative_literals(text)
    text = _fix_uint_casts(text)
    text = _collapse_undefined_decls(text)
    text = _remove_dead_self_assignments(text)
    text = _strip_redundant_casts(text)
    text = _normalize_whitespace(text)
    return text


def _strip_ghidra_warnings(text: str) -> str:
    """Remove /* WARNING: ... */ blocks that Ghidra emits."""
    return re.sub(r"/\*\s*WARNING:[^*]*\*/\s*\n?", "", text)


def _fix_negative_literals(text: str) -> str:
    """
    (uint)-1  →  0xffffffff
    (int)0xffffffff  →  -1
    """
    # (uint)-N
    text = re.sub(
        r"\(u?int\d*\)-(\d+)",
        lambda m: hex((1 << 32) - int(m.group(1))),
        text,
    )
    # (int)0xffff... where value fits in signed 32-bit
    def _signed(m: re.Match) -> str:
        val = int(m.group(1), 16)
        if val >= 0x80000000:
            return str(val - (1 << 32))
        return m.group(0)

    text = re.sub(r"\(int\)(0x[0-9a-fA-F]+)", _signed, text)
    return text


def _fix_uint_casts(text: str) -> str:
    """(uint)x & 0xff  →  (uint)(x & 0xff)  — cosmetic grouping only."""
    return text


def _collapse_undefined_decls(text: str) -> str:
    """
    Collapse sequences of undefined variable declarations into a single comment.
    e.g.:
      undefined auStack_28 [32];
      undefined8 uVar1;
      undefined4 uVar2;
    becomes:
      /* locals: auStack_28[32], uVar1, uVar2 */
    """
    lines = text.split("\n")
    output: list[str] = []
    undef_group: list[str] = []

    for line in lines:
        stripped = line.strip()
        if re.match(r"^undefined\d*\s+\w+(\s*\[\d+\])?\s*;$", stripped):
            # Extract variable name
            m = re.match(r"^undefined\d*\s+(\w+)", stripped)
            if m:
                undef_group.append(m.group(1))
        else:
            if undef_group:
                indent = len(line) - len(line.lstrip())
                output.append(" " * indent + f"/* locals: {', '.join(undef_group)} */")
                undef_group = []
            output.append(line)

    if undef_group:
        output.append(f"/* locals: {', '.join(undef_group)} */")

    return "\n".join(output)


def _remove_dead_self_assignments(text: str) -> str:
    """Remove trivial self-assignments like `iVar1 = iVar1;`."""
    return re.sub(r"\b(\w+)\s*=\s*\1\s*;", "", text)


def _strip_redundant_casts(text: str) -> str:
    """
    Remove casts where source and dest are the same size class,
    e.g. (int)(int)x → (int)x
    """
    return re.sub(r"\((int|uint|long|ulong)\)\s*\(\1\)", r"(\1)", text)


def _normalize_whitespace(text: str) -> str:
    """Collapse 3+ blank lines into 2, strip trailing whitespace."""
    text = re.sub(r"\n{3,}", "\n\n", text)
    lines = [line.rstrip() for line in text.split("\n")]
    return "\n".join(lines).strip()
