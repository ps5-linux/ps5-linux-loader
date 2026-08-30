#!/usr/bin/env python3
"""Reject ELF properties that make extracted flat shellcode non-relocatable."""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path


SAFE_RELOCATIONS = {
    "R_X86_64_PC32",
    "R_X86_64_PLT32",
    "R_X86_64_GOTPCREL",
    "R_X86_64_GOTPCRELX",
    "R_X86_64_REX_GOTPCRELX",
}


def find_readelf() -> str:
    for name in ("x86_64-elf-readelf", "llvm-readelf", "readelf"):
        path = shutil.which(name)
        if path:
            return path
    raise RuntimeError("readelf was not found")


def inspect(readelf: str, path: Path) -> tuple[str | None, set[str]]:
    header = subprocess.run(
        [readelf, "-hW", str(path)], check=True, capture_output=True, text=True
    ).stdout
    relocations = subprocess.run(
        [readelf, "-rW", str(path)], check=True, capture_output=True, text=True
    ).stdout
    kind_match = re.search(r"^\s*Type:\s+(\S+)", header, re.MULTILINE)
    kinds = set(re.findall(r"\bR_X86_64_[A-Z0-9_]+\b", relocations))
    return (kind_match.group(1) if kind_match else None, kinds)


def main() -> int:
    if len(sys.argv) < 2:
        print(f"usage: {Path(sys.argv[0]).name} ELF...", file=sys.stderr)
        return 2

    try:
        readelf = find_readelf()
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    failed = False
    for value in sys.argv[1:]:
        path = Path(value)
        kind, relocations = inspect(readelf, path)
        if path.suffix == ".elf":
            if kind != "DYN" or relocations:
                print(
                    f"error: {path} type={kind} runtime_relocations="
                    f"{','.join(sorted(relocations)) or 'none'}"
                )
                failed = True
        else:
            unsafe = relocations - SAFE_RELOCATIONS
            if unsafe:
                print(
                    f"error: {path} unsafe relocations: "
                    f"{','.join(sorted(unsafe))}"
                )
                failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
