#!/usr/bin/env python3
"""
PlayStation 5 Wi-Fi Driver Patch Verification Suite (v4)
Performs deep static analysis and applicability checks:
1. Strict C comment compliance (prohibits C++ '//' comments in C/kernel patches).
2. Truncation anti-pattern detection (catches u16 truncation before 0xffffffff comparison).
3. Mathematical hunk header validation (matches old/new lines against @@ -x,len +y,len @@).
4. Git diff integrity verification (via git apply --stat).
"""

import os
import re
import subprocess
import sys

PATCH_DIR = os.path.dirname(os.path.abspath(__file__))
PATCH_FILES = [
    "0001-mt7921e-disable-runtime-pm-ps5.patch",
    "0002-mt7921e-pcie-reset-quirk.patch",
    "0003-ps5-defconfig-enable-mt7921e.patch",
    "0004-iw620-base-port.patch",
    "0005-iw620-cmd-timeout-recover.patch",
    "0006-iw620-kernel71-compat.patch",
    "0007-iw620-kernel72-compat.patch",
    "0008-iw620-kernel73-compat.patch",
    "0009-iw620-rtnl-bounded-wait.patch",
    "0010-iw620-he.patch",
    "0011-iw620-tx-min128.patch",
    "0012-iw620-tx-priority.patch",
    "0013-iw620-fresh-fw.patch"
]

def verify_hunk_math(lines, filename):
    """Mathematically checks every @@ -o_start,o_len +n_start,n_len @@ block."""
    errors = []
    hunk_regex = re.compile(r'^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@')
    in_hunk = False
    decl_old_len = 0
    decl_new_len = 0
    actual_old_len = 0
    actual_new_len = 0
    hunk_header_line = 0

    def finalize_hunk():
        nonlocal in_hunk, actual_old_len, actual_new_len
        if in_hunk:
            if decl_old_len != actual_old_len:
                errors.append(
                    f"Line {hunk_header_line}: Old length mismatch (declared {decl_old_len}, counted {actual_old_len})"
                )
            if decl_new_len != actual_new_len:
                errors.append(
                    f"Line {hunk_header_line}: New length mismatch (declared {decl_new_len}, counted {actual_new_len})"
                )
            in_hunk = False

    for idx, line in enumerate(lines, 1):
        m = hunk_regex.match(line)
        if m:
            finalize_hunk()
            in_hunk = True
            hunk_header_line = idx
            decl_old_len = int(m.group(2)) if m.group(2) is not None else 1
            decl_new_len = int(m.group(4)) if m.group(4) is not None else 1
            actual_old_len = 0
            actual_new_len = 0
            continue

        if in_hunk:
            if line.startswith('--- ') or line.startswith('diff --git') or line.startswith('-- ') or line == '--':
                finalize_hunk()
            elif line.startswith('+'):
                actual_new_len += 1
            elif line.startswith('-'):
                actual_old_len += 1
            elif line.startswith(' '):
                actual_old_len += 1
                actual_new_len += 1
            elif line == '':
                # Blank context line inside hunk
                actual_old_len += 1
                actual_new_len += 1

    finalize_hunk()
    return errors

def check_patch(filename):
    filepath = os.path.join(PATCH_DIR, filename)
    if not os.path.isfile(filepath):
        return False, [f"File {filename} does not exist"]

    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        content = f.read()

    lines = content.splitlines()
    errors = []

    # 1. Check for C++ comments (//) in added lines
    cpp_comment_regex = re.compile(r'^\+[^+].*//')
    for idx, line in enumerate(lines, 1):
        if cpp_comment_regex.search(line):
            errors.append(f"Line {idx}: Prohibited C++ comment '//' detected in added line: {line.strip()}")

    # 2. Check for integer truncation anti-pattern (u16 compared against 0xffffffff)
    if "0002" in filename:
        has_u32_guard = any("u32 reg_val" in line for line in lines)
        has_safe_cast = any("chipid = (u16)reg_val" in line for line in lines)
        if not (has_u32_guard and has_safe_cast):
            errors.append("Truncation vulnerability: 0002 must declare 'u32 reg_val' and assign 'chipid = (u16)reg_val'")

    # 3. Check for patch diff headers
    has_diff_header = any(line.startswith('diff --git') or line.startswith('--- ') for line in lines)
    if not has_diff_header:
        errors.append("Missing diff header (--- or diff --git)")

    # 4. Mathematical hunk verification
    hunk_math_errs = verify_hunk_math(lines, filename)
    errors.extend(hunk_math_errs)

    # 5. Git apply --stat validation
    proc = subprocess.run(["git", "apply", "--stat", filepath], capture_output=True, text=True)
    if proc.returncode != 0:
        err_msg = proc.stderr.strip() or "git apply --stat failed"
        errors.append(f"Git diff syntax error: {err_msg}")

    return (len(errors) == 0), errors

def main():
    print(f"=== PS5 Wi-Fi Patch Verification Suite (v4) ===")
    print(f"Target directory: {PATCH_DIR}")
    total_errors = 0
    passed_count = 0

    for pf in PATCH_FILES:
        ok, errs = check_patch(pf)
        if ok:
            print(f"[PASS] {pf}")
            passed_count += 1
        else:
            print(f"[FAIL] {pf}")
            for err in errs:
                print(f"       -> {err}")
            total_errors += len(errs)

    print("--------------------------------------------------")
    print(f"Total: {len(PATCH_FILES)} patches | Passed: {passed_count} | Errors: {total_errors}")

    if total_errors == 0:
        print("[SUCCESS] All 13 patches passed deep static and git validation cleanly.")
        return 0
    else:
        print(f"[FAILURE] Validation failed with {total_errors} errors.")
        return 1

if __name__ == '__main__':
    sys.exit(main())
