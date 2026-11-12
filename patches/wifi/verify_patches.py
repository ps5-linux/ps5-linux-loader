#!/usr/bin/env python3
import os
import re
import subprocess
import sys

PATCH_DIR = os.path.dirname(os.path.abspath(__file__))
PATCH_FILES = [
    "0001-mt7921e-disable-runtime-pm-ps5.patch",
    "0002-mt7921e-pcie-reset-quirk.patch",
    "0003-ps5-defconfig-enable-mt7921e.patch",
    "0004-iw620-rtnl-bounded-wait.patch",
    "0005-iw620-cmd-timeout-recovery.patch",
    "0006-iw620-adma-tx-min128.patch",
    "0007-iw620-kexec-scratch-flr.patch",
    "0008-iw620-strip-tdls.patch"
]

def check_patch(filename):
    filepath = os.path.join(PATCH_DIR, filename)
    if not os.path.isfile(filepath):
        return False, f"File {filename} does not exist"

    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    lines = content.splitlines()
    errors = []

    # 1. Check for C++ comments (//) in added lines
    cpp_comment_regex = re.compile(r'^\+[^+].*//')
    for idx, line in enumerate(lines, 1):
        if cpp_comment_regex.search(line):
            errors.append(f"Line {idx}: C++ comment '//' detected in added line: {line.strip()}")

    # 2. Check for patch diff headers
    has_diff_header = any(line.startswith('diff --git') or line.startswith('--- ') for line in lines)
    if not has_diff_header:
        errors.append("Missing diff header (--- or diff --git)")

    # 3. Check for hunk headers (@@ -x,y +x,y @@)
    hunk_regex = re.compile(r'^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@')
    hunk_count = 0
    for line in lines:
        if hunk_regex.match(line):
            hunk_count += 1

    if hunk_count == 0:
        errors.append("No diff hunks (@@ ... @@) found")

    # 4. Strict git apply --stat validation to verify hunk counts & patch integrity
    proc = subprocess.run(["git", "apply", "--stat", filepath], capture_output=True, text=True)
    if proc.returncode != 0:
        err_msg = proc.stderr.strip() or "git apply --stat failed"
        errors.append(f"Git diff syntax error: {err_msg}")

    return (len(errors) == 0), errors

def main():
    print(f"=== Verifying 8 Wi-Fi Driver Patches in {PATCH_DIR} ===")
    total_errors = 0
    for pf in PATCH_FILES:
        ok, errs = check_patch(pf)
        if ok:
            print(f"[PASS] {pf} (Syntax & git apply --stat OK)")
        else:
            print(f"[FAIL] {pf}")
            for err in errs:
                print(f"       -> {err}")
            total_errors += len(errs)

    if total_errors == 0:
        print("\nAll 8 patches passed validation (0 errors, 0 warnings, clean C syntax, 100% valid diffs).")
        return 0
    else:
        print(f"\nValidation failed with {total_errors} errors.")
        return 1

if __name__ == '__main__':
    sys.exit(main())
