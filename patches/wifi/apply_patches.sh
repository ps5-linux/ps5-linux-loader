#!/usr/bin/env bash
# ==============================================================================
# PlayStation 5 Wi-Fi Driver Patch Applicator (v2)
# Applies in-tree MT7921e patches (0001-0003) and out-of-tree IW620 patches (0004-0012)
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DRY_RUN=0
KERNEL_DIR=""
MWIFIEX_DIR=""

usage() {
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  --kernel-dir <dir>   Path to Linux kernel tree"
    echo "  --mwifiex-dir <dir>  Path to ps5-linux-mwifiex source tree"
    echo "  --dry-run            Check patch applicability without modifying files"
    echo "  -h, --help           Show this help message"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --kernel-dir)
            KERNEL_DIR="$2"
            shift 2
            ;;
        --mwifiex-dir)
            MWIFIEX_DIR="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "ERROR: Unknown argument: $1" >&2
            usage
            ;;
    esac
done

echo "=== PlayStation 5 Wi-Fi Driver Patch Applicator ==="
echo "Patch suite directory: ${SCRIPT_DIR}"
if [[ ${DRY_RUN} -eq 1 ]]; then
    echo "Mode: DRY-RUN (verification only, no files modified)"
else
    echo "Mode: APPLY"
fi

apply_patch() {
    local target_dir="$1"
    local patch_file="$2"
    local desc="$3"

    if [[ ! -f "${patch_file}" ]]; then
        echo "ERROR: Patch file missing: ${patch_file}" >&2
        exit 1
    fi

    echo "--> [${desc}] Checking $(basename "${patch_file}") against ${target_dir}..."

    if git -C "${target_dir}" apply --check "${patch_file}" >/dev/null 2>&1; then
        if [[ ${DRY_RUN} -eq 1 ]]; then
            echo "    [PASS] Patch applies cleanly (dry-run)."
        else
            git -C "${target_dir}" apply "${patch_file}"
            echo "    [APPLIED] Patch successfully applied."
        fi
    elif git -C "${target_dir}" apply -R --check "${patch_file}" >/dev/null 2>&1; then
        echo "    [INFO] Patch is already applied."
    else
        echo "    [FAIL] ERROR: Patch $(basename "${patch_file}") does not apply cleanly to ${target_dir}!" >&2
        exit 1
    fi
}

# 1. Linux Kernel Patches (0001 - 0003)
if [[ -n "${KERNEL_DIR}" ]]; then
    if [[ ! -d "${KERNEL_DIR}" ]]; then
        echo "ERROR: Kernel directory does not exist: ${KERNEL_DIR}" >&2
        exit 1
    fi
    echo "--- Validating Kernel Patches in ${KERNEL_DIR} ---"
    apply_patch "${KERNEL_DIR}" "${SCRIPT_DIR}/0001-mt7921e-disable-runtime-pm-ps5.patch" "MT7921 Runtime PM Guard"
    apply_patch "${KERNEL_DIR}" "${SCRIPT_DIR}/0002-mt7921e-pcie-reset-quirk.patch" "MT7921 PCIe Reset Quirk"
    apply_patch "${KERNEL_DIR}" "${SCRIPT_DIR}/0003-ps5-defconfig-enable-mt7921e.patch" "PS5 Defconfig MT7921 Enablement"
else
    echo "Note: --kernel-dir not specified; skipping kernel patch application."
fi

# 2. IW620 Out-of-tree Driver Patches (0004 - 0012)
if [[ -n "${MWIFIEX_DIR}" ]]; then
    if [[ ! -d "${MWIFIEX_DIR}" ]]; then
        echo "ERROR: MWIFIEX directory does not exist: ${MWIFIEX_DIR}" >&2
        exit 1
    fi
    echo "--- Validating IW620 mwifiex Patches in ${MWIFIEX_DIR} ---"
    apply_patch "${MWIFIEX_DIR}" "${SCRIPT_DIR}/0004-iw620-base-port.patch" "IW620 Base Port & Scan Stability"
    apply_patch "${MWIFIEX_DIR}" "${SCRIPT_DIR}/0005-iw620-cmd-timeout-recovery.patch" "IW620 Command Timeout Soft Recovery"
    apply_patch "${MWIFIEX_DIR}" "${SCRIPT_DIR}/0006-iw620-kernel-compat.patch" "IW620 Kernel 6.x/7.x API Compat"
    apply_patch "${MWIFIEX_DIR}" "${SCRIPT_DIR}/0007-iw620-rtnl-bounded-wait.patch" "IW620 RTNL Bounded Wait"
    apply_patch "${MWIFIEX_DIR}" "${SCRIPT_DIR}/0008-iw620-he-ppe-fix.patch" "IW620 5GHz HE PPE Profile"
    apply_patch "${MWIFIEX_DIR}" "${SCRIPT_DIR}/0009-iw620-adma-tx-min128.patch" "IW620 128-byte ADMA Padding"
    apply_patch "${MWIFIEX_DIR}" "${SCRIPT_DIR}/0010-iw620-tx-priority-wmm.patch" "IW620 TX QoS TID Priority Remap"
    apply_patch "${MWIFIEX_DIR}" "${SCRIPT_DIR}/0011-iw620-kexec-scratch-flr.patch" "IW620 Kexec Scratch Check & FLR"
    apply_patch "${MWIFIEX_DIR}" "${SCRIPT_DIR}/0012-iw620-strip-tdls.patch" "IW620 Strip TDLS Flags"
else
    echo "Note: --mwifiex-dir not specified; skipping mwifiex patch application."
fi

echo "=== Operation completed successfully. ==="
