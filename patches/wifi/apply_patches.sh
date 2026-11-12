#!/bin/bash
# ==============================================================================
# PlayStation 5 Wi-Fi Driver Patch Applicator
# Applies kernel patches (0001-0003) and out-of-tree IW620 patches (0004-0008)
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== PlayStation 5 Wi-Fi Driver Fix Suite ==="
echo "Patch directory: ${SCRIPT_DIR}"

apply_patch() {
    local target_dir="$1"
    local patch_file="$2"
    local desc="$3"

    echo "--> [${desc}] Applying $(basename "${patch_file}") to ${target_dir}..."
    if [ ! -d "${target_dir}" ]; then
        echo "    Target directory ${target_dir} not found. Skipping."
        return 0
    fi

    if git -C "${target_dir}" apply --check "${patch_file}" >/dev/null 2>&1; then
        git -C "${target_dir}" apply "${patch_file}"
        echo "    Applied successfully."
    elif git -C "${target_dir}" apply -R --check "${patch_file}" >/dev/null 2>&1; then
        echo "    Patch is already applied."
    else
        echo "    ERROR: Patch failed to apply cleanly to ${target_dir}."
        exit 1
    fi
}

# 1. Linux Kernel Patches (MT7921 + ps5_defconfig)
KERNEL_DIR="${1:-/usr/src/linux}"
if [ -d "${KERNEL_DIR}" ]; then
    echo "--- Patching Kernel Source Tree: ${KERNEL_DIR} ---"
    apply_patch "${KERNEL_DIR}" "${SCRIPT_DIR}/0001-mt7921e-disable-runtime-pm-ps5.patch" "MT7921 Runtime PM Guard"
    apply_patch "${KERNEL_DIR}" "${SCRIPT_DIR}/0002-mt7921e-pcie-reset-quirk.patch" "MT7921 PCIe Reset Quirk"
    apply_patch "${KERNEL_DIR}" "${SCRIPT_DIR}/0003-ps5-defconfig-enable-mt7921e.patch" "PS5 Defconfig Enablement"
else
    echo "Note: Kernel source directory '${KERNEL_DIR}' not provided or does not exist."
fi

# 2. IW620 Out-of-tree Driver Patches (ps5-linux-mwifiex)
MWIFIEX_DIR="${2:-/usr/src/ps5-linux-mwifiex}"
if [ -d "${MWIFIEX_DIR}" ]; then
    echo "--- Patching IW620 mwifiex Tree: ${MWIFIEX_DIR} ---"
    apply_patch "${MWIFIEX_DIR}" "${SCRIPT_DIR}/0004-iw620-rtnl-bounded-wait.patch" "IW620 RTNL Bounded Wait"
    apply_patch "${MWIFIEX_DIR}" "${SCRIPT_DIR}/0005-iw620-cmd-timeout-recovery.patch" "IW620 Command Timeout Soft Recovery"
    apply_patch "${MWIFIEX_DIR}" "${SCRIPT_DIR}/0006-iw620-adma-tx-min128.patch" "IW620 ADMA TX Min-128 Padding"
    apply_patch "${MWIFIEX_DIR}" "${SCRIPT_DIR}/0007-iw620-kexec-scratch-flr.patch" "IW620 Kexec Scratch FLR"
    apply_patch "${MWIFIEX_DIR}" "${SCRIPT_DIR}/0008-iw620-strip-tdls.patch" "IW620 Strip TDLS Flags"
else
    echo "Note: MWIFIEX directory '${MWIFIEX_DIR}' not provided or does not exist."
fi

echo "=== All patch checks completed ==="
