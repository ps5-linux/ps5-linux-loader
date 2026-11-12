#!/usr/bin/env bash
# ==============================================================================
# PlayStation 5 Wi-Fi Driver Patch Applicator (v3)
# Applies in-tree MT7921e patches (0001-0003) and out-of-tree IW620 patches (0004-0012)
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DRY_RUN=0
KERNEL_DIR=""
MWIFIEX_DIR=""
TEMP_KERNEL_DIR=""
TEMP_MWIFIEX_DIR=""

cleanup() {
    if [[ -n "${TEMP_KERNEL_DIR:-}" && -d "${TEMP_KERNEL_DIR}" ]]; then
        rm -rf "${TEMP_KERNEL_DIR}"
    fi
    if [[ -n "${TEMP_MWIFIEX_DIR:-}" && -d "${TEMP_MWIFIEX_DIR}" ]]; then
        rm -rf "${TEMP_MWIFIEX_DIR}"
    fi
}
trap cleanup EXIT INT TERM

usage() {
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  --kernel-dir <dir>   Path to Linux kernel tree"
    echo "  --mwifiex-dir <dir>  Path to ps5-linux-mwifiex source tree"
    echo "  --dry-run            Perform true sequential dry-run in isolated temporary workspace"
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

if [[ -z "${KERNEL_DIR}" && -z "${MWIFIEX_DIR}" ]]; then
    echo "ERROR: At least one of --kernel-dir or --mwifiex-dir must be specified." >&2
    usage
fi

echo "=== PlayStation 5 Wi-Fi Driver Patch Applicator (v3) ==="
echo "Suite directory: ${SCRIPT_DIR}"

KERNEL_PATCHES=(
    "0001-mt7921e-disable-runtime-pm-ps5.patch"
    "0002-mt7921e-pcie-reset-quirk.patch"
    "0003-ps5-defconfig-enable-mt7921e.patch"
)

MWIFIEX_PATCHES=(
    "0004-iw620-base-port.patch"
    "0005-iw620-cmd-timeout-recovery.patch"
    "0006-iw620-kernel-compat.patch"
    "0007-iw620-rtnl-bounded-wait.patch"
    "0008-iw620-he-ppe-fix.patch"
    "0009-iw620-adma-tx-min128.patch"
    "0010-iw620-tx-priority-wmm.patch"
    "0011-iw620-kexec-scratch-flr.patch"
    "0012-iw620-strip-tdls.patch"
)

apply_sequential_chain() {
    local base_dir="$1"
    local patches=("${@:2}")
    local work_dir="${base_dir}"

    if [[ ${DRY_RUN} -eq 1 ]]; then
        local temp_dir
        temp_dir="$(mktemp -d)"
        echo "--> [DRY-RUN] Creating temporary workspace at ${temp_dir}..."
        cp -a "${base_dir}/." "${temp_dir}/"
        work_dir="${temp_dir}"
    fi

    echo "--> Processing patch chain in: ${work_dir}..."
    for patch_name in "${patches[@]}"; do
        local patch_file="${SCRIPT_DIR}/${patch_name}"
        if [[ ! -f "${patch_file}" ]]; then
            echo "ERROR: Missing patch file: ${patch_file}" >&2
            exit 1
        fi

        echo "    Applying ${patch_name}..."
        if git -C "${work_dir}" apply --ignore-whitespace --whitespace=nowarn "${patch_file}"; then
            echo "    [PASS] Applied: ${patch_name}"
        elif git -C "${work_dir}" apply -R --check --ignore-whitespace "${patch_file}" >/dev/null 2>&1; then
            echo "    [INFO] Already applied: ${patch_name}"
        else
            echo "ERROR: Failed to apply ${patch_name} cleanly onto sequential tree!" >&2
            exit 1
        fi
    done

    if [[ ${DRY_RUN} -eq 1 ]]; then
        rm -rf "${work_dir}"
        echo "--> [DRY-RUN] Sequential chain verification succeeded!"
    fi
}

# 1. Process Kernel Patches
if [[ -n "${KERNEL_DIR}" ]]; then
    if [[ ! -d "${KERNEL_DIR}" ]]; then
        echo "ERROR: Kernel directory does not exist: ${KERNEL_DIR}" >&2
        exit 1
    fi
    echo "--- [Kernel MT7921e] Patch Sequence (0001 - 0003) ---"
    apply_sequential_chain "${KERNEL_DIR}" "${KERNEL_PATCHES[@]}"
fi

# 2. Process MWIFIEX Patches
if [[ -n "${MWIFIEX_DIR}" ]]; then
    if [[ ! -d "${MWIFIEX_DIR}" ]]; then
        echo "ERROR: MWIFIEX directory does not exist: ${MWIFIEX_DIR}" >&2
        exit 1
    fi
    echo "--- [Out-of-Tree IW620] Patch Sequence (0004 - 0012) ---"
    apply_sequential_chain "${MWIFIEX_DIR}" "${MWIFIEX_PATCHES[@]}"
fi

echo "=== All patch operations completed successfully. ==="
