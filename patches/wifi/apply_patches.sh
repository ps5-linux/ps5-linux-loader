#!/usr/bin/env bash
# ==============================================================================
# PlayStation 5 Wi-Fi Driver Patch Applicator (v5)
# Applies in-tree MT7921e patches (0001-0003) and out-of-tree IW620 patches (0004-0013)
# Supports dual-mode target kernel selection (Kernel 6.x vs Kernel 7.x)
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DRY_RUN=0
KERNEL_DIR=""
MWIFIEX_DIR=""
TARGET_KERNEL="7"
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
    echo "  --kernel-dir <dir>       Path to Linux kernel tree"
    echo "  --mwifiex-dir <dir>      Path to ps5-linux-mwifiex source tree"
    echo "  --target-kernel <6|7>    Target kernel generation (default: 7)"
    echo "  --dry-run                Perform true sequential dry-run in isolated temporary workspace"
    echo "  -h, --help               Show this help message"
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
        --target-kernel)
            TARGET_KERNEL="$2"
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

echo "=== PlayStation 5 Wi-Fi Driver Patch Applicator (v5) ==="
echo "Suite directory: ${SCRIPT_DIR}"
echo "Target kernel generation: ${TARGET_KERNEL}"

KERNEL_PATCHES=(
    "0001-mt7921e-disable-runtime-pm-ps5.patch"
    "0002-mt7921e-pcie-reset-quirk.patch"
    "0003-ps5-defconfig-enable-mt7921e.patch"
)

if [[ "${TARGET_KERNEL}" =~ ^6 ]]; then
    echo "Configuring IW620 patch chain for Kernel 6.x (skipping 7.x shims)..."
    MWIFIEX_PATCHES=(
        "0004-iw620-base-port.patch"
        "0005-iw620-cmd-timeout-recover.patch"
        "0009-iw620-rtnl-bounded-wait.patch"
        "0010-iw620-he.patch"
        "0011-iw620-tx-min128.patch"
        "0012-iw620-tx-priority.patch"
        "0013-iw620-fresh-fw.patch"
    )
else
    echo "Configuring IW620 patch chain for Kernel 7.x (full 10-patch upstream suite)..."
    MWIFIEX_PATCHES=(
        "0004-iw620-base-port.patch"
        "0005-iw620-cmd-timeout-recover.patch"
        "0006-iw620-kernel71-compat.patch"
        "0007-iw620-kernel72-compat.patch"
        "0008-iw620-kernel73-compat.patch"
        "0009-iw620-rtnl-bounded-wait.patch"
        "0010-iw620-he.patch"
        "0011-iw620-tx-min128.patch"
        "0012-iw620-tx-priority.patch"
        "0013-iw620-fresh-fw.patch"
    )
fi

apply_sequential_chain() {
    local target_type="$1"
    local base_dir="$2"
    local patches=("${@:3}")
    local work_dir="${base_dir}"

    if [[ ${DRY_RUN} -eq 1 ]]; then
        local temp_dir
        temp_dir="$(mktemp -d)"
        if [[ "${target_type}" == "kernel" ]]; then
            TEMP_KERNEL_DIR="${temp_dir}"
        else
            TEMP_MWIFIEX_DIR="${temp_dir}"
        fi
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

        # Idempotent defconfig check for all 3 MT7921 symbols
        if [[ "${patch_name}" == "0003-ps5-defconfig-enable-mt7921e.patch" ]]; then
            local cfg_file=""
            if [[ -f "${work_dir}/arch/x86/configs/ps5_defconfig" ]]; then
                cfg_file="${work_dir}/arch/x86/configs/ps5_defconfig"
            elif [[ -f "${work_dir}/.config" ]]; then
                cfg_file="${work_dir}/.config"
            fi
            if [[ -n "${cfg_file}" ]] && \
               grep -q "^CONFIG_MT76_CORE=m" "${cfg_file}" && \
               grep -q "^CONFIG_MT7921_COMMON=m" "${cfg_file}" && \
               grep -q "^CONFIG_MT7921E=m" "${cfg_file}"; then
                echo "    [INFO] Already enabled: ${patch_name} (MT76_CORE, MT7921_COMMON, and MT7921E present in ${cfg_file##*/})"
                continue
            fi
        fi

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
        if [[ "${target_type}" == "kernel" ]]; then
            TEMP_KERNEL_DIR=""
        else
            TEMP_MWIFIEX_DIR=""
        fi
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
    apply_sequential_chain "kernel" "${KERNEL_DIR}" "${KERNEL_PATCHES[@]}"
fi

# 2. Process MWIFIEX Patches
if [[ -n "${MWIFIEX_DIR}" ]]; then
    if [[ ! -d "${MWIFIEX_DIR}" ]]; then
        echo "ERROR: MWIFIEX directory does not exist: ${MWIFIEX_DIR}" >&2
        exit 1
    fi
    echo "--- [Out-of-Tree IW620] Patch Sequence (Target Kernel ${TARGET_KERNEL}) ---"
    apply_sequential_chain "mwifiex" "${MWIFIEX_DIR}" "${MWIFIEX_PATCHES[@]}"
fi

echo "=== All patch operations completed successfully. ==="
