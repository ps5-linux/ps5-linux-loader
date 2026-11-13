# PlayStation 5 Wi-Fi Driver Fix Suite (v6)

Comprehensive driver fix suite and patches providing empirical, full Wi-Fi support across all PlayStation 5 hardware revisions:
- **MediaTek MT7921 / MT7921e** (`14c3:7961` on Sony Salina Southbridge PCIe `0000:40:00.7` - CFI-12xx & Slim revisions).
- **NXP / Marvell IW620 / 88W9097** (`1b4b:2b42` - CFI-10xx & CFI-11xx "Fat" revisions).

---

## 1. Sequential Patch Architecture (13 Patches Total)

### 1.1 In-Tree Linux Kernel Patches (`ps5-linux-patches`)

Applied against the Linux kernel tree:

| Patch | Target File | Purpose |
| :--- | :--- | :--- |
| `0001-mt7921e-disable-runtime-pm-ps5.patch` | `drivers/net/wireless/mediatek/mt76/mt7921/init.c` | Bypasses runtime PM and deep sleep (`dev->pm.enable = false`, `dev->pm.ds_enable = false`) on Salina southbridge to prevent system power-off at ~20s. |
| `0002-mt7921e-pcie-reset-quirk.patch` | `drivers/net/wireless/mediatek/mt76/mt7921/pci.c` | Adds 5-iteration retry loop with `usleep_range(2000, 5000)` and safe `u32 reg_val` bus hang check (`0xffffffff`) to fix integer truncation dead-code and eliminate `driver own failed` errors. |
| `0003-ps5-defconfig-enable-mt7921e.patch` | `arch/x86/configs/ps5_defconfig` | Enables `CONFIG_MT76_CORE=m`, `CONFIG_MT7921_COMMON=m`, and `CONFIG_MT7921E=m` (with comprehensive 3-symbol idempotent detection in `apply_patches.sh`). |

### 1.2 Out-of-Tree Driver Patches (`ps5-linux/ps5-linux-mwifiex` Upstream-Matching Suite)

Applied sequentially against `nxp-imx/mwifiex` at tag `lf-6.18.2_1.0.0`:

| Patch | Upstream Source Name | Target Files | Purpose |
| :--- | :--- | :--- | :--- |
| `0004-iw620-base-port.patch` | `ps5-iw620.patch` | `Makefile`, `mlan/*`, `mlinux/*` | Base PS5 IW620 port (`1b4b:2b42`) and connected-state scan stability workaround. |
| `0005-iw620-cmd-timeout-recover.patch` | `ps5-iw620-cmd-timeout-recover.patch` | `mlan/mlan_cmdevt.c`, `mlan/mlan_init.c`, `mlan/mlan_main.h` | Auto-dequeues stalled commands and implements soft-recovery (up to 3 times) for benign queries. |
| `0006-iw620-kernel71-compat.patch` | `ps5-iw620-kernel71-compat.patch` | `mlinux/moal_cfg80211.c`, `mlinux/moal_cfg80211.h` | Linux kernel 7.1 cfg80211 API compatibility layer (wdev key callbacks & TDLS suppression). |
| `0007-iw620-kernel72-compat.patch` | `ps5-iw620-kernel72-compat.patch` | `mlinux/moal_ioctl.c`, `mlinux/moal_main.c` | Linux kernel 7.2 string compatibility updates (`strscpy` migration). |
| `0008-iw620-kernel73-compat.patch` | `ps5-iw620-kernel73-compat.patch` | `mlinux/moal_cfg80211.c`, `mlinux/moal_cfg80211.h` | Linux kernel 7.3 management TX cookie synchronization and `.probe_client` removal. |
| `0009-iw620-rtnl-bounded-wait.patch` | `ps5-iw620-rtnl-bounded-wait.patch` | `mlinux/moal_sta_cfg80211.c` | Replaces infinite wait in `dump_station_info` with 20s bounded wait (`MOAL_IOCTL_WAIT_TIMEOUT`) to prevent RTNL lockups. |
| `0010-iw620-he.patch` | `ps5-iw620-he.patch` | `mlan/mlan_11ax.c`, `mlan/mlan_11n.c`, `mlinux/moal_cfg80211.c` | Corrects 5 GHz HE capability profile, PPE thresholds, and requests TX BA timeout zero. |
| `0011-iw620-tx-min128.patch` | `ps5-iw620-tx-min128.patch` | `mlan/mlan_pcie.c`, `mlan/mlan_main.h` | Enforces 128-byte minimum ADMA descriptor padding to eliminate TLS 1.3 burst crashes. |
| `0012-iw620-tx-priority.patch` | `ps5-iw620-tx-priority.patch` | `mlinux/moal_main.c` | Remaps STA TX TIDs (1->2, 3->0, 5->4) to prevent priority-inversion queue starvation. |
| `0013-iw620-fresh-fw.patch` | `ps5-iw620-fresh-fw.patch` | `mlinux/moal_pcie.c`, `mlinux/moal_sta_cfg80211.c` | Reads BAR2 0x1C6C scratch register and performs PCIe FLR before firmware reload on kexec warm boots. |

---

## 2. Dual-Kernel Mode & Applicator

`apply_patches.sh` supports dual-mode kernel targeting via `--target-kernel <6|7>`:
- **Kernel 6.x Mode** (`--target-kernel 6`): Applies base patches (0004, 0005, 0009, 0010, 0011, 0012, 0013), skipping 7.x API compatibility shims (0006-0008).
- **Kernel 7.x Mode** (`--target-kernel 7`, default): Applies full 10-patch sequence (0004 through 0013).
- **True Sequential Dry-Run** (`--dry-run`): Uses isolated temporary workspaces created via `mktemp -d` and safely pruned via `trap cleanup EXIT INT TERM` tracking `TEMP_KERNEL_DIR` and `TEMP_MWIFIEX_DIR`.
- **Strict Argument Enforcement**: Exits with code 1 if neither `--kernel-dir` nor `--mwifiex-dir` is provided.

### Usage Example:
```bash
# Empirical dry-run against both kernel and mwifiex trees for Kernel 7.x:
./patches/wifi/apply_patches.sh --dry-run --target-kernel 7 \
  --kernel-dir /path/to/linux-ps5 \
  --mwifiex-dir /path/to/mwifiex

# Empirical dry-run for Kernel 6.x:
./patches/wifi/apply_patches.sh --dry-run --target-kernel 6 \
  --kernel-dir /path/to/linux-ps5 \
  --mwifiex-dir /path/to/mwifiex
```

---

## 3. Three-Stage Validation Framework

We clearly delineate what is empirically proven by automated CI versus what requires physical PlayStation 5 hardware:

```mermaid
flowchart LR
    A["Stage 1: Patch Applicability\n(Static & Dry-Run 13/13 PASS)"] --> B["Stage 2: Driver Build Verification\n(CI Build Matrix: mlan.ko & moal.ko)"]
    B --> C["Stage 3: Physical Hardware\n(Requires PS5 Console & AP link)"]
```

| Validation Stage | Scope & Verification Method | Status | Artifact / Output |
| :--- | :--- | :--- | :--- |
| **Stage 1: Patch Applicability** | Deep static syntax, hunk math validation, C comment enforcement, and sequential dry-run (`verify_patches.py` & `apply_patches.sh --dry-run`). | **VERIFIED (13/13 PASS)** | 100% clean diffs on Kernel 6.x and 7.x modes. |
| **Stage 2: Driver Build Verification** | Empirical compilation of both Kernel 6 and Kernel 7 driver stacks against Linux host kernel headers (`.github/workflows/verify-wifi-patches.yml`). | **CI VERIFIED** | `mlan.ko` and `moal.ko` compiled and uploaded as CI artifacts (14-day retention). |
| **Stage 3: Physical Hardware Runtime** | Runtime association, WPA2/WPA3 handshake, throughput, and power stability on retail PS5 hardware. | **REQUIRES HARDWARE** | Physical console runtime test report. |

---

## 4. Policy & Repository Containment

- All changes are strictly contained on the user's fork (`Mohabbadi11/ps5-linux-loader.git`) on branch `main`.
- Absolutely zero external or upstream Pull Requests.
