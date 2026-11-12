# PlayStation 5 Wi-Fi Driver Fix Suite (v3)

Comprehensive driver fix suite and patches providing full Wi-Fi support across all PlayStation 5 hardware revisions:
- **MediaTek MT7921 / MT7921e** (`14c3:7961` on Sony Salina Southbridge PCIe `0000:40:00.7` - CFI-12xx & Slim revisions).
- **NXP / Marvell IW620 / 88W9097** (`1b4b:2b42` - CFI-10xx & CFI-11xx "Fat" revisions).

---

## 1. Sequential Patch Architecture

### 1.1 In-Tree Linux Kernel Patches (`ps5-linux-patches`)

Applied against the Linux kernel tree:

| Patch | Target File | Purpose |
| :--- | :--- | :--- |
| `0001-mt7921e-disable-runtime-pm-ps5.patch` | `drivers/net/wireless/mediatek/mt76/mt7921/init.c` | Bypasses runtime PM and deep sleep (`dev->pm.enable = false`, `dev->pm.ds_enable = false`) on Salina southbridge to prevent system power-off at ~20s. |
| `0002-mt7921e-pcie-reset-quirk.patch` | `drivers/net/wireless/mediatek/mt76/mt7921/pci.c` | Adds 5-iteration retry loop with `usleep_range(2000, 5000)` and safe `u32 reg_val` bus hang check (`0xffffffff`) to fix integer truncation dead-code and eliminate `driver own failed` errors. |
| `0003-ps5-defconfig-enable-mt7921e.patch` | `arch/x86/configs/ps5_defconfig` | Enables `CONFIG_MT76_CORE=m`, `CONFIG_MT7921_COMMON=m`, and `CONFIG_MT7921E=m`. |

### 1.2 Out-of-Tree Driver Patches (`ps5-linux-mwifiex`)

Applied sequentially against `nxp-imx/mwifiex` at tag `lf-6.18.2_1.0.0`:

| Patch | Target Files | Purpose |
| :--- | :--- | :--- |
| `0004-iw620-base-port.patch` | `Makefile`, `mlan/*`, `mlinux/*` | Base PS5 IW620 port (`1b4b:2b42`) and connected-state scan stability workaround. |
| `0005-iw620-cmd-timeout-recovery.patch` | `mlan/mlan_cmdevt.c`, `mlan/mlan_init.c`, `mlan/mlan_main.h` | Auto-dequeues stalled commands and implements soft-recovery (up to 3 times) for benign queries. |
| `0006-iw620-kernel-compat.patch` | `mlinux/moal_cfg80211.c`, `mlinux/moal_cfg80211.h` | Linux kernel 6.x vs 7.1/7.2/7.3 cfg80211 API compatibility layer (conditionally wrapping `wdev` vs `netdev`). |
| `0007-iw620-rtnl-bounded-wait.patch` | `mlinux/moal_sta_cfg80211.c` | Replaces infinite wait in `dump_station_info` with 20s bounded wait (`MOAL_IOCTL_WAIT_TIMEOUT`) to prevent RTNL lockups. |
| `0008-iw620-he-ppe-fix.patch` | `mlan/mlan_11ax.c`, `mlinux/moal_sta_cfg80211.c` | Corrects 5 GHz HE capability profile and PPE thresholds; requests TX BA timeout zero. |
| `0009-iw620-adma-tx-min128.patch` | `mlan/mlan_pcie.c`, `mlan/mlan_main.h` | Enforces 128-byte minimum ADMA descriptor padding to eliminate TLS 1.3 burst crashes. |
| `0010-iw620-tx-priority-wmm.patch` | `mlinux/moal_main.c` | Remaps STA TX TIDs (1->2, 3->0, 5->4) to prevent priority-inversion queue starvation. |
| `0011-iw620-kexec-scratch-flr.patch` | `mlinux/moal_pcie.c`, `mlinux/moal_sta_cfg80211.c` | Reads BAR2 0x1C6C scratch register and performs PCIe FLR before firmware reload on kexec warm boots. |
| `0012-iw620-strip-tdls.patch` | `mlinux/moal_sta_cfg80211.c` | Strips `WIPHY_FLAG_SUPPORTS_TDLS` to prevent unhandled TDLS 0x122 firmware panics. |

---

## 2. Tools & Verification

- `verify_patches.py`: Deep static validator testing:
  - C++ comment prohibition.
  - Truncation anti-pattern detection (`u32 reg_val` vs `0xffffffff`).
  - Mathematical hunk line count verification.
  - Full `git apply --stat` applicability verification.
- `apply_patches.sh`: Safe patch application script with true sequential dry-run in isolated temporary workspaces (`--dry-run`, `--kernel-dir`, and `--mwifiex-dir` flags).
- `ps5-wifi.conf`: System module options for `/etc/modprobe.d/ps5-wifi.conf`.

---

## 3. Policy & Repository Containment

- All changes are strictly contained on the user's fork (`Mohabbadi11/ps5-linux-loader.git`) on branch `main`.
- Absolutely zero external or upstream Pull Requests.
