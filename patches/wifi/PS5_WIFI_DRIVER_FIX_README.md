# PlayStation 5 Wi-Fi Driver Fix Suite

Comprehensive fix suite and patches for Wi-Fi support across all Sony PlayStation 5 revisions:
- **MediaTek MT7921 / MT7921e** (`14c3:7961` on Salina Southbridge bus `40:00.7` - CFI-12xx & Slim revisions).
- **NXP / Marvell IW620 / 88W9097** (`1b4b:2b42` - CFI-10xx & CFI-11xx "Fat" revisions).

---

## 1. Patches Overview

| Patch File | Subsystem / File | Purpose |
| :--- | :--- | :--- |
| `0001-mt7921e-disable-runtime-pm-ps5.patch` | `drivers/net/wireless/mediatek/mt76/mt7921/init.c` | Bypasses runtime PM and deep sleep (`dev->pm.enable = false`) on Salina southbridge to prevent system power-off at ~20s. |
| `0002-mt7921e-pcie-reset-quirk.patch` | `drivers/net/wireless/mediatek/mt76/mt7921/pci.c` | Adds 5-iteration retry loop with `usleep_range(2000, 5000)` and 0xffffffff bus check to eliminate "driver own failed" errors. |
| `0003-ps5-defconfig-enable-mt7921e.patch` | `arch/x86/configs/ps5_defconfig` | Enables `CONFIG_MT76_CORE=m`, `CONFIG_MT7921_COMMON=m`, and `CONFIG_MT7921E=m`. |
| `0004-iw620-rtnl-bounded-wait.patch` | `ps5-linux-mwifiex` (`moal_sta_cfg80211.c`) | Replaces infinite wait in `dump_station_info` with 20s bounded wait (`MOAL_IOCTL_WAIT_TIMEOUT`) to prevent RTNL lockups. |
| `0005-iw620-cmd-timeout-recovery.patch` | `ps5-linux-mwifiex` (`mlan_cmdevt.c`, `mlan_init.c`, `mlan_main.h`) | Auto-dequeues stalled commands and implements soft-recovery (up to 3 times) for benign queries. |
| `0006-iw620-adma-tx-min128.patch` | `ps5-linux-mwifiex` (`mlan_pcie.c`, `mlan_main.h`) | Enforces 128-byte minimum ADMA descriptor padding to eliminate TLS 1.3 burst crashes. |
| `0007-iw620-kexec-scratch-flr.patch` | `ps5-linux-mwifiex` (`moal_pcie.c`, `moal_sta_cfg80211.c`) | Reads BAR2 0x1C6C scratch register and performs PCIe FLR before firmware reload on kexec warm boots. |
| `0008-iw620-strip-tdls.patch` | `ps5-linux-mwifiex` (`moal_sta_cfg80211.c`) | Strips `WIPHY_FLAG_SUPPORTS_TDLS` to prevent unhandled TDLS 0x122 firmware panics. |

---

## 2. Kernel & Module Configuration

A template configuration is provided in `ps5-wifi.conf`:
- `options mt7921e disable_aspm=1`: Ensures stable link on southbridge interconnect.
- `options moal ps5_fresh_fw=1`: Enables PCIe function level reset on kexec boots.

Copy `ps5-wifi.conf` to `/etc/modprobe.d/ps5-wifi.conf` on the target system.

---

## 3. Local Verification & Policy Compliance

- All patches are strictly local.
- No changes pushed to remote repositories or external PRs.
- Clean kernel C coding standard applied (no C++ comments).
