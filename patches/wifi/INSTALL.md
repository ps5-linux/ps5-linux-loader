# PlayStation 5 Wi-Fi Driver Installation & Configuration Guide

This guide details the exact procedure to install, configure, and verify the PlayStation 5 Wi-Fi drivers for both **NXP / Marvell IW620** (PS5 Phat / Slim) and **MediaTek MT7921 / MT7925** (PS5 Slim / Pro) on PS5 Linux Kernels **7.1.7**, **7.2.3**, and **7.3.1**.

---

## 1. Prerequisites

Before installing, confirm your running kernel version:
```bash
uname -r
```
The output will be `7.1.7`, `7.2.3`, or `7.3.1`.

> [!IMPORTANT]
> **Never load modules compiled for another kernel version.** Linux kernel module ABI differs across releases. Ensure you install files from the directory matching `uname -r`.

---

## 2. Firmware Installation

The Wi-Fi chips require proprietary firmware blobs placed in `/lib/firmware/`.

### A. NXP IW620 Firmware (PS5 Phat / Slim)
1. Create the target directory:
   ```bash
   sudo mkdir -p /lib/firmware/nxp
   ```
2. Obtain `sdrv_iw620_pcie.bin` from the official NXP repository or Linux firmware distribution and copy it:
   ```bash
   sudo cp sdrv_iw620_pcie.bin /lib/firmware/nxp/sdrv_iw620_pcie.bin
   sudo chmod 644 /lib/firmware/nxp/sdrv_iw620_pcie.bin
   ```

### B. MediaTek MT7921 Firmware (PS5 Slim / Pro)
1. Create the target directory:
   ```bash
   sudo mkdir -p /lib/firmware/mediatek
   ```
2. Obtain the MT7961 firmware binaries from upstream `linux-firmware.git`:
   - `WIFI_MT7961_patch_mcu_1_2_hdr.bin`
   - `WIFI_RAM_CODE_MT7961_1.bin`
3. Copy them into `/lib/firmware/mediatek/`:
   ```bash
   sudo cp WIFI_MT7961_patch_mcu_1_2_hdr.bin /lib/firmware/mediatek/
   sudo cp WIFI_RAM_CODE_MT7961_1.bin /lib/firmware/mediatek/
   sudo chmod 644 /lib/firmware/mediatek/WIFI_*
   ```

---

## 3. Kernel Module Installation

Extract or copy the verified `.ko` files from the release package matching your kernel version.

### A. For NXP IW620 (`mlan.ko` and `moal.ko`):
```bash
KERNEL_VER="$(uname -r)"
sudo mkdir -p "/lib/modules/${KERNEL_VER}/extra"
sudo cp "${KERNEL_VER}/iw620/mlan.ko" "/lib/modules/${KERNEL_VER}/extra/"
sudo cp "${KERNEL_VER}/iw620/moal.ko" "/lib/modules/${KERNEL_VER}/extra/"
sudo chmod 644 "/lib/modules/${KERNEL_VER}/extra/"*.ko
```

### B. For MediaTek MT7921 (`mt7921-common.ko` and `mt7921e.ko`):
*(Applicable to 7.2.3 and 7.3.1 only. For 7.1.7, see `7.1.7/mt7921/UNSUPPORTED_NOTE.md`)*
```bash
KERNEL_VER="$(uname -r)"
TARGET_DIR="/lib/modules/${KERNEL_VER}/kernel/drivers/net/wireless/mediatek/mt76/mt7921"
sudo mkdir -p "${TARGET_DIR}"
sudo cp "${KERNEL_VER}/mt7921/mt7921-common.ko" "${TARGET_DIR}/"
sudo cp "${KERNEL_VER}/mt7921/mt7921e.ko" "${TARGET_DIR}/"
sudo chmod 644 "${TARGET_DIR}/"*.ko
```

---

## 4. Module Dependencies & Modprobe Configuration

1. Rebuild the kernel module dependency database:
   ```bash
   sudo depmod -a
   ```

2. Install the modprobe options configuration to optimize PCIe throughput and avoid command timeouts:
   ```bash
   sudo cp ps5-wifi.conf /etc/modprobe.d/ps5-wifi.conf
   sudo chmod 644 /etc/modprobe.d/ps5-wifi.conf
   ```

---

## 5. Loading the Driver & Verification

### A. NXP IW620:
Load the modules in order (`mlan` first, then `moal`):
```bash
sudo modprobe mlan
sudo modprobe moal
```

### B. MediaTek MT7921:
```bash
sudo modprobe mt7921e
```

### C. Verify in Kernel Log:
```bash
sudo dmesg | grep -E 'mwifiex|moal|mlan|mt7921'
```
You should see:
- PCIe device successfully detected and initialized.
- Firmware successfully downloaded and handshake confirmed.
- Network interface `wlan0` or `mlan0` created.

### D. Bring Up Interface & Scan:
```bash
sudo ip link set up dev mlan0 2>/dev/null || sudo ip link set up dev wlan0
sudo iw dev
sudo iw dev wlan0 scan 2>/dev/null || sudo iw dev mlan0 scan
```

---

## 6. Removal / Rollback

To unload the driver:
```bash
# For IW620:
sudo modprobe -r moal mlan

# For MT7921:
sudo modprobe -r mt7921e mt7921-common
```
