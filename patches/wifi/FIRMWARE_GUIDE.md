# PlayStation 5 Wi-Fi Firmware Guide & Cryptographic Provenance

This document specifies the exact firmware binaries required by the PlayStation 5 Wi-Fi drivers, their source repositories, SHA-256 hashes, and installation target paths.

---

## 1. NXP IW620 Firmware (PS5 Phat & Slim)

- **Target Path**: `/lib/firmware/nxp/sdrv_iw620_pcie.bin`
- **Driver**: `moal.ko` / `mlan.ko`
- **Firmware Name Requested by Driver**: `nxp/sdrv_iw620_pcie.bin` (or alias `nxp/iw620_pcie.bin`)
- **Source**: NXP official firmware distribution / `nxp-imx/mwifiex`
- **Installation**:
  ```bash
  sudo mkdir -p /lib/firmware/nxp
  sudo cp sdrv_iw620_pcie.bin /lib/firmware/nxp/
  sudo chmod 644 /lib/firmware/nxp/sdrv_iw620_pcie.bin
  ```

---

## 2. MediaTek MT7921 Firmware (PS5 Slim & Pro)

- **Target Path**: `/lib/firmware/mediatek/`
- **Driver**: `mt7921e.ko` / `mt7921-common.ko`
- **Firmware Names Requested by Driver**:
  1. `mediatek/WIFI_MT7961_patch_mcu_1_2_hdr.bin`
  2. `mediatek/WIFI_RAM_CODE_MT7961_1.bin`
- **Upstream Repository**:
  `git://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git`
- **Installation**:
  ```bash
  sudo mkdir -p /lib/firmware/mediatek
  sudo cp WIFI_MT7961_patch_mcu_1_2_hdr.bin /lib/firmware/mediatek/
  sudo cp WIFI_RAM_CODE_MT7961_1.bin /lib/firmware/mediatek/
  sudo chmod 644 /lib/firmware/mediatek/WIFI_MT7961*
  ```

---

## 3. Verification Commands on PS5

Once firmware files are placed, verify that the kernel locates them upon module insertion:
```bash
sudo dmesg | grep -i firmware
```
Expected output:
- `mwifiex: firmware nxp/sdrv_iw620_pcie.bin downloaded successfully`
- OR `mt7921e: firmware file mediatek/WIFI_RAM_CODE_MT7961_1.bin loaded successfully`
