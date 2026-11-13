# MediaTek MT7921 Status on PS5 Linux Kernel 7.1.7: UNSUPPORTED

## Technical Rationale & Evidence

MediaTek MT7921 / MT7925 is **UNSUPPORTED** on the official stock PS5 Linux Kernel **7.1.7** (`kernel-7.1.7-56922cf` / `linux-ps5_7.1.7_amd64.deb`):

1. **Kernel Configuration**:
   - The official configuration `/boot/config-7.1.7` explicitly has:
     ```text
     # CONFIG_MT7921E is not set
     ```
2. **Missing In-Tree Module**:
   - Unlike releases 7.2.3 and 7.3.1, the 7.1.7 Debian package does not include `mt7921e.ko` under `/lib/modules/7.1.7/kernel/drivers/net/wireless/mediatek/mt76/mt7921/`.
3. **Missing Runtime PM Guard in Stock Common Module**:
   - The stock `mt7921-common.ko` included in 7.1.7 lacks Patch 0001 (`0001-mt7921e-disable-runtime-pm-ps5.patch`). Loading an out-of-tree `mt7921e.ko` against this unpatched common module triggers PCIe Runtime PM sleep, causing a hard power-off / emergency shutdown of the PS5 console after ~20 seconds of idle.
4. **Resolution Path**:
   - To use MT7921 Wi-Fi, users should upgrade to **PS5 Linux Kernel 7.2.3** or **7.3.1**, where MT7921 is natively supported and patched.
   - Alternatively, 7.1.7 users must perform a full kernel source rebuild incorporating Patch 0003 (`0003-ps5-defconfig-enable-mt7921e.patch`) and Patch 0001.
