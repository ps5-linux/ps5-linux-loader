# PlayStation 5 Wi-Fi Driver Verification & Testing Protocol

This document outlines the complete quality assurance, testing methodology, and verification protocols for the PlayStation 5 Wi-Fi driver packages.

---

## 1. Automated CI & Software Validation (Completed)

All driver builds undergo a 5-stage automated CI validation pipeline prior to release:

### A. Static Patch Analysis (`verify_patches.py`)
- Verifies that all 13 patches conform strictly to Unified Diff format.
- Validates chunk offsets, line markers, and absence of malformed Git headers.
- Confirms zero syntax corruption in C header and source additions.

### B. Patch Applicability Matrix Dry-Run (`apply_patches.sh --dry-run`)
- Clones pinned Linux kernel and NXP mwifiex trees.
- Validates sequential applicability of:
  - Patches 0001 - 0003 against Linux tree.
  - Patches 0004 - 0013 against NXP mwifiex tree.
- Ensures zero rejected hunks across all target kernel versions (7.1.7, 7.2.3, 7.3.1).

### C. Native Toolchain & Kbuild Execution
- Eliminates any stub bypass (`exit 0`).
- Builds native x86_64 `objtool` from pinned Linux kernel source (`tools/objtool`).
- Executes genuine Kbuild compilation and MODPOST with ORC unwind table generation and stack validation.

### D. Strict ABI & Symbol CRC Validation (`validate_abi_crc.py`)
- Inspects ELF64 Little-Endian headers (`e_machine == EM_X86_64`).
- Verifies exact target kernel string in `vermagic` along with required flags (`SMP`, `preempt`, `mod_unload`, `modversions`).
- Parses symbol versions from `.modinfo`, `__versions`, and `__version_ext_crcs`.
- Cross-references 100% of imported symbols against the official target kernel's `Module.symvers`.
- Validates exported symbols across peer modules (`mlan.ko` for `moal.ko`, and `mt7921-common.ko` for `mt7921e.ko`).

### E. Adversarial Negative Test Suite
- Deliberately introduces 10 corruptions and anomalies into the build pipeline:
  1. Corrupted ELF Magic header (`NOPE`) -> Hard-fail.
  2. Injected ARM64 machine architecture (`EM_AARCH64`) on x86_64 target -> Hard-fail.
  3. Incompatible 32-bit ELF class (`ELFCLASS32`) -> Hard-fail.
  4. Incompatible vermagic kernel version (`9.9.9`) -> Hard-fail.
  5. Stripped `modversions` flag in vermagic -> Hard-fail.
  6. Adversarial single-bit CRC flip in `__versions` -> Hard-fail.
  7. Dual-section CRC bit-flip mismatch between `__versions` and `__version_ext_crcs` -> Hard-fail.
  8. Injected nonexistent missing symbol (`injected_dummy_missing_symbol`) -> Hard-fail.
  9. Truncated binary file with corrupt section table -> Hard-fail.
  10. Stripped preemption flag in vermagic -> Hard-fail.
- Proves that the verification tool is incapable of false positives.

---

## 2. Retail PlayStation 5 Hardware Field-Testing Protocol

> [!WARNING]
> **Status: PENDING Physical Console Hardware Execution.**
> While the software compilation, ELF structure, vermagic, and symbol CRCs are 100% verified against the official PS5 kernel headers, runtime execution on physical retail hardware requires manual console testing.

When executing field testing on a jailbroken PS5 console, follow this checklist:

### Phase 1: Hardware PCI Detection
```bash
lspci -nnk | grep -E 'Network|Wireless|MediaTek|Marvell|NXP'
```
- **Expected Result**:
  - For IW620: Device `11ab:2b43` or `1b4b:2b43` bound to `moal` or unassigned.
  - For MT7921: Device `14c3:7961` or `14c3:7922` bound to `mt7921e`.

### Phase 2: Driver Probe & Firmware Handshake
```bash
# Load module and inspect dmesg
sudo modprobe moal # or mt7921e
sudo dmesg -w
```
- **Expected Result**:
  - No kernel panic or Salina PCIe bridge freeze.
  - Firmware file loaded successfully from `/lib/firmware/`.
  - Firmware handshake confirmed, MAC address assigned.

### Phase 3: Interface Configuration & Network Scanning
```bash
sudo ip link set wlan0 up
sudo iw dev wlan0 scan | grep SSID
```
- **Expected Result**:
  - Interface state transitions to `UP`.
  - Wireless access points (SSIDs) detected and listed.

### Phase 4: Authentication & DHCP
```bash
# Connect using wpa_supplicant or NetworkManager
sudo nmcli dev wifi connect "MySSID" password "MyPassword"
ip addr show dev wlan0
```
- **Expected Result**:
  - Successful 4-way handshake (WPA2-PSK or WPA3-SAE).
  - IPv4 address assigned via DHCP and default gateway configured.

### Phase 5: Sustained Throughput & Stability Benchmark
```bash
iperf3 -c <server-ip> -t 300 -i 5
```
- **Expected Result**:
  - Zero dropped connections or PCIe timeouts over 5 minutes.
  - Stable throughput matching 802.11ax / 802.11ac standards.

### Phase 6: Sleep / Reboot Quirk Validation
```bash
sudo reboot
```
- **Expected Result**:
  - System reboots cleanly without hang.
  - On next boot, the wireless card is enumerated immediately (PCIe reset quirk verified).
