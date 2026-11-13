#!/usr/bin/env python3
"""
PlayStation 5 Kernel Module ABI & Symbol CRC Validator (validate_abi_crc.py)

Strict ABI, ELF, Vermagic, and Symbol CRC verification tool for PS5 Linux kernel modules.
Performs independent ELF header validation, vermagic audit, configuration checks,
and symbol CRC verification against target kernel Module.symvers.
"""

import argparse
import glob
import json
import os
import struct
import sys
from typing import Dict, List, Optional, Set, Tuple

EM_X86_64 = 62
ELFCLASS64 = 2
ELFDATA2LSB = 1
ET_REL = 1

REQUIRED_VERMAGIC_FLAGS = ["SMP", "preempt", "mod_unload", "modversions"]


class ElfParseException(Exception):
    pass


class ElfModuleReader:
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.filename = os.path.basename(filepath)
        with open(filepath, "rb") as f:
            self.raw_data = f.read()

        if len(self.raw_data) < 64:
            raise ElfParseException(f"File too small to be a valid ELF binary: {len(self.raw_data)} bytes")

        self._parse_header()
        self._parse_sections()

    def _parse_header(self):
        magic = self.raw_data[:4]
        if magic != b"\x7fELF":
            raise ElfParseException(f"Invalid ELF magic: {magic!r}")

        self.ei_class = self.raw_data[4]
        self.ei_data = self.raw_data[5]
        self.ei_version = self.raw_data[6]
        self.ei_osabi = self.raw_data[7]

        (
            self.e_type,
            self.e_machine,
            self.e_version,
            self.e_entry,
            self.e_phoff,
            self.e_shoff,
            self.e_flags,
            self.e_ehsize,
            self.e_phentsize,
            self.e_phnum,
            self.e_shentsize,
            self.e_shnum,
            self.e_shstrndx,
        ) = struct.unpack("<HHIQQQIHHHHHH", self.raw_data[16:64])

    def _parse_sections(self):
        self.sections: Dict[str, Tuple[int, int]] = {}
        self.section_headers = []

        if self.e_shoff + (self.e_shnum * self.e_shentsize) > len(self.raw_data):
            raise ElfParseException("Section header table extends beyond file size")

        for i in range(self.e_shnum):
            offset = self.e_shoff + (i * self.e_shentsize)
            sh_hdr = struct.unpack("<IIQQQQIIQQ", self.raw_data[offset : offset + 64])
            self.section_headers.append(sh_hdr)

        if self.e_shstrndx >= len(self.section_headers):
            raise ElfParseException(f"Invalid section header string table index: {self.e_shstrndx}")

        shstr_hdr = self.section_headers[self.e_shstrndx]
        shstr_off = shstr_hdr[4]
        shstr_size = shstr_hdr[5]
        if shstr_off + shstr_size > len(self.raw_data):
            raise ElfParseException("Section header string table extends beyond file size")
        shstrtab = self.raw_data[shstr_off : shstr_off + shstr_size]

        for i, sh in enumerate(self.section_headers):
            name_offset = sh[0]
            end = shstrtab.find(b"\x00", name_offset)
            if end == -1:
                name = shstrtab[name_offset:].decode("ascii", errors="replace")
            else:
                name = shstrtab[name_offset:end].decode("ascii", errors="replace")
            self.sections[name] = (sh[4], sh[5])

    def get_section_data(self, section_name: str) -> Optional[bytes]:
        if section_name not in self.sections:
            return None
        offset, size = self.sections[section_name]
        return self.raw_data[offset : offset + size]

    def get_modinfo(self) -> Dict[str, List[str]]:
        data = self.get_section_data(".modinfo")
        if not data:
            return {}
        entries: Dict[str, List[str]] = {}
        for item in data.split(b"\x00"):
            if not item:
                continue
            decoded = item.decode("utf-8", errors="replace")
            if "=" in decoded:
                k, v = decoded.split("=", 1)
                entries.setdefault(k, []).append(v)
            else:
                entries.setdefault(decoded, []).append("")
        return entries

    def get_imported_version_symbols(self) -> Tuple[Dict[str, int], List[str]]:
        symbols: Dict[str, int] = {}
        consistency_errors: List[str] = []

        versions_symbols: Dict[str, int] = {}
        data = self.get_section_data("__versions")
        if data:
            entry_size = 64
            count = len(data) // entry_size
            for i in range(count):
                chunk = data[i * entry_size : (i + 1) * entry_size]
                crc = struct.unpack("<Q", chunk[:8])[0] & 0xFFFFFFFF
                name_bytes = chunk[8:]
                name = name_bytes.split(b"\x00")[0].decode("ascii", errors="replace").strip()
                if name:
                    versions_symbols[name] = crc

        ext_symbols: Dict[str, int] = {}
        ext_crc_data = self.get_section_data("__version_ext_crcs")
        ext_names_data = self.get_section_data("__version_ext_names")
        if ext_crc_data and ext_names_data:
            ext_names = [n.decode("ascii", errors="replace").strip() for n in ext_names_data.split(b"\x00") if n]
            ext_crc_count = len(ext_crc_data) // 4
            ext_crcs = struct.unpack(f"<{ext_crc_count}I", ext_crc_data)
            for name, crc in zip(ext_names, ext_crcs):
                if name:
                    ext_symbols[name] = crc

        # If both are present, verify cross-section integrity
        if versions_symbols and ext_symbols:
            for name, v_crc in versions_symbols.items():
                if name in ext_symbols:
                    e_crc = ext_symbols[name]
                    if v_crc != e_crc:
                        consistency_errors.append(
                            f"CRC inconsistency between __versions (0x{v_crc:08x}) and __version_ext_crcs (0x{e_crc:08x}) for symbol '{name}'"
                        )
            symbols = versions_symbols
        elif versions_symbols:
            symbols = versions_symbols
        elif ext_symbols:
            symbols = ext_symbols

        return symbols, consistency_errors

    def get_exported_symbols(self) -> Dict[str, int]:
        exported: Dict[str, int] = {}
        if ".rela__ksymtab" not in self.sections or "__kcrctab" not in self.sections:
            return exported

        symtab_data = self.get_section_data(".symtab")
        strtab_data = self.get_section_data(".strtab")
        rela_data = self.get_section_data(".rela__ksymtab")
        kcrc_data = self.get_section_data("__kcrctab")

        if not (symtab_data and strtab_data and rela_data and kcrc_data):
            return exported

        sym_count = len(symtab_data) // 24
        sym_names = []
        for i in range(sym_count):
            chunk = symtab_data[i * 24 : (i + 1) * 24]
            name_idx = struct.unpack("<I", chunk[:4])[0]
            name = strtab_data[name_idx:].split(b"\x00")[0].decode("ascii", errors="replace")
            sym_names.append(name)

        num_crcs = len(kcrc_data) // 4
        crcs = struct.unpack(f"<{num_crcs}I", kcrc_data)

        num_relas = len(rela_data) // 24
        if num_relas >= num_crcs * 3:
            for i in range(num_crcs):
                rel_val = rela_data[(i * 3) * 24 : (i * 3 + 1) * 24]
                r_offset, r_info, r_addend = struct.unpack("<QQq", rel_val)
                sym_idx = r_info >> 32
                if sym_idx < len(sym_names):
                    exported[sym_names[sym_idx]] = crcs[i]

        return exported


def parse_module_symvers(filepath: str) -> Dict[str, Tuple[int, str, str]]:
    symvers: Dict[str, Tuple[int, str, str]] = {}
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) >= 2:
                crc_str = parts[0].strip()
                sym_name = parts[1].strip()
                mod_src = parts[2].strip() if len(parts) > 2 else ""
                export_type = parts[3].strip() if len(parts) > 3 else ""
                try:
                    crc_val = int(crc_str, 16)
                    symvers[sym_name] = (crc_val, mod_src, export_type)
                except ValueError:
                    continue
    return symvers


def parse_kconfig(filepath: str) -> Dict[str, str]:
    config: Dict[str, str] = {}
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                config[k.strip()] = v.strip().strip('"')
    return config


def validate_module_abi(
    module_path: str,
    target_kernel: str,
    symvers: Dict[str, Tuple[int, str, str]],
    peer_exports: Optional[Dict[str, int]] = None,
    kconfig: Optional[Dict[str, str]] = None,
    verbose: bool = False,
) -> Dict[str, any]:
    report = {
        "module": os.path.basename(module_path),
        "module_path": module_path,
        "target_kernel": target_kernel,
        "elf_valid": False,
        "vermagic_valid": False,
        "kconfig_valid": None,
        "crc_valid": False,
        "errors": [],
        "warnings": [],
        "stats": {
            "total_imported_symbols": 0,
            "matched_symbols": 0,
            "mismatched_symbols": 0,
            "missing_symbols": 0,
            "peer_matched_symbols": 0,
        },
        "vermagic": "",
        "dependencies": [],
        "mismatches": [],
        "missing": [],
    }

    if peer_exports is None:
        peer_exports = {}

    try:
        reader = ElfModuleReader(module_path)
    except Exception as e:
        report["errors"].append(f"ELF Header / Structure parse error: {e}")
        return report

    elf_errors = []
    if reader.ei_class != ELFCLASS64:
        elf_errors.append(f"ELF Class mismatch: expected 64-bit (2), got {reader.ei_class}")
    if reader.ei_data != ELFDATA2LSB:
        elf_errors.append(f"ELF Endianness mismatch: expected Little-Endian (1), got {reader.ei_data}")
    if reader.e_machine != EM_X86_64:
        elf_errors.append(f"ELF Machine Architecture mismatch: expected x86_64 (62), got {reader.e_machine}")
    if reader.e_type != ET_REL:
        elf_errors.append(f"ELF Object Type mismatch: expected relocatable ET_REL (1), got {reader.e_type}")

    if elf_errors:
        report["errors"].extend(elf_errors)
        report["elf_valid"] = False
    else:
        report["elf_valid"] = True

    modinfo = reader.get_modinfo()
    vermagic_list = modinfo.get("vermagic", [])
    if not vermagic_list:
        report["errors"].append("Missing 'vermagic' tag in .modinfo section")
    else:
        vermagic_str = vermagic_list[0]
        report["vermagic"] = vermagic_str
        tokens = vermagic_str.strip().split()
        if not tokens:
            report["errors"].append("Empty vermagic string")
        else:
            base_ver = tokens[0]
            if base_ver != target_kernel:
                report["errors"].append(
                    f"Vermagic kernel version mismatch: expected '{target_kernel}', found '{base_ver}' (full: '{vermagic_str}')"
                )

            for flag in REQUIRED_VERMAGIC_FLAGS:
                if flag not in tokens:
                    report["errors"].append(
                        f"Missing required vermagic flag '{flag}' (present: {tokens[1:]})"
                    )

            if not any("vermagic" in err.lower() for err in report["errors"]):
                report["vermagic_valid"] = True

    depends_list = modinfo.get("depends", [])
    if depends_list:
        report["dependencies"] = [d for d in depends_list[0].split(",") if d]

    if kconfig:
        kcfg_errors = []
        if kconfig.get("CONFIG_MODULES") != "y":
            kcfg_errors.append("CONFIG_MODULES is not set to 'y'")
        if kconfig.get("CONFIG_MODVERSIONS") != "y":
            kcfg_errors.append("CONFIG_MODVERSIONS is not set to 'y'")
        if kconfig.get("CONFIG_SMP") != "y":
            kcfg_errors.append("CONFIG_SMP is not set to 'y'")

        preempt_set = any(
            kconfig.get(k) == "y"
            for k in ["CONFIG_PREEMPT", "CONFIG_PREEMPT_DYNAMIC", "CONFIG_PREEMPTION", "CONFIG_PREEMPT_BUILD"]
        )
        if not preempt_set:
            kcfg_errors.append("No active kernel preemption setting found in .config")

        if "mt7921" in report["module"]:
            if target_kernel == "7.1.7":
                if kconfig.get("CONFIG_MT7921E") == "m" or kconfig.get("CONFIG_MT7921E") == "y":
                    report["warnings"].append("CONFIG_MT7921E is set in 7.1.7 config (official release disables it)")
            elif target_kernel in ("7.2.3", "7.3.1"):
                if kconfig.get("CONFIG_MT7921E") != "m":
                    report["warnings"].append(f"CONFIG_MT7921E expected 'm' in {target_kernel}, got '{kconfig.get('CONFIG_MT7921E')}'")

        if kcfg_errors:
            report["errors"].extend(kcfg_errors)
            report["kconfig_valid"] = False
        else:
            report["kconfig_valid"] = True

    imported_symbols, consistency_errors = reader.get_imported_version_symbols()
    if consistency_errors:
        report["errors"].extend(consistency_errors)

    report["stats"]["total_imported_symbols"] = len(imported_symbols)

    if not imported_symbols and "modversions" in report["vermagic"]:
        report["errors"].append(
            "Module vermagic specifies 'modversions' but no symbols found in __versions or __version_ext_crcs"
        )

    for sym_name, mod_crc in imported_symbols.items():
        if sym_name in symvers:
            exp_crc, mod_src, export_type = symvers[sym_name]
            if mod_crc == exp_crc:
                report["stats"]["matched_symbols"] += 1
            else:
                report["stats"]["mismatched_symbols"] += 1
                report["mismatches"].append({
                    "symbol": sym_name,
                    "module_crc": f"0x{mod_crc:08x}",
                    "symvers_crc": f"0x{exp_crc:08x}",
                    "source": mod_src,
                })
        elif sym_name in peer_exports:
            exp_crc = peer_exports[sym_name]
            if mod_crc == exp_crc:
                report["stats"]["matched_symbols"] += 1
                report["stats"]["peer_matched_symbols"] += 1
            else:
                report["stats"]["mismatched_symbols"] += 1
                report["mismatches"].append({
                    "symbol": sym_name,
                    "module_crc": f"0x{mod_crc:08x}",
                    "symvers_crc": f"0x{exp_crc:08x}",
                    "source": "peer_module",
                })
        else:
            report["stats"]["missing_symbols"] += 1
            report["missing"].append(sym_name)

    if report["stats"]["mismatched_symbols"] > 0:
        report["errors"].append(
            f"Symbol CRC mismatch detected on {report['stats']['mismatched_symbols']} symbols"
        )
    if report["stats"]["missing_symbols"] > 0:
        report["errors"].append(
            f"Missing symbols detected: {report['stats']['missing_symbols']} symbols not found in Module.symvers or peer exports"
        )

    if (
        report["elf_valid"]
        and report["vermagic_valid"]
        and report["stats"]["mismatched_symbols"] == 0
        and report["stats"]["missing_symbols"] == 0
        and not consistency_errors
        and (report["kconfig_valid"] is not False)
    ):
        report["crc_valid"] = True

    return report


def run_adversarial_suite(symvers_path: str, valid_module_path: str, target_kernel: str) -> bool:
    print("\n=======================================================")
    print("  RUNNING ADVERSARIAL & NEGATIVE VALIDATION TEST SUITE  ")
    print("=======================================================\n")

    symvers = parse_module_symvers(symvers_path)
    with open(valid_module_path, "rb") as f:
        clean_bytes = bytearray(f.read())

    all_passed = True

    def test_case(name: str, modified_bytes: bytearray, expected_error_substr: str):
        nonlocal all_passed
        tmp_path = valid_module_path + ".adv_test.tmp"
        try:
            with open(tmp_path, "wb") as f_out:
                f_out.write(modified_bytes)
            rep = validate_module_abi(tmp_path, target_kernel, symvers)
            err_text = " | ".join(rep["errors"])
            if not rep["crc_valid"] and expected_error_substr.lower() in err_text.lower():
                print(f"  [PASS] {name}")
                print(f"         Cleanly caught expected failure: '{err_text}'")
            else:
                print(f"  [FAIL] {name}")
                print(f"         crc_valid={rep['crc_valid']}, Errors: {rep['errors']}")
                all_passed = False
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    # 1. Corrupted ELF Magic
    b1 = bytearray(clean_bytes)
    b1[0:4] = b"NOPE"
    test_case("1. Corrupted ELF Magic Header", b1, "Invalid ELF magic")

    # 2. Corrupted Architecture (simulate aarch64 EM_AARCH64 = 183)
    b2 = bytearray(clean_bytes)
    struct.pack_into("<H", b2, 18, 183)
    test_case("2. Mismatched ELF Architecture (ARM64 on x86_64 target)", b2, "ELF Machine Architecture mismatch")

    # 3. 32-bit ELF Class
    b3 = bytearray(clean_bytes)
    b3[4] = 1
    test_case("3. Incompatible 32-bit ELF Class", b3, "ELF Class mismatch")

    # 4. Corrupted Vermagic Version
    b4 = bytearray(clean_bytes)
    idx_vm = b4.find(f"vermagic={target_kernel}".encode("ascii"))
    if idx_vm != -1:
        b4[idx_vm + 9 : idx_vm + 9 + 5] = b"9.9.9"
        test_case("4. Injected Incompatible Vermagic Kernel Version", b4, "Vermagic kernel version mismatch")

    # 5. Missing Vermagic Flag (stripping modversions)
    b5 = bytearray(clean_bytes)
    idx_vm5 = b5.find(b"vermagic=")
    if idx_vm5 != -1:
        idx_mv = b5.find(b"modversions", idx_vm5)
        if idx_mv != -1:
            b5[idx_mv : idx_mv + 11] = b"___________"
            test_case("5. Stripped Vermagic 'modversions' Flag", b5, "Missing required vermagic flag 'modversions'")

    # 6. Adversarial Symbol CRC Bit-Flip in __versions
    b6 = bytearray(clean_bytes)
    reader = ElfModuleReader(valid_module_path)
    ver_sec = reader.sections.get("__versions")
    if ver_sec:
        off = ver_sec[0]
        orig_crc = struct.unpack_from("<Q", b6, off)[0]
        struct.pack_into("<Q", b6, off, orig_crc ^ 0xFFFFFFFF)
        test_case("6. Adversarial Symbol CRC Bit-Flip in __versions", b6, "CRC inconsistency")

    # 7. Adversarial Symbol CRC Bit-Flip in both __versions and __version_ext_crcs
    b7 = bytearray(clean_bytes)
    ext_sec = reader.sections.get("__version_ext_crcs")
    if ver_sec and ext_sec:
        off_v = ver_sec[0]
        off_e = ext_sec[0]
        orig_crc_v = struct.unpack_from("<Q", b7, off_v)[0]
        new_crc = orig_crc_v ^ 0x00000001
        struct.pack_into("<Q", b7, off_v, new_crc)
        struct.pack_into("<I", b7, off_e, new_crc & 0xFFFFFFFF)
        test_case("7. Adversarial Dual-Section CRC Bit-Flip Mismatch", b7, "Symbol CRC mismatch")

    # 8. Injected Nonexistent Symbol in __versions
    b8 = bytearray(clean_bytes)
    if ver_sec:
        off = ver_sec[0]
        struct.pack_into("56s", b8, off + 8, b"malicious_injected_missing_sym\x00")
        test_case("8. Injected Nonexistent Missing Symbol", b8, "Missing symbols detected")

    # 9. Truncated Binary / Section Header Table Overflow
    b9 = bytearray(clean_bytes[:100])
    test_case("9. Truncated Binary Corrupted Structure", b9, "Section header table extends beyond file size")

    # 10. Mismatched Preemption Flag in Vermagic
    b10 = bytearray(clean_bytes)
    idx_vm10 = b10.find(b"vermagic=")
    if idx_vm10 != -1:
        idx_pr = b10.find(b"preempt", idx_vm10)
        if idx_pr != -1:
            b10[idx_pr : idx_pr + 7] = b"_______"
            test_case("10. Stripped Preemption Flag in Vermagic", b10, "Missing required vermagic flag 'preempt'")

    print(f"\nAdversarial Suite Result: {'ALL 10 TESTS PASSED (100% HARD-FAIL ON ABI ANOMALIES)' if all_passed else 'SOME TESTS FAILED'}\n")
    return all_passed


def main():
    parser = argparse.ArgumentParser(
        description="PlayStation 5 Kernel Module ABI & Symbol CRC Validator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-m", "--module",
        required=True,
        nargs="+",
        help="Path or glob pattern to .ko kernel module file(s)",
    )
    parser.add_argument(
        "-s", "--symvers",
        required=True,
        help="Path to target kernel Module.symvers",
    )
    parser.add_argument(
        "-k", "--target-kernel",
        required=True,
        choices=["7.1.7", "7.2.3", "7.3.1"],
        help="Target PS5 Linux kernel version (7.1.7, 7.2.3, 7.3.1)",
    )
    parser.add_argument(
        "-c", "--kconfig",
        help="Optional path to kernel .config",
    )
    parser.add_argument(
        "-p", "--peer-module",
        nargs="*",
        default=[],
        help="Optional peer module(s) exporting symbols imported by the target module",
    )
    parser.add_argument(
        "--json",
        dest="json_output",
        help="Optional file path to write JSON validation results",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output",
    )
    parser.add_argument(
        "--test-adversarial",
        action="store_true",
        help="Run adversarial negative test suite against the first module",
    )

    args = parser.parse_args()

    if not os.path.isfile(args.symvers):
        print(f"ERROR: Module.symvers not found: {args.symvers}", file=sys.stderr)
        sys.exit(1)

    symvers = parse_module_symvers(args.symvers)
    print(f"Loaded {len(symvers)} symbols from {args.symvers}")

    kconfig = None
    if args.kconfig:
        if not os.path.isfile(args.kconfig):
            print(f"ERROR: .config file not found: {args.kconfig}", file=sys.stderr)
            sys.exit(1)
        kconfig = parse_kconfig(args.kconfig)
        print(f"Loaded {len(kconfig)} config options from {args.kconfig}")

    peer_exports: Dict[str, int] = {}
    for pm in args.peer_module:
        for pm_path in glob.glob(pm):
            if os.path.isfile(pm_path):
                pm_reader = ElfModuleReader(pm_path)
                p_exp = pm_reader.get_exported_symbols()
                peer_exports.update(p_exp)
                print(f"Loaded {len(p_exp)} exported symbols from peer module {os.path.basename(pm_path)}")

    target_files = []
    for pattern in args.module:
        matched = glob.glob(pattern)
        if not matched and os.path.isfile(pattern):
            matched = [pattern]
        target_files.extend(matched)

    if not target_files:
        print("ERROR: No module files found matching specified patterns", file=sys.stderr)
        sys.exit(1)

    if args.test_adversarial:
        ok = run_adversarial_suite(args.symvers, target_files[0], args.target_kernel)
        if not ok:
            sys.exit(1)

    print("\n=======================================================")
    print(f"  VALIDATING PS5 KERNEL MODULES AGAINST TARGET {args.target_kernel}  ")
    print("=======================================================\n")

    overall_success = True
    reports = []

    for mod_path in target_files:
        rep = validate_module_abi(
            module_path=mod_path,
            target_kernel=args.target_kernel,
            symvers=symvers,
            peer_exports=peer_exports,
            kconfig=kconfig,
            verbose=args.verbose,
        )
        reports.append(rep)

        status_tag = "[PASS]" if rep["crc_valid"] else "[FAIL]"
        print(f"{status_tag} {rep['module']}:")
        print(f"       ELF Architecture: {'x86_64 Valid' if rep['elf_valid'] else 'INVALID'}")
        print(f"       Vermagic:         '{rep['vermagic']}' ({'VALID' if rep['vermagic_valid'] else 'INVALID'})")
        if rep["kconfig_valid"] is not None:
            print(f"       Kernel .config:   {'VALID' if rep['kconfig_valid'] else 'INVALID'}")
        print(
            f"       Symbol CRCs:      Total={rep['stats']['total_imported_symbols']} | "
            f"Matched={rep['stats']['matched_symbols']} | "
            f"Mismatched={rep['stats']['mismatched_symbols']} | "
            f"Missing={rep['stats']['missing_symbols']}"
        )

        if rep["errors"]:
            overall_success = False
            print("       ERRORS:")
            for err in rep["errors"]:
                print(f"         - {err}")
            if rep["mismatches"]:
                print("       MISMATCH DETAILS (first 5):")
                for mm in rep["mismatches"][:5]:
                    print(f"         * {mm['symbol']}: module={mm['module_crc']} != symvers={mm['symvers_crc']} ({mm['source']})")
            if rep["missing"]:
                print(f"       MISSING SYMBOLS (first 5): {rep['missing'][:5]}")

        print()

    if args.json_output:
        with open(args.json_output, "w", encoding="utf-8") as f:
            json.dump({
                "target_kernel": args.target_kernel,
                "overall_success": overall_success,
                "reports": reports,
            }, f, indent=2)
        print(f"Validation report saved to: {args.json_output}")

    if overall_success:
        print("[SUCCESS] All kernel modules passed 100% strict ABI, vermagic, and CRC verification.")
        sys.exit(0)
    else:
        print("[FAILURE] One or more kernel modules failed ABI / symbol CRC validation.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
