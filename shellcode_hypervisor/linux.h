/*
 * Copyright (C) 2026 Andy Nguyen
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

#ifndef __LINUX_H__
#define __LINUX_H__

#include <stdint.h>

#define X86_SUBARCH_PS5 5

enum e820_type {
  E820_TYPE_RAM = 1,
  E820_TYPE_RESERVED = 2,
  E820_TYPE_ACPI = 3,
  E820_TYPE_NVS = 4,
  E820_TYPE_UNUSABLE = 5,
  E820_TYPE_PMEM = 7,
  E820_TYPE_PRAM = 12,
  E820_TYPE_SOFT_RESERVED = 0xefffffff,
};

struct boot_e820_entry {
  uint64_t addr;
  uint64_t size;
  uint32_t type;
} __attribute__((packed));

struct setup_header {
  uint8_t setup_sects;
  uint16_t root_flags;
  uint32_t syssize;
  uint16_t ram_size;
  uint16_t vid_mode;
  uint16_t root_dev;
  uint16_t boot_flag;
  uint16_t jump;
  uint32_t header;
  uint16_t version;
  uint32_t realmode_swtch;
  uint16_t start_sys_seg;
  uint16_t kernel_version;
  uint8_t type_of_loader;
  uint8_t loadflags;
  uint16_t setup_move_size;
  uint32_t code32_start;
  uint32_t ramdisk_image;
  uint32_t ramdisk_size;
  uint32_t bootsect_kludge;
  uint16_t heap_end_ptr;
  uint8_t ext_loader_ver;
  uint8_t ext_loader_type;
  uint32_t cmd_line_ptr;
  uint32_t initrd_addr_max;
  uint32_t kernel_alignment;
  uint8_t relocatable_kernel;
  uint8_t min_alignment;
  uint16_t xloadflags;
  uint32_t cmdline_size;
  uint32_t hardware_subarch;
  uint64_t hardware_subarch_data;
  uint32_t payload_offset;
  uint32_t payload_length;
  uint64_t setup_data;
  uint64_t pref_address;
  uint32_t init_size;
  uint32_t handover_offset;
  uint32_t kernel_info_offset;
} __attribute__((packed));

#define E820_MAX_ENTRIES_ZEROPAGE 128

struct boot_params {
  uint8_t screen_info[0x40];       // 0x000
  uint8_t apm_bios_info[0x14];     // 0x040
  uint8_t _pad2[4];                // 0x054
  uint64_t tboot_addr;             // 0x058
  uint8_t ist_info[0x10];          // 0x060
  uint64_t acpi_rsdp_addr;         // 0x070
  uint8_t _pad3[8];                // 0x078
  uint8_t hd0_info[16];            // 0x080
  uint8_t hd1_info[16];            // 0x090
  uint8_t sys_desc_table[0x10];    // 0x0a0
  uint8_t olpc_ofw_header[0x10];   // 0x0b0
  uint32_t ext_ramdisk_image;      // 0x0c0
  uint32_t ext_ramdisk_size;       // 0x0c4
  uint32_t ext_cmd_line_ptr;       // 0x0c8
  uint8_t _pad4[112];              // 0x0cc
  uint32_t cc_blob_address;        // 0x13c
  uint8_t edid_info[0x80];         // 0x140
  uint8_t efi_info[0x20];          // 0x1c0
  uint32_t alt_mem_k;              // 0x1e0
  uint32_t scratch;                // 0x1e4
  uint8_t e820_entries;            // 0x1e8
  uint8_t eddbuf_entries;          // 0x1e9
  uint8_t edd_mbr_sig_buf_entries; // 0x1ea
  uint8_t kbd_status;              // 0x1eb
  uint8_t secure_boot;             // 0x1ec
  uint8_t _pad5[2];                // 0x1ed
  uint8_t sentinel;                // 0x1ef
  uint8_t _pad6[1];                // 0x1f0
  struct setup_header hdr;         // 0x1f1
  uint8_t _pad7[0x290 - 0x1f1 - sizeof(struct setup_header)];
  uint32_t edd_mbr_sig_buffer[16];                              // 0x290
  struct boot_e820_entry e820_table[E820_MAX_ENTRIES_ZEROPAGE]; // 0x2d0
  uint8_t _pad8[48];                                            // 0xcd0
  uint8_t eddbuf[0x1ec];                                        // 0xd00
  uint8_t _pad9[276];                                           // 0xeec
} __attribute__((packed));

#endif
