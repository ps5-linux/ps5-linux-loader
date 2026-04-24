#include "boot_linux.h"
#include "../include/config.h"
#include "linux.h"
#include "utils.h"
#include <stddef.h>
#include <stdint.h>

struct linux_info {
  uintptr_t bzimage;
  size_t bzimage_size;
  uintptr_t initrd;
  size_t initrd_size;
  size_t vram_size;
  char cmdline[2048];
};

static struct linux_info info;

static volatile int exited_cpus = 0;

static void configure_vram(uint64_t fb_start, uint64_t vram_start,
                           uint64_t vram_size) {
  uint64_t vram_end = vram_start + vram_size - 1;
  uint64_t fb_top = fb_start + vram_size - 1;

  *(uint32_t *)(AMDGPU_MMIO_BASE + RCC_CONFIG_MEMSIZE) = vram_size >> 20;

  *(uint32_t *)(AMDGPU_MMIO_BASE + GCMC_VM_FB_OFFSET) = vram_start >> 24;

  *(uint32_t *)(AMDGPU_MMIO_BASE + GCMC_VM_LOCAL_HBM_ADDRESS_START) =
      vram_start >> 24;
  *(uint32_t *)(AMDGPU_MMIO_BASE + GCMC_VM_LOCAL_HBM_ADDRESS_END) =
      vram_end >> 24;
  *(uint32_t *)(AMDGPU_MMIO_BASE + GCMC_VM_FB_LOCATION_BASE) = fb_start >> 24;
  *(uint32_t *)(AMDGPU_MMIO_BASE + GCMC_VM_FB_LOCATION_TOP) = fb_top >> 24;

  *(uint32_t *)(AMDGPU_MMIO_BASE + MMMC_VM_FB_OFFSET) = vram_start >> 24;
  *(uint32_t *)(AMDGPU_MMIO_BASE + MMMC_VM_LOCAL_HBM_ADDRESS_START) =
      vram_start >> 24;
  *(uint32_t *)(AMDGPU_MMIO_BASE + MMMC_VM_LOCAL_HBM_ADDRESS_END) =
      vram_end >> 24;
  *(uint32_t *)(AMDGPU_MMIO_BASE + MMMC_VM_FB_LOCATION_BASE) = fb_start >> 24;
  *(uint32_t *)(AMDGPU_MMIO_BASE + MMMC_VM_FB_LOCATION_TOP) = fb_top >> 24;

  *(uint32_t *)(AMDGPU_MMIO_BASE + MMHUBBUB_WHITELIST_BASE_ADDR_0) =
      vram_start >> 12;
  *(uint32_t *)(AMDGPU_MMIO_BASE + MMHUBBUB_WHITELIST_TOP_ADDR_0) =
      vram_end >> 12;
  *(uint32_t *)(AMDGPU_MMIO_BASE + DCHUBBUB_WHITELIST_BASE_ADDR_0) =
      vram_start >> 12;
  *(uint32_t *)(AMDGPU_MMIO_BASE + DCHUBBUB_WHITELIST_TOP_ADDR_0) =
      vram_end >> 12;
}

static void append_e820_table(struct boot_params *bp, uint64_t start,
                              uint64_t end, uint32_t type) {
  uint8_t idx = bp->e820_entries;
  bp->e820_table[idx].addr = start;
  bp->e820_table[idx].size = end - start;
  bp->e820_table[idx].type = type;
  bp->e820_entries++;
}

static void e820_memory_setup(struct boot_params *bp) {
  append_e820_table(bp, 0x000000000, 0x000001000, E820_TYPE_RESERVED);
  append_e820_table(bp, 0x000001000, 0x000070000, E820_TYPE_RAM);
  append_e820_table(bp, 0x000070000, 0x0000a0000, E820_TYPE_RESERVED);
  append_e820_table(bp, 0x0000a0000, 0x0000c0000, E820_TYPE_RESERVED);
  append_e820_table(bp, 0x0000c0000, 0x000100000, E820_TYPE_RESERVED); // VBIOS
  append_e820_table(bp, 0x000100000, 0x03fffc000, E820_TYPE_RAM);
  append_e820_table(bp, 0x03fffc000, 0x040000000, E820_TYPE_RESERVED);
  append_e820_table(bp, 0x040000000, 0x060000000, E820_TYPE_RAM);
  append_e820_table(bp, 0x060000000, 0x060800000, E820_TYPE_RESERVED); // MP4
  append_e820_table(bp, 0x060800000, 0x060c00000, E820_TYPE_RESERVED); // VCN FW
  append_e820_table(bp, 0x060c00000, 0x062800000, E820_TYPE_RAM);
  append_e820_table(bp, 0x062800000, 0x064800000, E820_TYPE_RESERVED); // HV
  append_e820_table(bp, 0x064800000, 0x064829000, E820_TYPE_RESERVED); // MP3
  append_e820_table(bp, 0x064829000, 0x07f9d0000, E820_TYPE_RAM);
  append_e820_table(bp, 0x07f9d0000, 0x07fd5f000, E820_TYPE_RESERVED);
  append_e820_table(bp, 0x07fd5f000, 0x07fd63000, E820_TYPE_RESERVED);
  append_e820_table(bp, 0x07fd63000, 0x07fd67000, E820_TYPE_RESERVED);
  append_e820_table(bp, 0x07fd67000, 0x07fd6f000, E820_TYPE_NVS);
  append_e820_table(bp, 0x07fd6f000, 0x07fd8f000, E820_TYPE_ACPI);
  append_e820_table(bp, 0x07fd8f000, 0x07fd90000, E820_TYPE_RESERVED);
  append_e820_table(bp, 0x07fd90000, 0x080000000, E820_TYPE_RESERVED);
  append_e820_table(bp, 0x080000000, 0x0c4400000, E820_TYPE_RESERVED);
  append_e820_table(bp, 0x0d0000000, 0x0e0700000, E820_TYPE_RESERVED);
  append_e820_table(bp, 0x0f0000000, 0x0f8000000, E820_TYPE_RESERVED);
  append_e820_table(bp, 0x100000000, VRAM_BASE, E820_TYPE_RAM);
  append_e820_table(bp, VRAM_BASE, 0x470000000, E820_TYPE_RESERVED); // VRAM
  append_e820_table(bp, 0x470000000, 0x47f300000, E820_TYPE_RAM);
  append_e820_table(bp, 0x47f300000, 0x480000000, E820_TYPE_RESERVED);
}

void boot_linux(void) {
  uintptr_t kernel_pa = 0x100000;
  uintptr_t setup_pa = 0x10000;
  uintptr_t cmdline_pa = 0x20000;

  struct boot_params *bzimage_bp = (struct boot_params *)info.bzimage;

  struct boot_params *bp = (struct boot_params *)setup_pa;
  struct setup_header *shdr = &bp->hdr;

  memset(bp, 0, sizeof(struct boot_params));

  memcpy(shdr, &bzimage_bp->hdr, sizeof(struct setup_header));

  e820_memory_setup(bp);

  shdr->hardware_subarch = X86_SUBARCH_PS5;
  shdr->type_of_loader = 0xff;
  shdr->cmd_line_ptr = cmdline_pa;
  shdr->ramdisk_image = info.initrd & 0xffffffff;
  shdr->ramdisk_size = info.initrd_size & 0xffffffff;
  bp->ext_ramdisk_image = info.initrd >> 32;
  bp->ext_ramdisk_size = info.initrd_size >> 32;
  bp->acpi_rsdp_addr = ACPI_RSDP_ADDRESS;

  strcpy((char *)cmdline_pa, info.cmdline);

  size_t setup_size = (shdr->setup_sects + 1) * 512;
  size_t kernel_size = shdr->syssize * 16;

  memcpy((void *)kernel_pa, (void *)(info.bzimage + setup_size), kernel_size);

  // printf("This is kernel_pa: "); print_val64(kernel_pa); printf("\n");
  void (*startup_64)(uint64_t physaddr, struct boot_params *bp) =
      (void *)(kernel_pa + 0x200);
  startup_64(kernel_pa, bp);
}

void entry(void) {

  disable_intr();

  // Set global interrupt flag.
  __asm__ volatile("stgi\n");

  // Clear SVM flag.
  wrmsr(MSR_EFER, rdmsr(MSR_EFER) & ~EFER_SVM);

  // Disable INIT redirection.
  wrmsr(MSR_VM_CR, rdmsr(MSR_VM_CR) & ~VM_CR_R_INIT);

  // Clean up mtrr.
  wrmsr(MSR_MTRR4kBase + 0, 0);

  wrmsr(MSR_MTRR4kBase + 1, 0);

  wrmsr(MSR_MTRRVarBase + 7 * 2 + 1, 0);

  atomic_add_32(&exited_cpus, 1);

  while (atomic_cmpset_32(&exited_cpus, MAXCPU, MAXCPU) == 0)
    ;

  if (get_cpu() != 0) {
    while (1) {
      halt();
    }
  }

  // Disable IOMMU.
  *(volatile uint64_t *)0xfdd80018 &= ~1;

  memcpy(&info, (void *)(cave_linux_info), sizeof(struct linux_info));

  configure_vram(FB_BASE, VRAM_BASE, info.vram_size);

  printf("[*] Booting Linux in bare metal...\n");
  boot_linux();
}
