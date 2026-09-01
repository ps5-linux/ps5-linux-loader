#include "boot_linux.h"
#include "../include/config_0250.h"
#include "../include/linux.h"
#include "exceptions.h"
#include "utils.h"
#include <stdint.h>

static struct linux_info info;
static volatile uint32_t exited_cpus;
static volatile uint32_t entered_cpu_mask;
static volatile uint32_t ready_cpu_mask;
static volatile uint32_t barrier_reported;

#define BARRIER_TIMEOUT 0x10000000U

#define PCI_CONFIG_ADDRESS 0xCF8U
#define PCI_CONFIG_DATA 0xCFCU
#define PCI_COMMAND_MASTER 0x0004U
#define ARIEL_ZCN_BUS 0x20U
#define ARIEL_ZCN_DEVICE 0U
#define ARIEL_ZCN_FUNCTION 3U
#define ARIEL_ZCN_ID 0x13EF1022U

_Static_assert(sizeof(struct boot_params) == 0x1000,
               "Linux boot_params layout changed");
_Static_assert(offsetof(struct boot_params, acpi_rsdp_addr) == 0x70,
               "Linux acpi_rsdp_addr offset changed");
_Static_assert(offsetof(struct boot_params, ext_ramdisk_image) == 0xC0,
               "Linux ext_ramdisk_image offset changed");
_Static_assert(offsetof(struct boot_params, e820_entries) == 0x1E8,
               "Linux e820_entries offset changed");
_Static_assert(offsetof(struct boot_params, hdr) == 0x1F1,
               "Linux setup_header offset changed");
_Static_assert(offsetof(struct boot_params, e820_table) == 0x2D0,
               "Linux e820_table offset changed");

static void outl(uint16_t port, uint32_t value) {
  __asm__ volatile("outl %0, %w1" : : "a"(value), "Nd"(port));
}

static uint32_t inl(uint16_t port) {
  uint32_t value;
  __asm__ volatile("inl %w1, %0" : "=a"(value) : "Nd"(port));
  return value;
}

static uint32_t pci_config_address(uint8_t bus, uint8_t device,
                                   uint8_t function, uint8_t offset) {
  return 0x80000000U | ((uint32_t)bus << 16) |
         ((uint32_t)device << 11) | ((uint32_t)function << 8) |
         (offset & 0xFCU);
}

static uint32_t pci_read32(uint8_t bus, uint8_t device, uint8_t function,
                           uint8_t offset) {
  outl(PCI_CONFIG_ADDRESS,
       pci_config_address(bus, device, function, offset));
  return inl(PCI_CONFIG_DATA);
}

static void pci_write32(uint8_t bus, uint8_t device, uint8_t function,
                        uint8_t offset, uint32_t value) {
  outl(PCI_CONFIG_ADDRESS,
       pci_config_address(bus, device, function, offset));
  outl(PCI_CONFIG_DATA, value);
}

static int quiesce_ariel_zcn(uint8_t cpu) {
  uint32_t id = pci_read32(ARIEL_ZCN_BUS, ARIEL_ZCN_DEVICE,
                           ARIEL_ZCN_FUNCTION, 0x00);
  uint32_t class_revision = pci_read32(
      ARIEL_ZCN_BUS, ARIEL_ZCN_DEVICE, ARIEL_ZCN_FUNCTION, 0x08);
  uint32_t command_status = pci_read32(
      ARIEL_ZCN_BUS, ARIEL_ZCN_DEVICE, ARIEL_ZCN_FUNCTION, 0x04);

  uart_trace(0x04, cpu, id);
  uart_trace(0x05, cpu, class_revision);
  uart_trace(0x06, cpu, command_status & 0xFFFFU);
  if (id != ARIEL_ZCN_ID || (class_revision >> 24) != 0x10U)
    return -1;

  pci_write32(ARIEL_ZCN_BUS, ARIEL_ZCN_DEVICE, ARIEL_ZCN_FUNCTION, 0x04,
              (command_status & 0xFFFFU) & ~PCI_COMMAND_MASTER);
  command_status = pci_read32(ARIEL_ZCN_BUS, ARIEL_ZCN_DEVICE,
                              ARIEL_ZCN_FUNCTION, 0x04);
  uart_trace(0x07, cpu, command_status & 0xFFFFU);
  return (command_status & PCI_COMMAND_MASTER) ? -1 : 0;
}

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

static void append_e820(struct boot_params *bp, uint64_t start, uint64_t end,
                        uint32_t type) {
  if (bp->e820_entries >= E820_MAX_ENTRIES_ZEROPAGE || start >= end)
    return;
  uint8_t index = bp->e820_entries++;
  bp->e820_table[index].addr = start;
  bp->e820_table[index].size = end - start;
  bp->e820_table[index].type = type;
}

static void setup_e820(struct boot_params *bp) {
  append_e820(bp, 0x000000000, 0x000001000, E820_TYPE_RESERVED);
  append_e820(bp, 0x000001000, 0x000070000, E820_TYPE_RAM);
  append_e820(bp, 0x000070000, 0x000100000, E820_TYPE_RESERVED);
  append_e820(bp, 0x000100000, 0x03fffc000, E820_TYPE_RAM);
  append_e820(bp, 0x03fffc000, 0x040000000, E820_TYPE_RESERVED);
  append_e820(bp, 0x040000000, 0x060000000, E820_TYPE_RAM);
  append_e820(bp, 0x060000000, 0x060800000, E820_TYPE_RESERVED);
  append_e820(bp, 0x060800000, 0x060c00000, E820_TYPE_RESERVED);
  append_e820(bp, 0x060c00000, 0x062800000, E820_TYPE_RAM);
  append_e820(bp, 0x062800000, 0x064800000, E820_TYPE_RESERVED);
  append_e820(bp, 0x064800000, 0x064829000, E820_TYPE_RESERVED);
  append_e820(bp, 0x064829000, 0x07f9d0000, E820_TYPE_RAM);
  append_e820(bp, 0x07f9d0000, 0x07fd67000, E820_TYPE_RESERVED);
  append_e820(bp, 0x07fd67000, 0x07fd6f000, E820_TYPE_NVS);
  append_e820(bp, 0x07fd6f000, 0x07fd8f000, E820_TYPE_ACPI);
  append_e820(bp, 0x07fd8f000, 0x080000000, E820_TYPE_RESERVED);
  append_e820(bp, 0x080000000, 0x0c4400000, E820_TYPE_RESERVED);
  append_e820(bp, 0x0d0000000, 0x0e0700000, E820_TYPE_RESERVED);
  append_e820(bp, 0x0f0000000, 0x0f8000000, E820_TYPE_RESERVED);
  append_e820(bp, 0x100000000, VRAM_BASE, E820_TYPE_RAM);
  append_e820(bp, VRAM_BASE, 0x470000000, E820_TYPE_RESERVED);

  if (info.kit_type == KIT_DEVKIT) {
    append_e820(bp, 0x470000000, 0x87f300000, E820_TYPE_RAM);
    append_e820(bp, 0x87f300000, 0x880000000, E820_TYPE_RESERVED);
  } else {
    append_e820(bp, 0x470000000, 0x47f300000, E820_TYPE_RAM);
    append_e820(bp, 0x47f300000, 0x480000000, E820_TYPE_RESERVED);
  }
}

static int start_linux(void) {
  const uintptr_t kernel_pa = 0x100000;
  const uintptr_t setup_pa = 0x10000;
  const uintptr_t cmdline_pa = 0x20000;
  struct boot_params *image = (struct boot_params *)info.bzimage;
  struct boot_params *bp = (struct boot_params *)setup_pa;
  struct setup_header *header = &bp->hdr;

  if (info.bzimage != cave_bzImage || info.initrd < info.bzimage ||
      info.bzimage > hv_stack_floor || info.initrd > hv_stack_floor ||
      info.bzimage_size < 0x240 || !info.initrd_size ||
      info.bzimage_size > hv_stack_floor - info.bzimage ||
      info.initrd_size > hv_stack_floor - info.initrd ||
      info.kit_type < KIT_RETAIL || info.kit_type > KIT_DEVKIT ||
      info.cmdline[sizeof(info.cmdline) - 1] != '\0' ||
      image->hdr.boot_flag != 0xAA55 || image->hdr.header != 0x53726448 ||
      image->hdr.version < 0x020C || (image->hdr.loadflags & 1) == 0 ||
      (image->hdr.xloadflags & 3) != 3 || !image->hdr.init_size)
    return -1;

  zero_bytes(bp, sizeof(*bp));
  copy_bytes(header, &image->hdr, sizeof(*header));
  setup_e820(bp);

  header->hardware_subarch = X86_SUBARCH_PS5;
  header->hardware_subarch_data = 0;
  header->setup_data = 0;
  header->type_of_loader = 0xFF;
  header->cmd_line_ptr = cmdline_pa;
  header->ramdisk_image = (uint32_t)info.initrd;
  header->ramdisk_size = (uint32_t)info.initrd_size;
  bp->ext_ramdisk_image = (uint32_t)(info.initrd >> 32);
  bp->ext_ramdisk_size = (uint32_t)(info.initrd_size >> 32);
  bp->acpi_rsdp_addr = ACPI_RSDP_ADDRESS;

  copy_bytes((void *)cmdline_pa, info.cmdline, sizeof(info.cmdline));

  uint8_t setup_sects = header->setup_sects ? header->setup_sects : 4;
  uint64_t setup_size = ((uint64_t)setup_sects + 1) * 512;
  uint64_t kernel_size = (uint64_t)header->syssize * 16;
  if (!kernel_size || setup_size + kernel_size > info.bzimage_size ||
      image->hdr.init_size > 0x3FFFC000U - kernel_pa)
    return -2;

  copy_bytes((void *)kernel_pa, (const void *)(info.bzimage + setup_size),
             kernel_size);
  uart_trace(3, 0, (uint32_t)kernel_size);

  void (*startup_64)(uint64_t, struct boot_params *) =
      (void *)(kernel_pa + 0x200);
  startup_64(kernel_pa, bp);
  return -3;
}

void entry(uint32_t cpu) {
  uint32_t cpu_bit = 1U << cpu;
  atomic_or_32(&entered_cpu_mask, cpu_bit);
  install_exception_idt();
  disable_intr();
  activate_uart();

  __asm__ volatile("stgi");
  wrmsr(MSR_EFER, rdmsr(MSR_EFER) & ~EFER_SVM);
  wrmsr(MSR_VM_CR, rdmsr(MSR_VM_CR) & ~VM_CR_R_INIT);
  wrmsr(MSR_MTRR4kBase + 0, 0);
  wrmsr(MSR_MTRR4kBase + 1, 0);
  wrmsr(MSR_MTRRVarBase + 7 * 2 + 1, 0);

  atomic_or_32(&ready_cpu_mask, cpu_bit);
  atomic_add_32(&exited_cpus, 1);
  uint32_t timeout = BARRIER_TIMEOUT;
  while (atomic_load_32(&exited_cpus) != MAXCPU && --timeout)
    __asm__ volatile("pause");

  if (!timeout) {
    if (__sync_bool_compare_and_swap(&barrier_reported, 0, 1)) {
      uart_trace(0xB0, (uint8_t)cpu, entered_cpu_mask);
      uart_trace(0xB1, (uint8_t)cpu, ready_cpu_mask);
      uart_trace(0xB2, (uint8_t)cpu, exited_cpus);
      volatile uint32_t *handoff_audit =
          (volatile uint32_t *)cave_hv_audit;
      uart_trace(0xB3, (uint8_t)cpu,
                 handoff_audit[HV_AUDIT_CALLBACK_MASK]);
      uart_trace(0xB4, (uint8_t)cpu,
                 handoff_audit[HV_AUDIT_ENTRY_MASK]);
      uart_trace(0xB5, (uint8_t)cpu,
                 handoff_audit[HV_AUDIT_RETURN_MASK]);
    }
    for (;;)
      halt();
  }

  if (cpu != 0) {
    for (;;)
      halt();
  }

  uart_trace(2, cpu, exited_cpus);
  if (quiesce_ariel_zcn(cpu)) {
    uart_emergency("[H25:EP]\n");
    for (;;)
      halt();
  }
  volatile uint64_t *iommu_control =
      (volatile uint64_t *)(AMDIOMMU_MMIO_BASE + AMDIOMMU_CTRL);
  *iommu_control &= ~1ULL;
  if (*iommu_control & 1ULL) {
    uart_emergency("[H25:EI]\n");
    for (;;)
      halt();
  }
  copy_bytes(&info, (const void *)cave_linux_info, sizeof(info));
  if (info.vram_size < 0x04000000ULL || info.vram_size > 0x40000000ULL ||
      (info.vram_size & 0x00FFFFFFULL)) {
    uart_emergency("[H25:EV]\n");
    for (;;)
      halt();
  }
  configure_vram(FB_BASE, VRAM_BASE, info.vram_size);

  int result = start_linux();
  if (result) {
    uart_trace(0xE0, cpu, (uint32_t)-result);
    uart_emergency("[H25:EE]\n");
  }
  for (;;)
    halt();
}
