#include "utils.h"
#include "offsets.h"
#include <ps5/kernel.h>
#include <stdio.h>
#include <sys/cpuset.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <unistd.h>

/* Global Variables */
offset_list env_offset;
uint64_t ktext;
uint64_t kdata;
uint64_t dmap;
uint64_t cr3;
uint32_t fw;
struct linux_info linux_i;

int set_offsets(void) {
  fw = kernel_get_fw_version() >> 16;
  if (fw == 0)
    return -1;
  switch (fw) {
  case 0x0300:
    env_offset = off_0300;
    break;
  case 0x0310:
    env_offset = off_0310;
    break;
  case 0x0320:
    env_offset = off_0320;
    break;
  case 0x0321:
    env_offset = off_0321;
    break;
  case 0x0400:
    env_offset = off_0400;
    break;
  case 0x0402:
    env_offset = off_0402;
    break;
  case 0x0403:
    env_offset = off_0403;
    break;
  case 0x0450:
    env_offset = off_0450;
    break;
  case 0x0451:
    env_offset = off_0451;
    break;
  default:
    return -1;
  }
  return 0;
}

int init_global_vars(void) {
  ktext = KERNEL_ADDRESS_TEXT_BASE;
  kdata = KERNEL_ADDRESS_DATA_BASE;

  flat_pmap kernel_pmap;
  kread(ktext + env_offset.PMAP_STORE, &kernel_pmap, sizeof(kernel_pmap));
  if (kernel_pmap.pm_pml4 == 0 || kernel_pmap.pm_cr3 == 0)
    return -1;

  cr3 = kernel_pmap.pm_cr3;
  dmap = kernel_pmap.pm_pml4 - kernel_pmap.pm_cr3;

  return 0;
}

uint64_t get_offset_va(uint64_t offset) { return ktext + offset; }

uint64_t get_pml4(uint64_t pmap) { return kread64(pmap + 0x20); }

uint64_t getpmap(uint64_t proc) {
  uint64_t vm = kread64(proc + KERNEL_OFFSET_PROC_P_VMSPACE);
  uint64_t vm_pmap = kread64(vm + env_offset.VMSPACE_VM_PMAP);
  return vm_pmap;
}

// for ring3
uint64_t va_to_pa_user(uint64_t va) {
  uintptr_t self_pmap = getpmap(kernel_get_proc(getpid()));
  uintptr_t self_pml4 = get_pml4(self_pmap);
  uint64_t pa = va_to_pa_custom(va, self_pml4 & 0xFFFFFFFF);
  return pa;
}

// for ring0
uint64_t va_to_pa_kernel(uint64_t va) { return va_to_pa_custom(va, cr3); }

// Source: PS5_kldload
uint64_t va_to_pa_custom(uint64_t va, uint64_t cr3_custom) {

  uint64_t table_phys = cr3_custom & 0xFFFFFFFF;

  for (int level = 0; level < 4; level++) {
    int shift = 39 - (level * 9);
    uint64_t idx = (va >> shift) & 0x1FF;
    uint64_t entry;
    uint64_t entry_va = dmap + PAGE_PA(table_phys) + idx * 8;

    kread(dmap + PAGE_PA(table_phys) + idx * 8, &entry, sizeof(entry));

    if (!PAGE_P(entry))
      return 0;

    if ((level == 1 || level == 2) && PAGE_PS(entry)) {
      uint64_t page_size = P_SIZE(level);
      return PAGE_PA(entry) | (va & (page_size - 1));
    }

    if (level == 3)
      return PAGE_PA(entry) | (va & 0xFFF);

    table_phys = PAGE_PA(entry);
  }
  return 0;
}

uint64_t pa_to_dmap(uint64_t pa) { return dmap + pa; }

// Set RW bit on all levels if needed and remove eXecute Only bit
void page_chain_set_rw(uint64_t va) {

  uint64_t table_phys = cr3;

  for (int level = 0; level < 4; level++) {
    int shift = 39 - (level * 9);
    uint64_t idx = (va >> shift) & 0x1FF;
    uint64_t entry_va = dmap + PAGE_PA(table_phys) + idx * 8;
    uint64_t entry;

    // Read Level X entry
    kread(entry_va, &entry, sizeof(entry));

    if (!PAGE_P(entry))
      return;

    uint8_t update = 0;
    // Set RW bit on this level
    if (!PAGE_RW(entry)) {
      PAGE_SET_RW(entry);
      update = 1;
    }
    // Unset XO on this level
    if (PAGE_XO(entry)) {
      PAGE_CLEAR_XO(entry);
      update = 1;
    }
    if (update) {
      kwrite(entry_va, &entry, sizeof(entry));
    }

    if (((level == 1 || level == 2) && PAGE_PS(entry)) || (level == 3)) {
      return;
    }

    table_phys = PAGE_PA(entry);
  }
  return;
}

// Remove Global bit on last level
uint64_t page_remove_global(uint64_t va) {

  uint64_t table_phys = cr3;

  for (int level = 0; level < 4; level++) {
    int shift = 39 - (level * 9);
    uint64_t idx = (va >> shift) & 0x1FF;
    uint64_t entry_va = dmap + PAGE_PA(table_phys) + idx * 8;
    uint64_t entry;

    // Read Level X entry
    kread(entry_va, &entry, sizeof(entry));

    if (!PAGE_P(entry))
      return 0;

    if ((level == 1 || level == 2) && PAGE_PS(entry)) {
      PAGE_CLEAR_G(entry);
      kwrite(entry_va, &entry, sizeof(entry));

      uint64_t page_size = P_SIZE(level);
      return PAGE_PA(entry) | (va & (page_size - 1));
    }

    if (level == 3) {

      PAGE_CLEAR_G(entry);
      kwrite(entry_va, &entry, sizeof(entry));

      return PAGE_PA(entry) | (va & 0xFFF);
    }

    table_phys = PAGE_PA(entry);
  }
  return 0;
}

int pin_to_core(int n) {
  uint64_t m[2] = {0};
  m[0] = (1 << n);
  return cpuset_setaffinity(3, 1, -1, 0x10, (const cpuset_t *)m);
}

int pin_to_first_available_core(void) {
  for (int i = 0; i < 16; i++)
    if (pin_to_core(i) == 0)
      return i;
  return -1;
}

void unpin(void) {
  uint64_t m[2] = {0xFFFF, 0};
  cpuset_setaffinity(3, 1, -1, 0x10, (const cpuset_t *)m);
}