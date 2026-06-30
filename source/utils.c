#include "utils.h"
#include "linux.h"
#include "offsets.h"
#include <stdio.h>
#include <sys/cpuset.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/stat.h>

/* Global Variables */
offset_list env_offset;
uint64_t ktext;
uint64_t kdata;
uint64_t dmap;
uint64_t cr3;
uint32_t fw;
struct linux_info linux_i;

int setup_env(void) {
  notify("Welcome to ps5-linux-loader. We'll defeat HV and prepare the system "
         "to boot Linux on sleep resume.\n");
  if (set_offsets())
    return -1;
  if (init_global_vars())
    return -1;
  return 0;
}

int set_offsets(void) {
  fw = (kernel_get_fw_version() >> 0x10) & 0xFFFF;
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
  case 0x0500:
    env_offset = off_0500;
    break;
  case 0x0502:
    env_offset = off_0502;
    break;
  case 0x0510:
    env_offset = off_0510;
    break;
  case 0x0550:
    env_offset = off_0550;
    break;
  case 0x0600:
    env_offset = off_0600;
    break;
  case 0x0602:
    env_offset = off_0602;
    break;
  case 0x0720:
    env_offset = off_0720;
    break;
  case 0x0761:
    env_offset = off_0761;
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
  kread(getpmap(kernel_get_proc(0)), &kernel_pmap, sizeof(kernel_pmap));
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
uint64_t vtophys_user(uint64_t va) {
  uintptr_t self_pmap = getpmap(kernel_get_proc(getpid()));
  uintptr_t self_pml4 = get_pml4(self_pmap);
  uint64_t pa = vtophys_custom(va, self_pml4 & 0xFFFFFFFF);
  return pa;
}

// for ring0
uint64_t vtophys(uint64_t va) { return vtophys_custom(va, cr3); }

// Source: PS5_kldload
uint64_t vtophys_custom(uint64_t va, uint64_t cr3_custom) {
  uint64_t table_phys = cr3_custom & 0xFFFFFFFF;

  for (int level = 0; level < 4; level++) {
    int shift = 39 - (level * 9);
    uint64_t idx = (va >> shift) & 0x1FF;
    uint64_t entry;

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

void notify(const char *fmt, ...) {
  static char buffer[2048];
  va_list args;

  va_start(args, fmt);
  vsnprintf(buffer, sizeof(buffer), fmt, args);
  va_end(args);

  notify_internal((uint8_t *)buffer);
  printf("%s", buffer);
}

void notify_internal(uint8_t *msg) {
  struct {
    char pad[45];
    char msg[3075];
  } req;
  bzero(&req, sizeof(req));
  uint64_t len = strlen((const char *)msg) < (sizeof(req.msg) - 1)
                     ? strlen((const char *)msg)
                     : (sizeof(req.msg) - 1);
  memcpy(req.msg, msg, len);
  sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
}

void enter_rest_mode(void) {
  void *event = NULL;
  sceKernelOpenEventFlag(&event, "SceSystemStateMgrStatus");
  sceKernelNotifySystemSuspendStart();
  sceKernelSetEventFlag(event, 0x400);
  sceKernelCloseEventFlag(&event);
}

// Kit type by EchoStretch
bool if_exists(const char *path) {
  struct stat st;
  return stat(path, &st) == 0;
}

bool sceKernelIsTestKit(void) {
  return if_exists("/system/priv/lib/libSceDeci5Ttyp.sprx");
}

bool sceKernelIsDevKit(void) {
  return if_exists("/system/priv/lib/libSceDeci5Dtracep.sprx");
}

enum kit_type get_kit_type(void) {
  if (sceKernelIsDevKit()) {
    notify("DevKit detected\n");
    return KIT_DEVKIT;
  }
  if (sceKernelIsTestKit()) {
    notify("TestKit detected\n");
    return KIT_TESTKIT;
  }
  notify("Retail console detected\n");
  return KIT_RETAIL;
}

uint64_t alloc_page(void) {
  void *page = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                    MAP_SHARED | MAP_ANONYMOUS, -1, 0);

  // Fault it to force physical allocation
  *(uint8_t *)page = 0;

  return vtophys_user((uintptr_t)page);
}

void install_page(uintptr_t pml4, vm_offset_t va, vm_paddr_t pa, int bits) {
  uint64_t entry;

  uintptr_t pml4e = pml4 + pmap_pml4e_index(va) * 8;
  entry = kread64(pml4e);
  if (!PAGE_P(entry)) {
    uint64_t page = alloc_page();
    entry = page | PG_B_RW | PG_B_P | bits;
    kwrite64(pml4e, entry);
  }

  uintptr_t pdpe = pa_to_dmap(PAGE_PA(entry)) + pmap_pdpe_index(va) * 8;
  entry = kread64(pdpe);
  if (!(entry & PG_B_P)) {
    uint64_t page = alloc_page();
    entry = page | PG_B_RW | PG_B_P | bits;
    kwrite64(pdpe, entry);
  }

  uintptr_t pde = pa_to_dmap(PAGE_PA(entry)) + pmap_pde_index(va) * 8;
  entry = kread64(pde);
  if (!(entry & PG_B_P)) {
    uint64_t page = alloc_page();
    entry = page | PG_B_RW | PG_B_P | bits;
    kwrite64(pde, entry);
  }

  uintptr_t pte = pa_to_dmap(PAGE_PA(entry)) + pmap_pte_index(va) * 8;
  entry = pa | PG_B_RW | PG_B_P | bits;
  pte_store(pte, entry);
}

void pte_store(uintptr_t ptep, uint64_t pte) {
  static_assert((PAGE_SIZE % 0x1000) == 0,
                "PAGE_SIZE should be a multiple of 0x1000");

  for (uint64_t i = 0; i < (PAGE_SIZE / 0x1000); i++) {
    kwrite64(ptep + i * 8, pte + i * 0x1000);
  }
}

void install_page_syscore(vm_offset_t va, vm_paddr_t pa, int bits) {
  uintptr_t syscore_pmap = getpmap(kernel_get_proc(MINI_SYSCORE_PID));
  uintptr_t syscore_pml4 = kread64(syscore_pmap + 0x20);
  install_page(syscore_pml4, va, pa, bits);
}
