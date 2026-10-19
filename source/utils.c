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

/* ------------------------------------------------------------------ H derivation
 * Moved here from hv_defeat_13xx.c (2026-10-18) so prepare_resume.c can call it too, to
 * re-base the HV-absolute offset table fields (HV_HANDLE_VMEXIT_PA, HV_CODE_CAVE_PA) before
 * hv_defeat_13xx() itself runs derive_H() the "real" time. See HV_BASE_REGULAR in utils.h.
 *
 * The carveout base is a RUNTIME value on every console. Our probes measure 0x62800000 on
 * devkit/base; PS5 Pro retail measures ~0x8e0000000 (confirmed 2026-10-18, real hardware). We
 * derive it and let the AP payload range-check every VMCB address against [H, H+0x2029000)
 * before it writes anything. */
#define OFF_PRELOAD_METADATA_DHB 0x3DF1070UL

uint64_t g_hv_carveout_size;

uint64_t derive_hv_base(void) {
  uint64_t pm_off = env_offset.PRELOAD_METADATA ? env_offset.PRELOAD_METADATA
                                               : OFF_PRELOAD_METADATA_DHB;
  uint64_t pm = kread64(ktext + pm_off);
  if (!pm || (pm >> 47) != 0x1FFFF)
    return 0;

  uint64_t p = pm;
  for (int i = 0; i < 64; i++) {
    uint32_t type = kread32(p), len = kread32(p + 4);
    if ((type == 0 && len == 0) || len > 0x10000)
      break;

    if (type == 0x9004) {
      uint64_t hdr = p + 8, msize = kread64(hdr), dsize = kread64(hdr + 8);
      if (dsize >= 0x28 && dsize <= 0x80 && msize && msize < 0x10000) {
        uint64_t d0 = hdr + 0x20, nd = msize / dsize;
        for (uint64_t j = 0; j < nd && j < 64; j++) {
          uint64_t d = d0 + j * dsize;
          uint32_t ty = kread32(d);
          uint64_t phys = kread64(d + 8), npg = kread64(d + 24);
          /* Upper bound raised from 4GB -- see HV_BASE_REGULAR comment in utils.h. */
          if (ty == 0 && npg * 0x1000UL >= 0x1800000UL && npg * 0x1000UL <= 0x4000000UL
              && phys && phys < 0x1000000000ULL) {
            g_hv_carveout_size = npg * 0x1000UL;
            return phys;
          }
        }
      }
    }
    p += 8 + ((len + 7UL) & ~7UL);
  }
  return 0;
}

int setup_env(void) {
  notify("Welcome to ps5-linux-loader. We'll defeat HV and prepare the system "
         "to boot Linux on sleep resume.\n");

  /* Say WHICH build this is. Two ELFs that differ only in behaviour are otherwise
   * indistinguishable in the logs, and an unattributable run is a wasted run. */
#ifndef PS5_BUILD_TAG
#define PS5_BUILD_TAG "untagged"
#endif
  notify("build: " PS5_BUILD_TAG);
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
  case 0x1360:   /* 13.60 retail -- base-SKU and Pro (Pro detected at runtime by SoC id) */
    env_offset = off_1360;
    break;
  default:
    return -1;   /* 13.60-only loader; all other firmware tables were removed in cleanup */
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
  /* pm_pml4 is a direct-map VA, not a physical address. Masking it to 32 bits only works
   * while the kernel PML4 physical happens to sit below 4GB (true on base 13.60, not
   * guaranteed on PS5 Pro). Subtract the direct-map base instead -- same fix as upstream
   * ps5-linux-loader PR #47. */
  uint64_t pa = vtophys_custom(va, self_pml4 - dmap);
  return pa;
}

// for ring0
uint64_t vtophys(uint64_t va) { return vtophys_custom(va, cr3); }

// Source: PS5_kldload
uint64_t vtophys_custom(uint64_t va, uint64_t cr3_custom) {
  /* cr3_custom is already a physical address (pm_cr3, or pm_pml4 - dmap from
   * vtophys_user). Do NOT mask it: on Pro the PML4 can live above 4GB. PR #47. */
  uint64_t table_phys = cr3_custom;

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

/* Reborn's pin convention, required by the khook route in hv_defeat_13xx.
 *
 * byepervisor_reborn's util.c carries this comment verbatim:
 *
 *     // Sony system so code that makes sense must be commented out
 *     //mask[0] = (1 << num);
 *     mask[0] = 1 << (15 - num);
 *
 * Reborn deliberately uses the INVERTED index, and our probe port keeps it "exactly as
 * upstream wrote it". Upstream ps5-linux-loader's pin_to_core above uses the plain `1 << n`
 * that Reborn commented out -- and the two select DIFFERENT cores.
 *
 * This is not cosmetic. Pinning to the wrong core while khook writes common_tss[HOOK_CORE]
 * sets IST6 for one CPU and raises the #DB on another. Measured on this console: the probe
 * with this convention ran mode 0 and mode 1 clean, so it is copied here rather than guessed
 * at. cpuset_setaffinity REFUSES without the kernel_set_ucred_authid elevation -- callers
 * elevate first.
 *
 * The original pin_to_core is left alone because hv_defeat_0304 (3.xx) depends on it. */
int pin_to_core_reborn(int num) {
  uint64_t mask[2] = {};
  cpusetid_t new_id;

  if (cpuset(&new_id))
    return 1;

  mask[0] = 0xFFFF;
  mask[1] = 0;
  cpuset_setaffinity(3, 3, new_id, 8, (const cpuset_t *)mask);

  mask[0] = (uint64_t)1 << (15 - num);
  mask[1] = 0;
  return cpuset_setaffinity(3, 1, -1, 0x10, (const cpuset_t *)mask);
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
  /* Also persist to /data so a headless probe run can be pulled via ftpsrv
   * (notify() is screen-only; this gives a durable log). Append, best-effort. */
  {
    FILE *lf = fopen("/data/ps5lin_probe.log", "a");
    if (lf) { fputs((const char *)buffer, lf); fclose(lf); }
  }
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
  /* PS5 Pro retail: different physical memory layout (HV carveout near 38GB instead of
   * ~1.6GB), needs its own e820 map in shellcode_hv/boot_linux.c and its own HV-code-base
   * offset in hv_defeat_13xx.c/prepare_resume.c. Cross-checked against
   * github.com/ps5-linux/ps5-linux-loader PR #47, 2026-10-18. */
  if (sceKernelGetMainSocId() == SOC_ID_PS5_PRO) {
    notify("PS5 Pro retail console detected\n");
    return KIT_RETAIL_PRO;
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
