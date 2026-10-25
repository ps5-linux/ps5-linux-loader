#include "loader_staging_1160.h"

#include "config.h"
#include "utils.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define X86_PAGE_SIZE 0x1000ULL
#define TABLE_FLAGS (PG_B_P | PG_B_RW)
#define MAX_COMBINED_MAPPING (160ULL * 1024ULL * 1024ULL)

static_assert(PAGE_SIZE == X86_PAGE_SIZE * 4,
              "11.60 staging requires four 4-KiB frames per logical page");

/*
 * The wake blob writes [cave, cave_bzImage + bzImage + initrd) through DMAP
 * before Linux starts: HV page tables and code, linux_info, bzImage, initrd.
 * The larger the boot files, the more of memory this covers, so refuse
 * anything the blob still needs that the copy would overwrite first: a source
 * page, linux_info, the alias and DMAP page tables, PID 1's PML4, the kernel
 * code cave the blob runs from and its #SX stack.
 */
static_assert(cave_bzImage + MAX_COMBINED_MAPPING <=
                  hv_base_rsp - hv_stack_size,
              "staged Linux files would reach the HV stacks");
static_assert(cave_bzImage + MAX_COMBINED_MAPPING <= cave + 0x40000000ULL,
              "staged Linux files would leave the HV identity leaf");

/* CODE_CAVE_CAPACITY in hv_defeat_1160.c; the Makefile holds the wake blob,
 * with its args and globals, to the same 20480 bytes. */
#define WAKE_CAVE_SIZE_1160 0x5000ULL
#define SX_STACK_BATCH_1160 16
#define SX_STACK_ROUNDS_1160 8
#define TABLE_ATTEMPTS_1160 16

static uint64_t wake_copy_end_1160;
/* Taken in take_sx_stack_page_1160, before any write. */
static uint64_t sx_stack_pa_1160;
/* Set when a refusal is about something that stays put until a reboot. */
static int refused_until_reboot_1160;

/* Nonzero when the 16-KiB page at pa overlaps the range the wake blob copies
 * Linux into. Valid after stage_linux_aliases_1160 has started. */
static int pa_in_wake_copy_1160(uint64_t pa) {
  return wake_copy_end_1160 != 0 && pa < wake_copy_end_1160 &&
         pa + PAGE_SIZE > cave;
}

int pa_under_sx_stack_1160(uint64_t pa) {
  return sx_stack_pa_1160 != 0 && pa < sx_stack_pa_1160 &&
         pa + PAGE_SIZE > sx_stack_pa_1160 - PAGE_SIZE;
}

uint64_t sx_stack_page_1160(void) { return sx_stack_pa_1160; }

/*
 * The copy runs forward: linux_info, then bzImage and initrd page by page, so
 * logical page i >= 1 lands at cave_bzImage + (i - 1) * PAGE_SIZE.  A bzImage
 * or initrd page is read before the copy reaches anything at or above the end
 * of its own destination.  linux_info, which also holds the MP3 buffers, is
 * used until Linux starts and has to be outside the whole range.
 */
static int source_overwritten_1160(size_t i, uint64_t pa) {
  if (i == 0)
    return pa_in_wake_copy_1160(pa);
  return pa + PAGE_SIZE > cave && pa < cave_bzImage + i * PAGE_SIZE;
}

struct alias_page_1160 {
  uint64_t target_va;
  const uint8_t *source;
  uint64_t source_pa;
};

struct journal_entry_1160 {
  uint64_t entry_va;
  uint64_t old_value;
};

struct owned_table_1160 {
  void *mapping;
  uint64_t pa;
};

struct alias_tx_1160 {
  uint64_t syscore_pml4;
  uint64_t source_pml4;
  struct journal_entry_1160 *journal;
  size_t journal_count;
  size_t journal_capacity;
  struct owned_table_1160 *tables;
  size_t table_count;
  size_t table_capacity;
};

struct retained_staging_1160 {
  void *bzimage;
  size_t bzimage_mapping_size;
  void *initrd;
  size_t initrd_mapping_size;
  void *info_page;
  struct alias_tx_1160 tx;
  int active;
};

/* One successful loader invocation owns these mappings until rest/wake. */
static struct retained_staging_1160 retained_staging;

static int add_size(size_t a, size_t b, size_t *out) {
  if (a > SIZE_MAX - b)
    return -1;
  *out = a + b;
  return 0;
}

static int read_kernel(uint64_t address, void *value, size_t size) {
  memset(value, 0, size);
  return kernel_copyout(address, value, size) == 0 ? 0 : -1;
}

static int write_kernel(uint64_t address, const void *value, size_t size) {
  return kernel_copyin(value, address, size) == 0 ? 0 : -1;
}

static int read_entry(uint64_t entry_va, uint64_t *value) {
  return read_kernel(entry_va, value, sizeof(*value));
}

static int is_kernel_pointer(uint64_t value) {
  return value >= 0xFFFF800000000000ULL;
}

static int get_proc_pmap_checked(pid_t pid, flat_pmap *flat_out) {
  uint64_t proc = kernel_get_proc(pid);
  uint64_t vmspace = 0;
  uint64_t pmap = 0;
  flat_pmap flat;

  memset(&flat, 0, sizeof(flat));
  if (!is_kernel_pointer(proc) ||
      read_entry(proc + KERNEL_OFFSET_PROC_P_VMSPACE, &vmspace) ||
      !is_kernel_pointer(vmspace) ||
      read_entry(vmspace + env_offset.VMSPACE_VM_PMAP, &pmap) ||
      !is_kernel_pointer(pmap) || (pmap & 7) != 0 ||
      read_kernel(pmap, &flat, sizeof(flat)) ||
      !is_kernel_pointer(flat.pm_pml4) ||
      (flat.pm_pml4 & (X86_PAGE_SIZE - 1)) != 0 || !flat.pm_cr3 ||
      (flat.pm_cr3 & (X86_PAGE_SIZE - 1)) != 0 ||
      PAGE_PA(flat.pm_cr3) != flat.pm_cr3 || flat.pm_pml4 <= flat.pm_cr3 ||
      flat.pm_pml4 - flat.pm_cr3 != dmap)
    return -1;

  *flat_out = flat;
  return 0;
}

static int translate_user_checked(uint64_t pml4, uint64_t va,
                                  uint64_t *pa_out) {
  uint64_t table_va = pml4;

  for (int level = 0; level < 4; level++) {
    int shift = 39 - level * 9;
    uint64_t entry = 0;
    uint64_t entry_va = table_va + ((va >> shift) & 0x1FF) * 8;

    if (read_entry(entry_va, &entry) || !PAGE_P(entry))
      return -1;
    if ((level == 1 || level == 2) && PAGE_PS(entry)) {
      uint64_t page_size = P_SIZE(level);
      *pa_out = PAGE_PA(entry) | (va & (page_size - 1));
      return 0;
    }
    if (level == 3) {
      *pa_out = PAGE_PA(entry) | (va & (X86_PAGE_SIZE - 1));
      return 0;
    }
    table_va = pa_to_dmap(PAGE_PA(entry));
  }
  return -1;
}

/* Validate all four hardware frames, including their bytes through DMAP. */
static int source_page_pa(uint64_t source_pml4, const uint8_t *source,
                          uint64_t *base_pa) {
  uint8_t physical[X86_PAGE_SIZE];
  uint64_t first = 0;

  if (((uintptr_t)source & (PAGE_SIZE - 1)) != 0)
    return -1;
  for (size_t sub = 0; sub < PAGE_SIZE; sub += X86_PAGE_SIZE) {
    uint64_t pa = 0;
    if (translate_user_checked(source_pml4, (uint64_t)(uintptr_t)source + sub,
                               &pa) ||
        !pa || (pa & (X86_PAGE_SIZE - 1)))
      return -1;
    if (sub == 0)
      first = pa;
    else if (pa != first + sub)
      return -1;
    if (read_kernel(pa_to_dmap(pa), physical, sizeof(physical)) ||
        memcmp(physical, source + sub, sizeof(physical)) != 0)
      return -1;
  }
  *base_pa = first;
  return 0;
}

/* A missing parent means every descendant is absent; large parents refuse. */
static int lookup_pte(uint64_t pml4, uint64_t va, uint64_t *pte_va,
                      int *absent) {
  uint64_t entry = 0;
  uint64_t entry_va;

  *absent = 0;
  entry_va = pml4 + pmap_pml4e_index(va) * 8;
  if (read_entry(entry_va, &entry))
    return -1;
  if (!PAGE_P(entry)) {
    *absent = 1;
    return 0;
  }

  entry_va = pa_to_dmap(PAGE_PA(entry)) + pmap_pdpe_index(va) * 8;
  if (read_entry(entry_va, &entry))
    return -1;
  if (!PAGE_P(entry)) {
    *absent = 1;
    return 0;
  }
  if (PAGE_PS(entry))
    return -1;

  entry_va = pa_to_dmap(PAGE_PA(entry)) + pmap_pde_index(va) * 8;
  if (read_entry(entry_va, &entry))
    return -1;
  if (!PAGE_P(entry)) {
    *absent = 1;
    return 0;
  }
  if (PAGE_PS(entry))
    return -1;

  *pte_va = pa_to_dmap(PAGE_PA(entry)) + pmap_pte_index(va) * 8;
  return 0;
}

static int preflight_target_page(uint64_t pml4, uint64_t va) {
  for (size_t sub = 0; sub < PAGE_SIZE; sub += X86_PAGE_SIZE) {
    uint64_t pte_va = 0;
    uint64_t pte = 0;
    int absent = 0;

    if (lookup_pte(pml4, va + sub, &pte_va, &absent))
      return -1;
    if (!absent && (read_entry(pte_va, &pte) || PAGE_P(pte)))
      return -1;
  }
  return 0;
}

static int tx_init(struct alias_tx_1160 *tx, size_t alias_pages) {
  flat_pmap syscore_flat;
  flat_pmap source_flat;
  size_t leaf_entries;

  memset(tx, 0, sizeof(*tx));
  if (get_proc_pmap_checked(MINI_SYSCORE_PID, &syscore_flat) ||
      get_proc_pmap_checked(getpid(), &source_flat) ||
      syscore_flat.pm_pml4 == source_flat.pm_pml4)
    return -1;

  tx->syscore_pml4 = syscore_flat.pm_pml4;
  tx->source_pml4 = source_flat.pm_pml4;
  if (alias_pages > SIZE_MAX / (PAGE_SIZE / X86_PAGE_SIZE))
    return -1;
  leaf_entries = alias_pages * (PAGE_SIZE / X86_PAGE_SIZE);
  if (leaf_entries > SIZE_MAX - 1024)
    return -1;
  tx->journal_capacity = leaf_entries + 1024;
  tx->journal = calloc(tx->journal_capacity, sizeof(*tx->journal));
  if (!tx->journal)
    return -1;

  tx->table_capacity = alias_pages / 128 + 16;
  tx->tables = calloc(tx->table_capacity, sizeof(*tx->tables));
  if (!tx->tables) {
    free(tx->journal);
    memset(tx, 0, sizeof(*tx));
    return -1;
  }
  return 0;
}

static int tx_write(struct alias_tx_1160 *tx, uint64_t entry_va,
                    uint64_t new_value) {
  uint64_t old_value = 0;
  uint64_t observed = 0;

  if (tx->journal_count >= tx->journal_capacity ||
      read_entry(entry_va, &old_value))
    return -1;
  tx->journal[tx->journal_count].entry_va = entry_va;
  tx->journal[tx->journal_count].old_value = old_value;
  tx->journal_count++;
  if (write_kernel(entry_va, &new_value, sizeof(new_value)) ||
      read_entry(entry_va, &observed) || observed != new_value)
    return -1;
  return 0;
}

static int tx_alloc_table(struct alias_tx_1160 *tx, uint64_t *pa_out) {
  void *mapping = MAP_FAILED;
  uint64_t pa = 0;
  int attempt;

  if (tx->table_count >= tx->table_capacity)
    return -1;
  /* A page in the copy range is left mapped so the next mmap differs. */
  for (attempt = 0; attempt < TABLE_ATTEMPTS_1160; attempt++) {
    mapping = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED)
      return -1;
    memset(mapping, 0, PAGE_SIZE);
    if (source_page_pa(tx->source_pml4, mapping, &pa)) {
      munmap(mapping, PAGE_SIZE);
      return -1;
    }
    if (!pa_in_wake_copy_1160(pa) && !pa_under_sx_stack_1160(pa))
      break;
  }
  /* This can come after alias writes, which the caller then rolls back. */
  if (attempt == TABLE_ATTEMPTS_1160) {
    notify("11.60 loader refused staging: alias table page 0x%llx is inside "
           "the Linux copy range or under the #SX stack page.\n",
           (unsigned long long)pa);
    fflush(stdout);
    return -1;
  }
  tx->tables[tx->table_count].mapping = mapping;
  tx->tables[tx->table_count].pa = pa;
  tx->table_count++;
  *pa_out = pa;
  return 0;
}

static int ensure_child_table(struct alias_tx_1160 *tx, uint64_t entry_va,
                              int reject_large, uint64_t *child_pa) {
  uint64_t entry = 0;
  uint64_t pa = 0;

  if (read_entry(entry_va, &entry))
    return -1;
  if (PAGE_P(entry)) {
    if (reject_large && PAGE_PS(entry))
      return -1;
    *child_pa = PAGE_PA(entry);
    return 0;
  }
  if (tx_alloc_table(tx, &pa) || tx_write(tx, entry_va, pa | TABLE_FLAGS))
    return -1;
  *child_pa = pa;
  return 0;
}

static int tx_install_page(struct alias_tx_1160 *tx,
                           const struct alias_page_1160 *page) {
  uint64_t entry_va;
  uint64_t child_pa;

  entry_va = tx->syscore_pml4 + pmap_pml4e_index(page->target_va) * 8;
  if (ensure_child_table(tx, entry_va, 0, &child_pa))
    return -1;
  entry_va = pa_to_dmap(child_pa) + pmap_pdpe_index(page->target_va) * 8;
  if (ensure_child_table(tx, entry_va, 1, &child_pa))
    return -1;
  entry_va = pa_to_dmap(child_pa) + pmap_pde_index(page->target_va) * 8;
  if (ensure_child_table(tx, entry_va, 1, &child_pa))
    return -1;

  entry_va = pa_to_dmap(child_pa) + pmap_pte_index(page->target_va) * 8;
  for (size_t sub = 0; sub < PAGE_SIZE; sub += X86_PAGE_SIZE) {
    uint64_t pte_va = entry_va + (sub / X86_PAGE_SIZE) * 8;
    uint64_t old_pte = 0;
    if (read_entry(pte_va, &old_pte) || PAGE_P(old_pte) ||
        tx_write(tx, pte_va, page->source_pa + sub + TABLE_FLAGS))
      return -1;
  }
  return 0;
}

static int translate_target(const struct alias_tx_1160 *tx, uint64_t va,
                            uint64_t *pa_out) {
  uint64_t pte_va = 0;
  uint64_t pte = 0;
  int absent = 0;

  if (lookup_pte(tx->syscore_pml4, va, &pte_va, &absent) || absent ||
      read_entry(pte_va, &pte) || !PAGE_P(pte))
    return -1;
  *pa_out = PAGE_PA(pte) | (va & (X86_PAGE_SIZE - 1));
  return 0;
}

static int verify_aliases(const struct alias_tx_1160 *tx,
                          const struct alias_page_1160 *pages,
                          size_t page_count) {
  for (size_t i = 0; i < page_count; i++) {
    for (size_t sub = 0; sub < PAGE_SIZE; sub += X86_PAGE_SIZE) {
      uint64_t pa = 0;
      if (translate_target(tx, pages[i].target_va + sub, &pa) ||
          pa != pages[i].source_pa + sub)
        return -1;
    }
  }
  return 0;
}

static int tx_rollback(struct alias_tx_1160 *tx) {
  int failed = 0;

  for (size_t i = tx->journal_count; i > 0; i--) {
    const struct journal_entry_1160 *entry = &tx->journal[i - 1];
    if (write_kernel(entry->entry_va, &entry->old_value,
                     sizeof(entry->old_value)))
      failed = 1;
  }
  for (size_t i = 0; i < tx->journal_count; i++) {
    const struct journal_entry_1160 *entry = &tx->journal[i];
    uint64_t observed = 0;
    if (read_entry(entry->entry_va, &observed) || observed != entry->old_value)
      failed = 1;
  }
  return failed ? -1 : 0;
}

static int verify_targets_absent(const struct alias_tx_1160 *tx,
                                 const struct alias_page_1160 *pages,
                                 size_t page_count) {
  for (size_t i = 0; i < page_count; i++) {
    for (size_t sub = 0; sub < PAGE_SIZE; sub += X86_PAGE_SIZE) {
      uint64_t pte_va = 0;
      uint64_t pte = 0;
      int absent = 0;
      if (lookup_pte(tx->syscore_pml4, pages[i].target_va + sub, &pte_va,
                     &absent))
        return -1;
      if (!absent && (read_entry(pte_va, &pte) || PAGE_P(pte)))
        return -1;
    }
  }
  return 0;
}

static void tx_release_backing(struct alias_tx_1160 *tx) {
  for (size_t i = 0; i < tx->table_count; i++) {
    munmap(tx->tables[i].mapping, PAGE_SIZE);
  }
  free(tx->tables);
  free(tx->journal);
  memset(tx, 0, sizeof(*tx));
}

[[noreturn]] static void hold_after_rollback_failure(void) {
  notify("11.60 staging rollback failed; cold reboot required\n");
  while (1)
    sleep(30);
}

/* Page tables and the code cave stay where they are until a reboot, so a
 * refusal for the copy range needs one.  The #SX stack page is new on every
 * run, so a refusal for the page under it does not. */
static int refuse_in_wake_copy_1160(const char *what, uint64_t pa) {
  if (pa_in_wake_copy_1160(pa)) {
    refused_until_reboot_1160 = 1;
    notify("11.60 loader refused staging: %s 0x%llx is inside the Linux copy "
           "range. Reboot before trying again.\n",
           what, (unsigned long long)pa);
    fflush(stdout);
    return 1;
  }
  if (pa_under_sx_stack_1160(pa)) {
    notify("11.60 loader refused staging: %s 0x%llx is under the #SX stack "
           "page.\n",
           what, (unsigned long long)pa);
    fflush(stdout);
    return 1;
  }
  return 0;
}

/* The alias tables that exist already; ensure_child_table reuses them. */
static int check_alias_tables_1160(uint64_t pml4, uint64_t va) {
  uint64_t table_va = pml4;

  for (int level = 0; level < 3; level++) {
    uint64_t entry = 0;
    int shift = 39 - level * 9;

    if (read_entry(table_va + ((va >> shift) & 0x1FF) * 8, &entry))
      return -1;
    if (!PAGE_P(entry))
      return 0;
    if (PAGE_PS(entry) ||
        refuse_in_wake_copy_1160("page table", PAGE_PA(entry)))
      return -1;
    table_va = pa_to_dmap(PAGE_PA(entry));
  }
  return 0;
}

/* Walks a mapped va, refusing any table on the way.  Returns the physical
 * address and the end of the mapping that holds it. */
static int walk_wake_mapping_1160(uint64_t pml4, uint64_t va, uint64_t *pa_out,
                                  uint64_t *next) {
  uint64_t table_va = pml4;

  for (int level = 0; level < 4; level++) {
    uint64_t entry = 0;
    int shift = 39 - level * 9;
    uint64_t size = 1ULL << shift;

    if (read_entry(table_va + ((va >> shift) & 0x1FF) * 8, &entry) ||
        !PAGE_P(entry))
      return -1;
    if (level == 3 || ((level == 1 || level == 2) && PAGE_PS(entry))) {
      *pa_out = (PAGE_PA(entry) & ~(size - 1)) | (va & (size - 1));
      *next = (va & ~(size - 1)) + size;
      return 0;
    }
    if (refuse_in_wake_copy_1160("page table", PAGE_PA(entry)))
      return -1;
    table_va = pa_to_dmap(PAGE_PA(entry));
  }
  return -1;
}

/*
 * The ROP chain leaves rsp at sx_ist + 0x1040, so the wake blob runs on this
 * page while it copies Linux, and past 0x1040 bytes its stack runs into the
 * page under it.  Both pages are taken from one batch of fresh pages before
 * any write, as a physically adjacent pair, so the page under the stack page
 * is ours and nothing allocated later can land there.  Neither page may be in
 * the copy range, and the DMAP tables that map them are walked like the
 * copy's.  The alias tables (tx_alloc_table), the tables and code cave the
 * blob uses (refuse_in_wake_copy_1160) and the wake arguments
 * (prepare_sck_args) are still checked against it.
 */
static int find_sx_stack_pair_1160(const uint64_t *pas, size_t count,
                                   uint64_t *stack_pa) {
  for (size_t i = 0; i < count; i++) {
    for (size_t j = 0; j < count; j++) {
      if (pas[j] == pas[i] + PAGE_SIZE && !pa_in_wake_copy_1160(pas[i]) &&
          !pa_in_wake_copy_1160(pas[j])) {
        *stack_pa = pas[j];
        return 0;
      }
    }
  }
  return -1;
}

static int take_sx_stack_page_1160(const struct alias_tx_1160 *tx,
                                   const struct alias_page_1160 *pages,
                                   size_t page_count) {
  uint8_t *batch;
  uint64_t pas[SX_STACK_BATCH_1160];
  uint64_t pa = 0;
  uint64_t walked = 0;
  uint64_t next = 0;
  int round;

  /* Batches without a usable pair stay mapped so the next one differs.  The
   * chosen batch stays mapped too; hv_defeat_1160 builds the ROP chain in the
   * stack page. */
  for (round = 0; round < SX_STACK_ROUNDS_1160; round++) {
    batch = mmap(NULL, SX_STACK_BATCH_1160 * PAGE_SIZE,
                 PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (batch == MAP_FAILED)
      return -1;
    memset(batch, 0, SX_STACK_BATCH_1160 * PAGE_SIZE);
    for (size_t i = 0; i < SX_STACK_BATCH_1160; i++) {
      if (source_page_pa(tx->source_pml4, batch + i * PAGE_SIZE, &pas[i]) ||
          pas[i] < PAGE_SIZE) {
        munmap(batch, SX_STACK_BATCH_1160 * PAGE_SIZE);
        return -1;
      }
    }
    if (!find_sx_stack_pair_1160(pas, SX_STACK_BATCH_1160, &pa))
      break;
  }
  if (round == SX_STACK_ROUNDS_1160) {
    notify("11.60 loader refused staging: no free #SX stack page with the "
           "page under it. Run the loader again.\n");
    fflush(stdout);
    return -1;
  }
  sx_stack_pa_1160 = pa;
  for (size_t i = 0; i < page_count; i++) {
    if (pa_under_sx_stack_1160(pages[i].source_pa)) {
      notify("11.60 loader refused staging: boot file page %zu at 0x%llx is "
             "under the #SX stack page.\n",
             i, (unsigned long long)pages[i].source_pa);
      fflush(stdout);
      return -1;
    }
  }
  if (walk_wake_mapping_1160(tx->syscore_pml4, pa_to_dmap(pa), &walked,
                             &next) ||
      walked != pa ||
      walk_wake_mapping_1160(tx->syscore_pml4, pa_to_dmap(pa - PAGE_SIZE),
                             &walked, &next) ||
      walked != pa - PAGE_SIZE)
    return -1;
  return 0;
}

/*
 * The wake blob runs on PID 1's page tables from the kernel code cave, reads
 * the boot files through the aliases and writes the copy through DMAP.  New
 * alias tables are checked in tx_alloc_table and the #SX stack in
 * take_sx_stack_page_1160; this checks PID 1's PML4, the alias tables already
 * present, the DMAP tables for the copy and the code cave with the tables that
 * map it.
 */
/* 10.x takes the #SX stack page without the 11.60 alias transaction. A batch
 * whose PAs do not resolve is kept mapped and the next round retried; the pair
 * must not overlap the fixed destination the shared wake blob copies into. */
int take_sx_stack_page_10xx(uint64_t copy_lo, uint64_t copy_hi) {
  uint8_t *batch;
  uint64_t pas[SX_STACK_BATCH_1160];
  uint64_t pa = 0;
  int round;

  for (round = 0; round < SX_STACK_ROUNDS_1160; round++) {
    int zero = 0, pairs = 0;
    batch = mmap(NULL, SX_STACK_BATCH_1160 * PAGE_SIZE,
                 PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (batch == MAP_FAILED) {
      notify("%04x sx: mmap failed round %d\n", fw, round);
      return -1;
    }
    memset(batch, 0, SX_STACK_BATCH_1160 * PAGE_SIZE);
    for (size_t i = 0; i < SX_STACK_BATCH_1160; i++) {
      pas[i] = vtophys_user((uintptr_t)batch + i * PAGE_SIZE);
      if (!pas[i])
        zero++;
    }
    printf("%04x sx r%d first=0x%llx zero=%d\n", fw, round,
           (unsigned long long)pas[0], zero);
    if (zero)
      continue;
    if (!find_sx_stack_pair_1160(pas, SX_STACK_BATCH_1160, &pa)) {
      uint64_t under = pa - PAGE_SIZE;
      int hit = (pa + PAGE_SIZE > copy_lo && pa < copy_hi) ||
                (under + PAGE_SIZE > copy_lo && under < copy_hi);
      pairs = 1;
      if (!hit) {
        sx_stack_pa_1160 = pa;
        notify("%04x sx: page 0x%llx under 0x%llx (round %d)\n", fw,
               (unsigned long long)pa, (unsigned long long)under, round);
        return 0;
      }
    }
    printf("%04x sx r%d pairs=%d rejected=%d\n", fw, round, pairs,
           pairs ? 1 : 0);
  }
  notify("%04x sx: no usable pair in %d rounds\n", fw,
         (int)SX_STACK_ROUNDS_1160);
  return -1;
}

static int preflight_wake_copy_1160(const struct alias_tx_1160 *tx,
                                    const struct alias_page_1160 *pages,
                                    size_t page_count) {
  uint64_t cave_va = ktext + env_offset.KERNEL_CODE_CAVE;
  uint64_t pa = 0;
  uint64_t next = 0;

  if (refuse_in_wake_copy_1160("page table", tx->syscore_pml4 - dmap))
    return -1;
  for (size_t i = 0; i < page_count; i++)
    if (check_alias_tables_1160(tx->syscore_pml4, pages[i].target_va))
      return -1;
  for (uint64_t va = dmap + cave; va < dmap + wake_copy_end_1160; va = next)
    if (walk_wake_mapping_1160(tx->syscore_pml4, va, &pa, &next))
      return -1;
  for (uint64_t va = cave_va; va < cave_va + WAKE_CAVE_SIZE_1160;
       va += X86_PAGE_SIZE)
    if (walk_wake_mapping_1160(tx->syscore_pml4, va, &pa, &next) ||
        refuse_in_wake_copy_1160("wake code page", pa & ~(X86_PAGE_SIZE - 1)))
      return -1;
  return 0;
}

static int build_alias_plan(const struct linux_info *info, void *bzimage,
                            size_t bzimage_mapping_size, void *initrd,
                            size_t initrd_mapping_size,
                            struct alias_tx_1160 *tx,
                            struct alias_page_1160 **pages_out,
                            size_t *page_count_out, void **info_page_out) {
  size_t bz_pages = bzimage_mapping_size / PAGE_SIZE;
  size_t initrd_pages = initrd_mapping_size / PAGE_SIZE;
  size_t page_count;
  struct alias_page_1160 *pages = NULL;
  void *info_page = MAP_FAILED;
  size_t at = 0;
  size_t overwritten = 0;
  size_t first_overwritten = 0;

  if (add_size(1, bz_pages, &page_count) ||
      add_size(page_count, initrd_pages, &page_count) ||
      page_count > SIZE_MAX / sizeof(*pages))
    return -1;
  pages = calloc(page_count, sizeof(*pages));
  if (!pages)
    return -1;

  info_page = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (info_page == MAP_FAILED) {
    free(pages);
    return -1;
  }
  memset(info_page, 0, PAGE_SIZE);
  memcpy(info_page, info, sizeof(*info));

  pages[at].target_va = info->linux_info;
  pages[at++].source = info_page;
  for (size_t offset = 0; offset < bzimage_mapping_size; offset += PAGE_SIZE) {
    pages[at].target_va = info->bzimage + offset;
    pages[at++].source = (const uint8_t *)bzimage + offset;
  }
  for (size_t offset = 0; offset < initrd_mapping_size; offset += PAGE_SIZE) {
    pages[at].target_va = info->initrd + offset;
    pages[at++].source = (const uint8_t *)initrd + offset;
  }

  for (size_t i = 0; i < page_count; i++) {
    if (source_page_pa(tx->source_pml4, pages[i].source, &pages[i].source_pa)) {
      munmap(info_page, PAGE_SIZE);
      free(pages);
      return -1;
    }
    if (source_overwritten_1160(i, pages[i].source_pa) && overwritten++ == 0)
      first_overwritten = i;
  }
  /* These pages come from this run's mmap, so another run may get others. */
  if (overwritten != 0) {
    notify("11.60 loader refused staging: %zu source pages would be "
           "overwritten by the Linux copy, first page %zu at 0x%llx. Run the "
           "loader again.\n",
           overwritten, first_overwritten,
           (unsigned long long)pages[first_overwritten].source_pa);
    fflush(stdout);
    munmap(info_page, PAGE_SIZE);
    free(pages);
    return -1;
  }

  *pages_out = pages;
  *page_count_out = page_count;
  *info_page_out = info_page;
  return 0;
}

int stage_linux_aliases_1160(const struct linux_info *info, void *bzimage,
                             size_t bzimage_mapping_size, void *initrd,
                             size_t initrd_mapping_size) {
  struct alias_tx_1160 tx;
  struct alias_page_1160 *pages = NULL;
  size_t page_count = 0;
  size_t combined_mapping = 0;
  void *info_page = MAP_FAILED;
  int writes_started = 0;
  int result = -1;

  memset(&tx, 0, sizeof(tx));
  /* The wake blob copies bzimage_size and initrd_size bytes, so they have to
   * fit the mappings checked here. */
  if (!info || !bzimage || !initrd || retained_staging.active ||
      !bzimage_mapping_size || !initrd_mapping_size ||
      (bzimage_mapping_size & (PAGE_SIZE - 1)) ||
      (initrd_mapping_size & (PAGE_SIZE - 1)) ||
      ALIGN_UP(info->bzimage_size, PAGE_SIZE) != bzimage_mapping_size ||
      ALIGN_UP(info->initrd_size, PAGE_SIZE) != initrd_mapping_size ||
      add_size(bzimage_mapping_size, initrd_mapping_size, &combined_mapping) ||
      info->linux_info != kernel_cave_linux_info ||
      info->bzimage != kernel_cave_bzImage ||
      info->initrd != info->bzimage + bzimage_mapping_size) {
    return -1;
  }
  if (combined_mapping > MAX_COMBINED_MAPPING) {
    size_t mib = (combined_mapping >> 20) + ((combined_mapping & 0xFFFFF) != 0);
    notify("11.60 loader refused staging: bzImage and initrd.img need %zu MiB "
           "together, the limit is 160 MiB.\n",
           mib);
    return -1;
  }

  wake_copy_end_1160 = cave_bzImage + combined_mapping;
  if (tx_init(&tx, 1 + combined_mapping / PAGE_SIZE)) {
    goto out;
  }
  if (build_alias_plan(info, bzimage, bzimage_mapping_size, initrd,
                       initrd_mapping_size, &tx, &pages, &page_count,
                       &info_page)) {
    goto out;
  }

  for (size_t i = 0; i < page_count; i++) {
    if (preflight_target_page(tx.syscore_pml4, pages[i].target_va)) {
      printf("11.60 alias staging: REFUSED target page %zu at 0x%llx before "
             "mutation\n",
             i, (unsigned long long)pages[i].target_va);
      fflush(stdout);
      goto out;
    }
  }
  /* The #SX stack page comes first so that the checks after it, and the
   * alias tables allocated during the install, keep the page under it free. */
  if (take_sx_stack_page_1160(&tx, pages, page_count) ||
      preflight_wake_copy_1160(&tx, pages, page_count)) {
    if (refused_until_reboot_1160)
      result = STAGING_REBOOT_FIRST_1160;
    goto out;
  }

  for (size_t i = 0; i < page_count; i++) {
    writes_started = 1;
    if (tx_install_page(&tx, &pages[i])) {
      printf("11.60 alias staging: install failed at page %zu target "
             "0x%llx\n",
             i, (unsigned long long)pages[i].target_va);
      fflush(stdout);
      goto rollback;
    }
  }

  if (verify_aliases(&tx, pages, page_count)) {
    goto rollback;
  }

  retained_staging.bzimage = bzimage;
  retained_staging.bzimage_mapping_size = bzimage_mapping_size;
  retained_staging.initrd = initrd;
  retained_staging.initrd_mapping_size = initrd_mapping_size;
  retained_staging.info_page = info_page;
  retained_staging.tx = tx;
  retained_staging.active = 1;
  result = 0;
  goto done;

rollback:
  if (tx_rollback(&tx) || verify_targets_absent(&tx, pages, page_count))
    hold_after_rollback_failure();
  writes_started = 0;

out:
  if (info_page != MAP_FAILED) {
    munmap(info_page, PAGE_SIZE);
  }
  if (writes_started && tx.journal_count != 0) {
    /* All mutation failures must pass through the rollback label. */
    hold_after_rollback_failure();
  }
  tx_release_backing(&tx);

done:
  free(pages);
  return result;
}
