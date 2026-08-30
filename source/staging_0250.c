#include "staging_0250.h"
#include "config_0250.h"
#include "prepare_resume.h"
#include "utils.h"
#include <string.h>
#include <sys/mman.h>

#define PHYS_LIMIT_0250 (1ULL << 40)

static uintptr_t staging_pml4e;
static uint64_t staging_pml4e_original;
static int staging_active;

static int kernel_pointer(uint64_t value) { return (value >> 48) == 0xFFFF; }

static int read_entry(uint64_t address, uint64_t *entry) {
  *entry = 0;
  return kernel_copyout(address, entry, sizeof(*entry));
}

static int write_entry(uint64_t address, uint64_t entry) {
  uint64_t readback = 0;
  return kernel_copyin(&entry, address, sizeof(entry)) ||
         read_entry(address, &readback) || readback != entry;
}

static uint64_t current_pml4(void) {
  uint64_t proc = kernel_get_proc(getpid());
  uint64_t pmap = getpmap(proc);
  uint64_t pml4 = get_pml4(pmap);

  return kernel_pointer(proc) && kernel_pointer(pmap) && kernel_pointer(pml4)
             ? pml4
             : 0;
}

static uint64_t walk_page_tables(uint64_t va, uint64_t root) {
  uint64_t table = PAGE_PA(root);

  for (int level = 0; level < 4; level++) {
    if (!table || (table & 0xFFF) || table >= PHYS_LIMIT_0250)
      return 0;

    uint64_t entry = 0;
    uint64_t index = (va >> (39 - level * 9)) & 0x1FF;
    if (kernel_copyout(dmap + table + index * 8, &entry, sizeof(entry)) ||
        !PAGE_P(entry))
      return 0;

    if ((level == 1 || level == 2) && PAGE_PS(entry)) {
      uint64_t page_size = level == 1 ? 1ULL << 30 : 1ULL << 21;
      return (PAGE_PA(entry) & ~(page_size - 1)) | (va & (page_size - 1));
    }
    if (level == 3)
      return PAGE_PA(entry) | (va & 0xFFF);

    table = PAGE_PA(entry);
  }
  return 0;
}

uint64_t staging_0250_user_pa(uint64_t va) {
  uint64_t pml4 = current_pml4();
  if (!pml4 || pml4 < dmap)
    return 0;

  uint64_t root = pml4 - dmap;
  if (!root || (root & 0xFFF) || root >= PHYS_LIMIT_0250)
    return 0;
  uint64_t pa = walk_page_tables(va, root);
  if (!(va & (PAGE_SIZE - 1)) &&
      walk_page_tables(va + PAGE_SIZE - 0x1000, root) !=
          pa + PAGE_SIZE - 0x1000)
    return 0;
  return pa;
}

uint64_t staging_0250_kernel_pa(uint64_t va) {
  return walk_page_tables(va, cr3);
}

uint64_t staging_0250_alloc_page(void) {
  void *page = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                    MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (page == MAP_FAILED)
    return 0;

  memset(page, 0, PAGE_SIZE);
  uint64_t pa = staging_0250_user_pa((uint64_t)page);
  if (!pa || (pa & (PAGE_SIZE - 1)) || pa >= PHYS_LIMIT_0250) {
    munmap(page, PAGE_SIZE);
    return 0;
  }
  return pa;
}

static int page_is_zero(uint64_t pa) {
  uint8_t buffer[256];

  for (size_t offset = 0; offset < PAGE_SIZE; offset += sizeof(buffer)) {
    if (kernel_copyout(dmap + pa + offset, buffer, sizeof(buffer)))
      return -1;
    for (size_t i = 0; i < sizeof(buffer); i++)
      if (buffer[i])
        return -1;
  }
  return 0;
}

static int ensure_table(uint64_t entry_va, uint64_t *entry_out) {
  uint64_t entry = 0;
  if (read_entry(entry_va, &entry))
    return -1;

  if (PAGE_P(entry)) {
    if (PAGE_PS(entry) || !PAGE_PA(entry) ||
        PAGE_PA(entry) >= PHYS_LIMIT_0250 || !PAGE_RW(entry) ||
        PAGE_XO(entry) || (entry & (1ULL << NX)))
      return -1;
  } else {
    uint64_t page = staging_0250_alloc_page();
    if (!page || page_is_zero(page))
      return -1;
    entry = page | PG_B_RW | PG_B_P;
    if (write_entry(entry_va, entry))
      return -1;
  }

  *entry_out = entry;
  return 0;
}

static int store_leaf(uint64_t pte, uint64_t pa) {
  for (uint64_t i = 0; i < PAGE_SIZE / 0x1000; i++) {
    uint64_t current = 0;
    uint64_t expected = (pa + i * 0x1000) | PG_B_RW | PG_B_P;
    if (read_entry(pte + i * 8, &current) ||
        (PAGE_P(current) && current != expected))
      return -1;
  }
  for (uint64_t i = 0; i < PAGE_SIZE / 0x1000; i++) {
    uint64_t expected = (pa + i * 0x1000) | PG_B_RW | PG_B_P;
    if (write_entry(pte + i * 8, expected))
      return -1;
  }
  return 0;
}

int staging_0250_map(uint64_t va, uint64_t pa) {
  uint64_t pml4 = current_pml4();
  uint64_t entry;

  if (!pml4 || !kernel_pointer(va) || ((va | pa) & (PAGE_SIZE - 1)) || !pa ||
      pa >= PHYS_LIMIT_0250)
    return -1;

  uint64_t pml4e = pml4 + pmap_pml4e_index(va) * 8;
  if (ensure_table(pml4e, &entry))
    return -1;
  uint64_t pdpe = dmap + PAGE_PA(entry) + pmap_pdpe_index(va) * 8;
  if (ensure_table(pdpe, &entry))
    return -1;
  uint64_t pde = dmap + PAGE_PA(entry) + pmap_pde_index(va) * 8;
  if (ensure_table(pde, &entry))
    return -1;
  uint64_t pte = dmap + PAGE_PA(entry) + pmap_pte_index(va) * 8;
  return store_leaf(pte, pa);
}

int staging_0250_flush(void) { return kernel_pmap_invalidate_all(); }

int staging_0250_begin(void) {
  uint64_t pml4 = current_pml4();
  if (!pml4)
    return -1;

  staging_pml4e = pml4 + pmap_pml4e_index(kernel_cave) * 8;
  if (read_entry(staging_pml4e, &staging_pml4e_original))
    return -1;
  if (staging_pml4e_original)
    return -1;

  staging_active = 1;
  return 0;
}

int staging_0250_rollback(void) {
  if (!staging_active)
    return 0;

  uint64_t current = 0;
  if (read_entry(staging_pml4e, &current))
    return -1;
  if (current != staging_pml4e_original &&
      (write_entry(staging_pml4e, staging_pml4e_original) ||
       staging_0250_flush())) {
    return -1;
  }
  staging_active = 0;
  return 0;
}
