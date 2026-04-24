#include "iommu.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>

iommu_ctx iommu_store;
iommu_ctx *iommu = &iommu_store;

int iommu_init(void) {
  uint64_t softc_ptr = get_offset_va(env_offset.IOMMU_SOFTC);
  if (softc_ptr == ktext) {
    DEBUG_PRINT("[iommu] no IOMMU_SOFTC offset");
    return -1;
  }

  uint64_t softc = kread64(softc_ptr);
  if (!softc) {
    DEBUG_PRINT("[iommu] softc is NULL\n");
    return -2;
  }

  iommu->mmio_va = kread64(softc + IOMMU_SC_MMIO_VA);
  iommu->cb2_base = kread64(softc + IOMMU_SC_CB2_PTR);
  iommu->cb3_base = kread64(softc + IOMMU_SC_CB3_PTR);
  iommu->eb_base = kread64(softc + IOMMU_SC_EB_PTR);

  if (!iommu->cb2_base || !iommu->mmio_va) {
    DEBUG_PRINT("[iommu] cb=0x%016lx mmio=0x%016lx - not initialized\n",
                iommu->cb2_base, iommu->mmio_va);
    return -3;
  }

  DEBUG_PRINT("[iommu] softc=0x%016lx cb=0x%016lx mmio=0x%016lx\n", softc,
              iommu->cb2_base, iommu->mmio_va);
  return 0;
}

// Submit a single 16-byte command and wait for completion
void iommu_submit_cmd(const void *cmd) {

  if (iommu->mmio_va == 0)
    iommu_init();

  uint64_t curr_tail = kread64(iommu->mmio_va + IOMMU_MMIO_CB_TAIL);
  uint64_t next_tail = (curr_tail + IOMMU_CMD_ENTRY_SIZE) & IOMMU_CB_MASK;

  kwrite(iommu->cb2_base + curr_tail, (void *)cmd, IOMMU_CMD_ENTRY_SIZE);
  kwrite64(iommu->mmio_va + IOMMU_MMIO_CB_TAIL, next_tail);

  while (kread64(iommu->mmio_va + IOMMU_MMIO_CB_HEAD) !=
         kread64(iommu->mmio_va + IOMMU_MMIO_CB_TAIL))
    ;
}

// Write 8 bytes to a physical address using IOMMU completion wait store
void iommu_write8_pa(uint64_t pa, uint64_t val) {
  uint32_t cmd[4];
  cmd[0] = (uint32_t)(pa & 0xFFFFFFF8) | 0x05;
  cmd[1] = ((uint32_t)(pa >> 32) & 0xFFFFF) | 0x10000000;
  cmd[2] = (uint32_t)(val);
  cmd[3] = (uint32_t)(val >> 32);
  iommu_submit_cmd(cmd);
}

// Write 4 bytes to a physical address
void iommu_write4_pa(uint64_t pa, uint32_t val) {
  uint64_t aligned = pa & ~7ULL;
  uint64_t existing = kread64(dmap + aligned);
  uint32_t off = (uint32_t)(pa & 7);
  memcpy((uint8_t *)&existing + off, &val, 4);
  iommu_write8_pa(aligned, existing);
}

// Write arbitrary length to a physical address in 8-byte chunks
void iommu_write_pa(uint64_t pa, const void *data, uint32_t len) {
  const uint8_t *src = (const uint8_t *)data;
  uint32_t off = 0;

  if (pa & 7) {
    uint32_t head = 8 - (uint32_t)(pa & 7);
    if (head > len)
      head = len;
    uint64_t aligned = pa & ~7ULL;
    uint64_t existing = kread64(dmap + aligned);
    memcpy((uint8_t *)&existing + (pa & 7), src, head);
    iommu_write8_pa(aligned, existing);
    off += head;
  }

  while (off + 8 <= len) {
    uint64_t val;
    memcpy(&val, src + off, 8);
    iommu_write8_pa(pa + off, val);
    off += 8;
  }

  if (off < len) {
    uint64_t aligned = pa + off;
    uint64_t existing = kread64(dmap + aligned);
    memcpy(&existing, src + off, len - off);
    iommu_write8_pa(aligned, existing);
  }
}