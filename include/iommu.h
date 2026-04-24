/*** Source: ps5-hen by cragson ***/

#ifndef IOMMU_H
#define IOMMU_H

#include <stdint.h>

// Command buffer MMIO offsets
#define IOMMU_MMIO_CB_HEAD 0xa000
#define IOMMU_MMIO_CB_TAIL 0xa008

// Queue constants
#define IOMMU_CB_SIZE 0x2000
#define IOMMU_CB_MASK (IOMMU_CB_SIZE - 1)
#define IOMMU_CMD_ENTRY_SIZE 0x10

// IOMMU softc field offsets
#define IOMMU_SC_MMIO_VA 0x40
#define IOMMU_SC_CB2_PTR 0x78
#define IOMMU_SC_CB3_PTR 0x80
#define IOMMU_SC_EB_PTR 0x60b90

typedef struct _iommu_ctx {
  uint64_t cb2_base; // kernel VA of command buffer 2 (hv terminology)
  uint64_t cb3_base; // kernel VA of command buffer 3 (hv terminology)
  uint64_t eb_base;  // kernel VA of event buffer
  uint64_t mmio_va;  // DMAP VA of IOMMU MMIO base
} iommu_ctx;

extern iommu_ctx iommu_store;
extern iommu_ctx *iommu;

int iommu_init(void);

// Submit a single 16-byte command and wait for completion
void iommu_submit_cmd(const void *cmd);
// Write 8 bytes to a physical address using IOMMU completion wait store
void iommu_write8_pa(uint64_t pa, uint64_t val);

// Write 4 bytes to a physical address
void iommu_write4_pa(uint64_t pa, uint32_t val);

// Write arbitrary length to a physical address in 8-byte chunks
void iommu_write_pa(uint64_t pa, const void *data, uint32_t len);

#endif