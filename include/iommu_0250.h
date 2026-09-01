#ifndef IOMMU_0250_H
#define IOMMU_0250_H

#include <stdint.h>
#define IOMMU_PHYS_ADDR_LIMIT (1ULL << 52)

struct iommu_0250_ctx {
  uint64_t cb_base;
  uint64_t mmio_va;
  uint64_t cb_index;
};

int iommu_0250_init(struct iommu_0250_ctx *ctx, uint64_t kbase);
int iommu_0250_write8_pa(struct iommu_0250_ctx *ctx, uint64_t pa,
                         uint64_t value);

#endif
