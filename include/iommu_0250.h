#ifndef IOMMU_0250_H
#define IOMMU_0250_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "util_0250.h"

#define IIOMMU_MMIO_CB3_HEAD 0xe000
#define IOMMU_MMIO_CB3_TAIL 0xe008

#define IOMMU_CB_SIZE 0x2000
#define IOMMU_CB_MASK (IOMMU_CB_SIZE - 1)
#define IOMMU_CMD_ENTRY_SIZE 0x10
#define IOMMU_CMD_TIMEOUT 10000000U
#define IOMMU_PHYS_ADDR_LIMIT (1ULL << 52)

#define IOMMU_SC_MMIO_VA 0x40
#define IOMMU_SC_CB3_PTR 0x80
#define IOMMU_SC_CB3_INDEX 0x88

struct iommu_ctx {
  uint64_t cb_base;
  uint64_t mmio_va;
  uint64_t cb_index;
};

static inline int iommu_0250_read64(uint64_t address, uint64_t *value) {
  *value = 0;
  return kernel_copyout(address, value, sizeof(*value));
}

static inline int iommu_0250_write64(uint64_t address, uint64_t value) {
  return kernel_copyin(&value, address, sizeof(value));
}

static inline int iommu_0250_init(struct iommu_ctx *ctx, uint64_t kbase) {
  uint64_t softc = kr8_0250(kbase + FW_0250_IOMMU_SOFTC);
  if (!INKERNEL(softc)) {
    printf("[iommu] bad softc 0x%lx\n", softc);
    return -2;
  }

  ctx->mmio_va = kr8_0250(softc + IOMMU_SC_MMIO_VA);
  ctx->cb_base = kr8_0250(softc + IOMMU_SC_CB3_PTR);
  ctx->cb_index = softc + IOMMU_SC_CB3_INDEX;

  if (!INKERNEL(ctx->cb_base) || !INKERNEL(ctx->mmio_va) ||
      !INKERNEL(ctx->cb_index) || (ctx->cb_base & 0xFFF) ||
      (ctx->mmio_va & 0xFFF)) {
    printf("[iommu] cb_base=0x%lx mmio=0x%lx - not initialized\n", ctx->cb_base,
           ctx->mmio_va);
    return -3;
  }

  uint64_t head = 0;
  uint64_t tail = 0;
  if (iommu_0250_read64(ctx->mmio_va + IIOMMU_MMIO_CB3_HEAD, &head) ||
      iommu_0250_read64(ctx->mmio_va + IOMMU_MMIO_CB3_TAIL, &tail) ||
      head >= IOMMU_CB_SIZE || tail >= IOMMU_CB_SIZE ||
      ((head | tail) & (IOMMU_CMD_ENTRY_SIZE - 1)) || head != tail) {
    printf("[iommu] command queue is not idle head=0x%lx tail=0x%lx\n", head,
           tail);
    return -4;
  }

  return 0;
}

static inline int iommu_0250_submit_cmd(struct iommu_ctx *ctx,
                                        const void *cmd) {
  uint64_t curr_head = 0;
  uint64_t curr_tail = 0;
  if (iommu_0250_read64(ctx->mmio_va + IIOMMU_MMIO_CB3_HEAD, &curr_head) ||
      iommu_0250_read64(ctx->mmio_va + IOMMU_MMIO_CB3_TAIL, &curr_tail) ||
      curr_head >= IOMMU_CB_SIZE || curr_tail >= IOMMU_CB_SIZE ||
      ((curr_head | curr_tail) & (IOMMU_CMD_ENTRY_SIZE - 1)) ||
      curr_head != curr_tail) {
    printf("[iommu] command queue busy head=0x%lx tail=0x%lx\n", curr_head,
           curr_tail);
    return -1;
  }
  uint64_t next_tail = (curr_tail + IOMMU_CMD_ENTRY_SIZE) & IOMMU_CB_MASK;

  uint8_t readback[IOMMU_CMD_ENTRY_SIZE] = {0};
  if (kernel_copyin(cmd, ctx->cb_base + curr_tail, IOMMU_CMD_ENTRY_SIZE) ||
      kernel_copyout(ctx->cb_base + curr_tail, readback, sizeof(readback)) ||
      memcmp(readback, cmd, sizeof(readback)) != 0) {
    printf("[iommu] command-buffer verification failed\n");
    return -1;
  }
  __sync_synchronize();
  if (iommu_0250_write64(ctx->mmio_va + IOMMU_MMIO_CB3_TAIL, next_tail) ||
      iommu_0250_write64(ctx->cb_index, next_tail)) {
    printf("[iommu] command queue update failed\n");
    return -1;
  }
  __sync_synchronize();

  int tail_advanced = 0;
  uint64_t head = curr_head;
  uint64_t tail = curr_tail;
  uint64_t index = curr_tail;
  for (uint32_t i = 0; i < IOMMU_CMD_TIMEOUT; i++) {
    if (iommu_0250_read64(ctx->mmio_va + IIOMMU_MMIO_CB3_HEAD, &head) ||
        iommu_0250_read64(ctx->mmio_va + IOMMU_MMIO_CB3_TAIL, &tail) ||
        iommu_0250_read64(ctx->cb_index, &index) || head >= IOMMU_CB_SIZE ||
        tail >= IOMMU_CB_SIZE || index >= IOMMU_CB_SIZE ||
        ((head | tail | index) & (IOMMU_CMD_ENTRY_SIZE - 1))) {
      printf("[iommu] command queue state became invalid "
             "head=0x%lx tail=0x%lx index=0x%lx\n",
             head, tail, index);
      return -1;
    }
    if (tail != curr_tail)
      tail_advanced = 1;
    if (tail_advanced && head == tail)
      return 0;
  }

  printf("[iommu] command timeout head=0x%lx tail=0x%lx index=0x%lx "
         "advanced=%d\n",
         head, tail, index, tail_advanced);
  return -1;
}

static inline int iommu_0250_write8_pa(struct iommu_ctx *ctx, uint64_t pa,
                                       uint64_t val) {
  if ((pa & 7) || pa >= IOMMU_PHYS_ADDR_LIMIT)
    return -1;
  uint32_t cmd[4];
  cmd[0] = (uint32_t)(pa & 0xFFFFFFF8) | 0x05;
  cmd[1] = ((uint32_t)(pa >> 32) & 0xFFFFF) | 0x10000000;
  cmd[2] = (uint32_t)(val);
  cmd[3] = (uint32_t)(val >> 32);
  return iommu_0250_submit_cmd(ctx, cmd);
}

#endif
