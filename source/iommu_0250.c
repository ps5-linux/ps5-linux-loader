#include "iommu_0250.h"
#include "util_0250.h"
#include <stdio.h>
#include <string.h>

#define IOMMU_MMIO_CB3_HEAD 0xe000
#define IOMMU_MMIO_CB3_TAIL 0xe008
#define IOMMU_CB_SIZE 0x2000
#define IOMMU_CB_MASK (IOMMU_CB_SIZE - 1)
#define IOMMU_CMD_SIZE 0x10
#define IOMMU_CMD_TIMEOUT 10000000U
#define IOMMU_SC_MMIO_VA 0x40
#define IOMMU_SC_CB3_PTR 0x80
#define IOMMU_SC_CB3_INDEX 0x88

static int read64(uint64_t address, uint64_t *value) {
  *value = 0;
  return kernel_copyout(address, value, sizeof(*value));
}

static int write64(uint64_t address, uint64_t value) {
  return kernel_copyin(&value, address, sizeof(value));
}

static int valid_index(uint64_t value) {
  return value < IOMMU_CB_SIZE && !(value & (IOMMU_CMD_SIZE - 1));
}

int iommu_0250_init(struct iommu_0250_ctx *ctx, uint64_t kbase) {
  uint64_t softc = kr8_0250(kbase + FW_0250_IOMMU_SOFTC);
  if (!INKERNEL(softc)) {
    printf("[iommu] bad softc 0x%lx\n", softc);
    return -2;
  }

  ctx->mmio_va = kr8_0250(softc + IOMMU_SC_MMIO_VA);
  ctx->cb_base = kr8_0250(softc + IOMMU_SC_CB3_PTR);
  ctx->cb_index = softc + IOMMU_SC_CB3_INDEX;
  if (!INKERNEL(ctx->cb_base) || !INKERNEL(ctx->mmio_va) ||
      !INKERNEL(ctx->cb_index) || (ctx->cb_base & 0xfff) ||
      (ctx->mmio_va & 0xfff)) {
    printf("[iommu] cb_base=0x%lx mmio=0x%lx - not initialized\n", ctx->cb_base,
           ctx->mmio_va);
    return -3;
  }

  uint64_t head = 0, tail = 0;
  if (read64(ctx->mmio_va + IOMMU_MMIO_CB3_HEAD, &head) ||
      read64(ctx->mmio_va + IOMMU_MMIO_CB3_TAIL, &tail) || !valid_index(head) ||
      !valid_index(tail) || head != tail) {
    printf("[iommu] command queue is not idle: head=0x%lx tail=0x%lx\n", head,
           tail);
    return -4;
  }
  return 0;
}

static int submit(struct iommu_0250_ctx *ctx, const void *command) {
  uint64_t current_head = 0, current_tail = 0;
  if (read64(ctx->mmio_va + IOMMU_MMIO_CB3_HEAD, &current_head) ||
      read64(ctx->mmio_va + IOMMU_MMIO_CB3_TAIL, &current_tail) ||
      !valid_index(current_head) || !valid_index(current_tail) ||
      current_head != current_tail) {
    printf("[iommu] command queue busy: head=0x%lx tail=0x%lx\n", current_head,
           current_tail);
    return -1;
  }

  uint8_t readback[IOMMU_CMD_SIZE] = {0};
  if (kernel_copyin(command, ctx->cb_base + current_tail, IOMMU_CMD_SIZE) ||
      kernel_copyout(ctx->cb_base + current_tail, readback, sizeof(readback)) ||
      memcmp(readback, command, sizeof(readback))) {
    printf("[iommu] command-buffer verification failed\n");
    return -1;
  }

  uint64_t next = (current_tail + IOMMU_CMD_SIZE) & IOMMU_CB_MASK;
  __sync_synchronize();
  if (write64(ctx->mmio_va + IOMMU_MMIO_CB3_TAIL, next) ||
      write64(ctx->cb_index, next))
    return -1;
  __sync_synchronize();

  int tail_advanced = 0;
  uint64_t head = current_head, tail = current_tail, index = current_tail;
  for (uint32_t i = 0; i < IOMMU_CMD_TIMEOUT; i++) {
    if (read64(ctx->mmio_va + IOMMU_MMIO_CB3_HEAD, &head) ||
        read64(ctx->mmio_va + IOMMU_MMIO_CB3_TAIL, &tail) ||
        read64(ctx->cb_index, &index) || !valid_index(head) ||
        !valid_index(tail) || !valid_index(index))
      return -1;
    if (tail != current_tail)
      tail_advanced = 1;
    if (tail_advanced && head == tail)
      return 0;
  }

  printf("[iommu] command timed out: head=0x%lx tail=0x%lx index=0x%lx\n", head,
         tail, index);
  return -1;
}

int iommu_0250_write8_pa(struct iommu_0250_ctx *ctx, uint64_t pa,
                         uint64_t value) {
  if ((pa & 7) || pa >= IOMMU_PHYS_ADDR_LIMIT)
    return -1;
  uint32_t command[4] = {
      (uint32_t)(pa & 0xfffffff8) | 0x05,
      ((uint32_t)(pa >> 32) & 0xfffff) | 0x10000000,
      (uint32_t)value,
      (uint32_t)(value >> 32),
  };
  return submit(ctx, command);
}
