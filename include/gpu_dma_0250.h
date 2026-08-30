#ifndef GPU_DMA_0250_H
#define GPU_DMA_0250_H

#include <stdint.h>

#define GPU_PDE_VALID_BIT 0
#define GPU_PDE_IS_PTE_BIT 54
#define GPU_PDE_ADDR_MASK 0x0000FFFFFFFFFFC0ULL
#define GPU_PHYS_ADDR_LIMIT (1ULL << 48)

#define PROT_GPU_READ 0x10
#define PROT_GPU_WRITE 0x20
#define MAP_NO_COALESCE 0x00400000
#define GPU_SUBMIT_IOCTL 0xC0108102

#define PM4_TYPE3 3
#define PM4_SHADER_COMPUTE 1
#define PM4_OPCODE_DMA_DATA 0x50

struct gpu_0250_offsets {
  uint64_t proc_vmspace;
  uint64_t vmspace_vm_vmid;
  uint64_t data_base_gvmspace;
  uint64_t sizeof_gvmspace;
  uint64_t gvmspace_page_dir_va;
  uint64_t gvmspace_size;
  uint64_t gvmspace_start_va;
};

struct gpu_0250_ctx {
  int fd;
  int initialized;
  uint64_t victim_va;
  uint64_t transfer_va;
  uint64_t cmd_va;
  uint64_t victim_real_pa;
  uint64_t transfer_real_pa;
  uint64_t victim_ptbe_va;
  uint64_t cleared_ptbe;
  uint64_t original_rw_ptbe;
  uint64_t leaf_pa_mask;
  uint64_t page_size;
  uint64_t dmem_size;
};

void gpu_0250_set_offsets(const struct gpu_0250_offsets *offsets);
int gpu_0250_init(void);
int gpu_0250_read_phys(uint64_t pa, void *buffer, uint32_t size);
int gpu_0250_cleanup(void);
struct gpu_0250_ctx *gpu_0250_get_ctx(void);

#endif
