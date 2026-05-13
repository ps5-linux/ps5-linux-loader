#include "gpu.h"
#include "utils.h"
#include <fcntl.h>
#include <ps5/kernel.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

int sceKernelAllocateMainDirectMemory(size_t size, size_t alignment,
                                      int mem_type, uint64_t *phys_out);
int sceKernelMapNamedDirectMemory(void **va_out, size_t size, int prot,
                                  int flags, uint64_t phys, size_t alignment,
                                  const char *name);
int sceKernelSleep(int secs);

static struct gpu_ctx s_gpu = {0};
static struct gpu_kernel_offsets s_gpu_offsets = {0};
static int s_offsets_set = 0;

struct gpu_ctx *gpu_get_ctx(void) { return &s_gpu; }

void gpu_set_offsets(struct gpu_kernel_offsets *offsets) {
  memcpy(&s_gpu_offsets, offsets, sizeof(s_gpu_offsets));
  s_offsets_set = 1;
}

static uint64_t gpu_pde_field(uint64_t pde, int shift, uint64_t mask) {
  return (pde >> shift) & mask;
}

static int gpu_get_vmid(void) {
  uint64_t curproc = kernel_get_proc(getpid());
  uint64_t vmspace;
  uint32_t vmid;

  kernel_copyout(curproc + s_gpu_offsets.proc_vmspace, &vmspace,
                 sizeof(vmspace));
  kernel_copyout(vmspace + s_gpu_offsets.vmspace_vm_vmid, &vmid, sizeof(vmid));

  return (int)vmid;
}

static uint64_t gpu_get_pdb2_addr(int vmid) {
  uint64_t gvmspace = KERNEL_ADDRESS_DATA_BASE +
                      s_gpu_offsets.data_base_gvmspace +
                      (uint64_t)vmid * s_gpu_offsets.sizeof_gvmspace;

  uint64_t pdb2_va;
  kernel_copyout(gvmspace + s_gpu_offsets.gvmspace_page_dir_va, &pdb2_va,
                 sizeof(pdb2_va));
  return pdb2_va;
}

static uint64_t gpu_get_relative_va(int vmid, uint64_t va) {
  uint64_t gvmspace = KERNEL_ADDRESS_DATA_BASE +
                      s_gpu_offsets.data_base_gvmspace +
                      (uint64_t)vmid * s_gpu_offsets.sizeof_gvmspace;

  uint64_t start_va, size;
  kernel_copyout(gvmspace + s_gpu_offsets.gvmspace_start_va, &start_va,
                 sizeof(start_va));
  kernel_copyout(gvmspace + s_gpu_offsets.gvmspace_size, &size, sizeof(size));

  if (va >= start_va && va < start_va + size)
    return va - start_va;

  return (uint64_t)-1;
}

static uint64_t gpu_walk_pt(int vmid, uint64_t gpu_va,
                            uint64_t *out_page_size) {
  uint64_t pdb2_addr = gpu_get_pdb2_addr(vmid);

  uint64_t pml4e_idx = (gpu_va >> 39) & 0x1FF;
  uint64_t pdpe_idx = (gpu_va >> 30) & 0x1FF;
  uint64_t pde_idx = (gpu_va >> 21) & 0x1FF;

  // PDB2 (PML4 equivalent)
  uint64_t pml4e;
  kernel_copyout(pdb2_addr + pml4e_idx * 8, &pml4e, sizeof(pml4e));

  if (gpu_pde_field(pml4e, GPU_PDE_VALID_BIT, 1) != 1)
    return 0;

  // PDB1 (PDPT equivalent)
  uint64_t pdp_pa = pml4e & GPU_PDE_ADDR_MASK;
  uint64_t pdpe_va = dmap + pdp_pa + pdpe_idx * 8;
  uint64_t pdpe;
  kernel_copyout(pdpe_va, &pdpe, sizeof(pdpe));

  if (gpu_pde_field(pdpe, GPU_PDE_VALID_BIT, 1) != 1)
    return 0;

  // PDB0 (PD equivalent)
  uint64_t pd_pa = pdpe & GPU_PDE_ADDR_MASK;
  uint64_t pde_va = dmap + pd_pa + pde_idx * 8;
  uint64_t pde;
  kernel_copyout(pde_va, &pde, sizeof(pde));

  if (gpu_pde_field(pde, GPU_PDE_VALID_BIT, 1) != 1)
    return 0;

  // If IS_PTE bit set, this is a 2MB leaf
  if (gpu_pde_field(pde, GPU_PDE_IS_PTE_BIT, 1) == 1) {
    *out_page_size = 0x200000;
    return pde_va;
  }

  // PTB (page table block)
  uint64_t frag_size = gpu_pde_field(pde, GPU_PDE_BLOCK_FRAG_BIT, 0x1F);
  uint64_t offset = gpu_va & 0x1FFFFF;
  uint64_t pt_pa = pde & GPU_PDE_ADDR_MASK;

  uint64_t pte_idx, pte_va;

  if (frag_size == 4) {
    pte_idx = offset >> 16;
    pte_va = dmap + pt_pa + pte_idx * 8;

    uint64_t pte;
    kernel_copyout(pte_va, &pte, sizeof(pte));

    if (gpu_pde_field(pte, GPU_PDE_VALID_BIT, 1) == 1 &&
        gpu_pde_field(pte, GPU_PDE_TF_BIT, 1) == 1) {
      pte_idx = (gpu_va & 0xFFFF) >> 13;
      pte_va = dmap + pt_pa + pte_idx * 8;
      *out_page_size = 0x2000; // 8KB
    } else {
      *out_page_size = 0x10000; // 64KB
    }
  } else if (frag_size == 1) {
    pte_idx = offset >> 13;
    pte_va = dmap + pt_pa + pte_idx * 8;
    *out_page_size = 0x2000; // 8KB
  } else {
    // Unknown fragment size - use 64KB as default
    pte_idx = offset >> 16;
    pte_va = dmap + pt_pa + pte_idx * 8;
    *out_page_size = 0x10000;
  }

  return pte_va;
}

static uint64_t gpu_alloc_dmem(uint64_t size, int gpu_write) {
  uint64_t phys_out = 0;
  void *va_out = NULL;

  int prot = PROT_READ | PROT_WRITE | PROT_GPU_READ;
  if (gpu_write)
    prot |= PROT_GPU_WRITE;

  int ret = sceKernelAllocateMainDirectMemory(size, size, 1, &phys_out);
  if (ret != 0) {
    printf("[gpu] sceKernelAllocateMainDirectMemory failed: 0x%d\n", ret);
    return 0;
  }

  ret = sceKernelMapNamedDirectMemory(&va_out, size, prot, MAP_NO_COALESCE,
                                      phys_out, size, "gpudma");
  if (ret != 0) {
    printf("[gpu] sceKernelMapNamedDirectMemory failed: 0x%d\n", ret);
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

static int gpu_transfer_physical(uint64_t phys_addr, void *local_buf,
                                 uint32_t size, int is_write) {
  if (!s_gpu.initialized)
    return -1;

  uint64_t aligned_pa = phys_addr & ~(s_gpu.dmem_size - 1);
  uint64_t offset = phys_addr - aligned_pa;

  if (offset + size > s_gpu.dmem_size) {
    printf("[gpu] transfer exceeds dmem_size\n");
    return -1;
  }

  int prot_ro = PROT_READ | PROT_WRITE | PROT_GPU_READ;
  int prot_rw = prot_ro | PROT_GPU_WRITE;

  mprotect((void *)s_gpu.victim_va, s_gpu.dmem_size, prot_ro);

  uint64_t new_ptbe = s_gpu.cleared_ptbe | aligned_pa;
  kernel_setlong(s_gpu.victim_ptbe_va, new_ptbe);

  mprotect((void *)s_gpu.victim_va, s_gpu.dmem_size, prot_rw);
  uint64_t src, dst;

  if (is_write) {
    memcpy((void *)s_gpu.transfer_va, local_buf, size);
    src = s_gpu.transfer_va;
    dst = s_gpu.victim_va + offset;
  } else {
    src = s_gpu.victim_va + offset;
    dst = s_gpu.transfer_va;
  }

  int cmd_size = pm4_build_dma_data((void *)s_gpu.cmd_va, dst, src, size);

  uint8_t desc[16];
  gpu_build_cmd_descriptor(desc, s_gpu.cmd_va, cmd_size);

  uint64_t desc_va = s_gpu.cmd_va + 0x1000;
  memcpy((void *)desc_va, desc, 16);

  int ret = gpu_submit_commands(s_gpu.fd, 0, 1, desc_va);
  if (ret != 0) {
    printf("[gpu] ioctl submit failed: %d\n", ret);
    return -1;
  }

  // Wait for GPU DMA completion
  // TODO: proper fence/signal wait
  usleep(100000);

  if (!is_write) {
    memcpy(local_buf, (void *)s_gpu.transfer_va, size);
  }

  // Restore victim PTE to original physical address
  uint64_t orig_ptbe = s_gpu.cleared_ptbe | s_gpu.victim_real_pa;
  kernel_setlong(s_gpu.victim_ptbe_va, orig_ptbe);

  return 0;
}

int gpu_init(void) {
  // init GPU DMA
  struct gpu_kernel_offsets go = {};
  go.proc_vmspace = KERNEL_OFFSET_PROC_P_VMSPACE;
  go.vmspace_vm_vmid = env_offset.VMSPACE_VM_VMID;
  go.sizeof_gvmspace = 0x100;
  go.gvmspace_page_dir_va = 0x38;
  go.gvmspace_size = 0x10;
  go.gvmspace_start_va = 0x08;
  go.data_base_gvmspace = env_offset.DATA_BASE_GVMSPACE;

  gpu_set_offsets(&go);

  if (gpu_init_internal())
    return -1;

  return 0;
}

int gpu_init_internal(void) {
  if (s_gpu.initialized) {
    DEBUG_PRINT("[gpu] Already initialized\n");
    return 0;
  }

  if (!s_offsets_set) {
    DEBUG_PRINT("[gpu] ERROR: call gpu_set_offsets() first\n");
    return -1;
  }

  DEBUG_PRINT("[gpu] init\n");

  s_gpu.dmem_size = 2 * 0x100000; // 2MB

  // Step 1: Open GPU device
  DEBUG_PRINT("[gpu] Opening /dev/gc\n");
  s_gpu.fd = open("/dev/gc", O_RDWR);
  if (s_gpu.fd < 0) {
    DEBUG_PRINT("[gpu] ERROR: failed to open /dev/gc (fd=%d)\n", s_gpu.fd);
    return -1;
  }
  DEBUG_PRINT("[gpu] /dev/gc fd=%d\n", s_gpu.fd);

  // Step 2: Allocate 3 GPU-mapped buffers
  DEBUG_PRINT("[gpu] Allocating GPU direct memory (3 x 2MB)\n");

  s_gpu.victim_va = gpu_alloc_dmem(s_gpu.dmem_size, 1);
  if (!s_gpu.victim_va) {
    DEBUG_PRINT("[gpu] victim alloc failed\n");
    return -2;
  }

  s_gpu.transfer_va = gpu_alloc_dmem(s_gpu.dmem_size, 1);
  if (!s_gpu.transfer_va) {
    DEBUG_PRINT("[gpu] transfer alloc failed\n");
    return -2;
  }

  s_gpu.cmd_va = gpu_alloc_dmem(s_gpu.dmem_size, 1);
  if (!s_gpu.cmd_va) {
    DEBUG_PRINT("[gpu] cmd alloc failed\n");
    return -2;
  }

  DEBUG_PRINT("[gpu] victim_va   = 0x%lx\n", s_gpu.victim_va);
  DEBUG_PRINT("[gpu] transfer_va = 0x%lx\n", s_gpu.transfer_va);
  DEBUG_PRINT("[gpu] cmd_va      = 0x%lx\n", s_gpu.cmd_va);

  // Step 3: Get the physical address of the victim buffer
  s_gpu.victim_real_pa = vtophys_user(s_gpu.victim_va);
  DEBUG_PRINT("[gpu] victim_real_pa = 0x%lx\n", s_gpu.victim_real_pa);

  // Step 4: Walk GPU page tables to find the PTE for the victim buffer
  int vmid = gpu_get_vmid();
  DEBUG_PRINT("[gpu] GPU VMID = %d\n", vmid);

  if (s_gpu_offsets.data_base_gvmspace == 0) {
    DEBUG_PRINT("[gpu] ERROR: data_base_gvmspace not set\n");
    return -3;
  }

  uint64_t rel_va = gpu_get_relative_va(vmid, s_gpu.victim_va);
  if (rel_va == (uint64_t)-1) {
    DEBUG_PRINT("[gpu] ERROR: could not get relative VA for victim\n");
    return -3;
  }
  DEBUG_PRINT("[gpu] victim relative GPU VA = 0x%lx\n", rel_va);

  s_gpu.victim_ptbe_va = gpu_walk_pt(vmid, rel_va, &s_gpu.page_size);
  if (s_gpu.victim_ptbe_va == 0) {
    DEBUG_PRINT("[gpu] ERROR: GPU page table walk failed\n");
    return -4;
  }
  DEBUG_PRINT("[gpu] victim GPU PTE VA  = 0x%lx\n", s_gpu.victim_ptbe_va);
  DEBUG_PRINT("[gpu] victim GPU page sz = 0x%lx\n", s_gpu.page_size);

  if (s_gpu.page_size != s_gpu.dmem_size) {
    DEBUG_PRINT("[gpu] WARNING: page size 0x%lx != dmem_size 0x%lx\n",
                s_gpu.page_size, s_gpu.dmem_size);
  }

  // Step 5: Prepare the cleared PTE template
  int prot_ro = PROT_READ | PROT_WRITE | PROT_GPU_READ;
  mprotect((void *)s_gpu.victim_va, s_gpu.dmem_size, prot_ro);

  uint64_t current_ptbe;
  kernel_copyout(s_gpu.victim_ptbe_va, &current_ptbe, sizeof(current_ptbe));
  s_gpu.cleared_ptbe = current_ptbe & ~s_gpu.victim_real_pa;

  DEBUG_PRINT("[gpu] current PTE = 0x%lx\n", current_ptbe);
  DEBUG_PRINT("[gpu] cleared PTE = 0x%lx\n", s_gpu.cleared_ptbe);

  int prot_rw = prot_ro | PROT_GPU_WRITE;
  mprotect((void *)s_gpu.victim_va, s_gpu.dmem_size, prot_rw);

  s_gpu.initialized = 1;
  DEBUG_PRINT("[gpu] ready\n");
  return 0;
}

int gpu_test(void) {
  if (!s_gpu.initialized) {
    printf("[gpu] ERROR: not initialized\n");
    return -1;
  }

  DEBUG_PRINT("[gpu] test\n");

  // Test 1: Read a known kernel .data value via GPU DMA and compare
  uint64_t test_va = (uint64_t)KERNEL_ADDRESS_DATA_BASE;
  uint64_t test_pa = vtophys(test_va);
  DEBUG_PRINT("[gpu] Test target: VA=0x%lx PA=0x%lx\n", test_va, test_pa);

  uint64_t kernel_val = kernel_getlong(test_va);
  DEBUG_PRINT("[gpu] kernel_read8 = 0x%lx\n", kernel_val);

  uint64_t gpu_val = gpu_read_phys8(test_pa);
  DEBUG_PRINT("[gpu] gpu_read8    = 0x%lx\n", gpu_val);

  if (kernel_val == gpu_val) {
    printf("[gpu] *** TEST PASSED: values match ***\n");
  } else {
    printf("[gpu] *** TEST FAILED: values differ ***\n");
    return -1;
  }

  // Test 2: Write and read-back test
  uint64_t test_write_pa = vtophys_user(s_gpu.transfer_va + 0x100000);
  uint64_t magic = 0xDEADBEEFCAFEBABEULL;

  DEBUG_PRINT("[gpu] Write test: PA=0x%lx val=0x%lx\n", test_write_pa, magic);
  gpu_write_phys8(test_write_pa, magic);

  uint64_t readback = gpu_read_phys8(test_write_pa);
  DEBUG_PRINT("[gpu] Readback    = 0x%lx\n", readback);

  if (readback == magic) {
    printf("[gpu] *** WRITE TEST PASSED ***\n");
  } else {
    printf("[gpu] *** WRITE TEST FAILED ***\n");
    return -1;
  }

  printf("[gpu] tests ok\n");
  return 0;
}

int gpu_read_phys(uint64_t phys_addr, void *out_buf, uint32_t size) {
  return gpu_transfer_physical(phys_addr, out_buf, size, 0);
}

uint8_t gpu_read_phys1(uint64_t phys_addr) {
  uint8_t val = 0;
  gpu_transfer_physical(phys_addr, &val, sizeof(val), 0);
  return val;
}

uint32_t gpu_read_phys4(uint64_t phys_addr) {
  uint32_t val = 0;
  gpu_transfer_physical(phys_addr, &val, sizeof(val), 0);
  return val;
}

uint64_t gpu_read_phys8(uint64_t phys_addr) {
  uint64_t val = 0;
  gpu_transfer_physical(phys_addr, &val, sizeof(val), 0);
  return val;
}

int gpu_write_phys(uint64_t phys_addr, const void *in_buf, uint32_t size) {
  return gpu_transfer_physical(phys_addr, (void *)in_buf, size, 1);
}

void gpu_write_phys4(uint64_t phys_addr, uint32_t value) {
  gpu_transfer_physical(phys_addr, &value, sizeof(value), 1);
}

void gpu_write_phys8(uint64_t phys_addr, uint64_t value) {
  gpu_transfer_physical(phys_addr, &value, sizeof(value), 1);
}

void gpu_cleanup(void) {
  if (s_gpu.fd >= 0) {
    close(s_gpu.fd);
    s_gpu.fd = -1;
  }

  s_gpu.initialized = 0;
  printf("[gpu] Cleaned up\n");
}
