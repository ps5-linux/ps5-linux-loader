#include "kernel_code.h"
#include "../include/config.h"
#include "../shellcode_hypervisor/shellcode_hypervisor.h"
#include "shellcode_kernel_args.h"
#include "utils.h"

#define DIG1TRANSMITTERCONTROL 0x4c

#define TRANSMITTER_CONTROL_ENABLE 1
#define TRANSMITTER_CONTROL_SET_VOLTAGE_AND_PREEMPASIS 11

int (*transmitter_control)(int cmd, void *control) = NULL;  // Filled by main.c
int (*mp3_initialize)(int vmid) = NULL;                     // Filled by main.c
int (*mp3_invoke)(int cmd_id, void *req, void *rsp) = NULL; // Filled by main.c

uint64_t g_vbios; // Filled by main.c

typedef struct {
  uint8_t lanenum;
  uint32_t rate;
  uint32_t pad;
  uint32_t lane_setting_1;
  uint32_t lane_setting_2;
} transmitter_args;

struct dig_transmitter_control_parameters_v1_6 {
  uint8_t phyid;
  uint8_t action;
  union {
    uint8_t digmode;
    uint8_t dplaneset;
  } mode_laneset;
  uint8_t lanenum;
  uint32_t symclk_10khz;
  uint8_t hpdsel;
  uint8_t digfe_sel;
  uint8_t connobj_id;
  uint8_t reserved;
  uint32_t reserved1;
};

struct linux_info {
  uintptr_t bzimage;
  size_t bzimage_size;
  uintptr_t initrd;
  size_t initrd_size;
  size_t vram_size;
  char cmdline[2048];
};

static struct linux_info info;

static int mp3_req[1281], mp3_rsp[1282];

static inline void stac(void) { __asm__ volatile("stac" : : : "cc"); }

static inline void clac(void) { __asm__ volatile("clac" : : : "cc"); }

static inline uint64_t vmmcall(uint64_t nr, uint64_t a0, uint64_t a1,
                               uint64_t a2) {
  uint64_t ret;
  __asm__ volatile("vmmcall"
                   : "=a"(ret)
                   : "a"(nr), "b"(a0), "c"(a1), "d"(a2)
                   : "memory");
  return ret;
}

static int dp_enable_link_phy(int lanenum, int linkrate) {
  struct dig_transmitter_control_parameters_v1_6 params = {};
  params.phyid = 0;
  params.action = TRANSMITTER_CONTROL_ENABLE;
  params.mode_laneset.digmode = 0;
  params.lanenum = lanenum;
  params.symclk_10khz = 27000 * linkrate / 10;
  params.hpdsel = 0;
  params.digfe_sel = 0;
  params.connobj_id = 0;

  return transmitter_control(DIG1TRANSMITTERCONTROL, &params);
}

static int mp3_set_hdcp_packet(int be, int mode) {
  mp3_req[0] = be;
  mp3_req[1] = mode;
  return mp3_invoke(21, mp3_req, mp3_rsp);
}

static int mp3_enable_output(int be, int mode) {
  mp3_req[0] = be;
  mp3_req[1] = mode;
  return mp3_invoke(22, mp3_req, mp3_rsp);
}

static void patch_hv(void) {

  // Install identity map for HV
  // HV Shellcode 1 it's updating CR3
  uint64_t identity_cr3 = cave_hv_paging; // P, RW, US=0
  uint64_t identity_pml4_0 =
      identity_cr3 +
      0x1003ULL; // P, RW, US=0 - 512GB // offset 0 +0x1000 from PML4
  uint64_t l40_l3_addr = PAGE_PA(identity_pml4_0); // addr PML4[0]
  uint64_t identity_pml40_l3[] = {
      0x0000000000000083, // P, RW, US=0 - 0 GB to 1 GB
      0x0000000040000083, // P, RW, US=0 - 1 GB to 2 GB
      0x0000000080000083, // P, RW, US=0 - 3 GB to 3 GB
      0x00000000C0000083, // P, RW, US=0 - 4 GB to 4 GB
      0x0000000100000083  // P, RW, US=0 - 5 GB to 6 GB --> Our paging structure
  };
  uint64_t l3_size = sizeof(identity_pml40_l3) / sizeof(identity_pml40_l3[0]);

  // Create the map in memory
  *(uint64_t *)PHYS_TO_DMAP(identity_cr3) = identity_pml4_0;
  for (uint64_t i = 0; i < l3_size; i++) {
    *(uint64_t *)PHYS_TO_DMAP(l40_l3_addr + i * 8) = identity_pml40_l3[i];
  }

  // Install hv_shellcode 2
  uint64_t hv_shellcode = cave_hv;
  memcpy((void *)PHYS_TO_DMAP(hv_shellcode), shellcode_hypervisor,
         shellcode_hypervisor_len);

  // Jump to shellcode final identity mapping
  uint8_t shellcode_jmp[] = {
      0x48, 0xC7, 0xC0, 0x00, 0x6F, 0x80, 0x62, // mov rax, 0x62806f00
      0xFF, 0xE0, 0xC3, 0xC3, 0xC3, 0xC3, 0xC3, // jmp rax
      0xC3, 0xC3};

  // Update code cave in hv 1:1 region
  *(uint32_t *)(&shellcode_jmp[3]) = (uint32_t)args.hv_code_cave_pa;

  // Just patch the VMEXIT handler directly, avoiding all checks (0x6282b45d)
  memcpy(PHYS_TO_DMAP(args.hv_handle_vmexit_pa), shellcode_jmp,
         sizeof(shellcode_jmp));

  uint8_t shellcode_identity_and_jmp[] = {
      0x48, 0xB8, 0x00, 0x00, 0x00,
      0x00, 0x01, 0x00, 0x00, 0x00, // movabs rax, 0x100000000
      0x0F, 0x22, 0xD8,             // mov    cr3, rax
      0x48, 0xB8, 0x00, 0x30, 0x00,
      0x00, 0x01, 0x00, 0x00, 0x00, // movabs rax, 0x100003000
      0xFF, 0xE0                    // jmp    rax
  };

  // Update CR3 PA (from config)
  *(uint64_t *)(&shellcode_identity_and_jmp[2]) = cave_hv_paging;
  // Update HV shellcode cave
  *(uint64_t *)(&shellcode_identity_and_jmp[15]) = cave_hv_code;

  // Install shellcode 1 to update CR3 and jump to main HV shellcode
  memcpy(PHYS_TO_DMAP(args.hv_code_cave_pa), shellcode_identity_and_jmp,
         sizeof(shellcode_identity_and_jmp));
}

void boot_linux(void) {

  patch_hv();

  memcpy((void *)PHYS_TO_DMAP(0xC0000), g_vbios, 0x10000);

  // Enable DP phys link.
  dp_enable_link_phy(4, 30);

  // Initialize hdcp in mp3.
  mp3_initialize(0);
  mp3_set_hdcp_packet(0, 1);
  mp3_enable_output(0, 1);

  // Copy bzImage and initrd into contiguous memory.
  memcpy(&info, (void *)args.linux_info_va, sizeof(struct linux_info));

  uintptr_t bzimage = info.bzimage; // Kernel wrote the VA here
  uintptr_t initrd = info.initrd;   // Kernel wrote the VA here

  info.bzimage = cave_bzImage;
  info.initrd = cave_bzImage + ALIGN_UP(info.bzimage_size, PAGE_SIZE);

  memcpy((void *)PHYS_TO_DMAP(cave_linux_info), &info,
         sizeof(struct linux_info));
  memcpy((void *)PHYS_TO_DMAP(info.bzimage), (void *)bzimage,
         info.bzimage_size);
  memcpy((void *)PHYS_TO_DMAP(info.initrd), (void *)initrd, info.initrd_size);
}
