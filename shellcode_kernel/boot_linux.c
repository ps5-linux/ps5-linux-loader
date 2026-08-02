#include "boot_linux.h"
#include "../include/config.h"
#include "../include/linux.h"
#include "../shellcode_hv/shellcode_hv.h"
#include "utils.h"

#define DIG1TRANSMITTERCONTROL 0x4c

#define TRANSMITTER_CONTROL_ENABLE 1
#define TRANSMITTER_CONTROL_SET_VOLTAGE_AND_PREEMPASIS 11

int (*transmitter_control)(int cmd, void *control) = NULL;
int (*mp3_initialize)(int vmid) = NULL;
int (*mp3_invoke)(int cmd_id, void *req, void *rsp) = NULL;

uint64_t g_vbios;

typedef struct {
  uint64_t flags;
  uint64_t addr;
  uint64_t size;
} __attribute__((packed)) SceSblHvShmTmrPtState;

typedef uint64_t SceSblHvShmTmrIdBmp;
typedef uint16_t SceSblHvShmTmrPtIdBmp;

typedef struct {
  uint32_t sig;
  uint32_t ver;
  SceSblHvShmTmrPtIdBmp tmrMapPts[64];
  SceSblHvShmTmrIdBmp tmrOvlpIds[64];
  SceSblHvShmTmrPtState tmrPtStates[64];
  uint32_t nmiCounts[16];
  uint8_t reserved[64];
} __attribute__((packed)) SceSblHvShm;

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

static uint64_t get_hv_shm(void) {
  if (args.fw_version >= 0x0500 && args.fw_version < 0x0600) {
    return 0x62a01000;
  } else if (args.fw_version >= 0x0600 && args.fw_version < 0x0800) {
    return 0x62a22000;
  }
  return -1;
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

static void install_hv_code(void) {
  // Install identity map for HV
  uint64_t identity_cr3 = cave_hv_paging;
  uint64_t identity_pml4_0 = identity_cr3 + 0x1003ULL;
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

  // Install shellcode_hv
  memcpy((void *)PHYS_TO_DMAP(cave_hv_code), shellcode_hv_bin,
         shellcode_hv_bin_len);
}

void patch_hv(void) {
  // Jump to shellcode final identity mapping
  uint8_t shellcode_jmp[] = {0x48, 0xC7, 0xC0, 0xAA,
                             0xAA, 0xAA, 0xAA, // mov rax, 0xAAAAAAAA
                             0xFF, 0xE0};      // jmp rax

  // Update code cave in hv 1:1 region
  *(uint32_t *)(&shellcode_jmp[3]) = (uint32_t)args.hv_code_cave_pa;

  // Just patch the VMEXIT handler directly, avoiding all checks
  memcpy((void *)PHYS_TO_DMAP(args.hv_handle_vmexit_pa), shellcode_jmp,
         sizeof(shellcode_jmp));

  uint8_t shellcode_identity_and_jmp[] = {
      0x48, 0xB8, 0xAA, 0xAA, 0xAA,
      0xAA, 0xAA, 0xAA, 0xAA, 0xAA, // movabs rax, 0xAAAAAAAAAAAAAAAA
      0x0F, 0x22, 0xD8,             // mov    cr3, rax
      0x48, 0xB8, 0xAA, 0xAA, 0xAA,
      0xAA, 0xAA, 0xAA, 0xAA, 0xAA, // movabs rax, 0xAAAAAAAAAAAAAAAA
      0xFF, 0xE0                    // jmp    rax
  };

  // Update CR3 PA (from config)
  *(uint64_t *)(&shellcode_identity_and_jmp[2]) = cave_hv_paging;
  // Update HV shellcode cave
  *(uint64_t *)(&shellcode_identity_and_jmp[15]) = cave_hv_code;

  // Install shellcode to update CR3 and jump to main HV shellcode
  memcpy((void *)PHYS_TO_DMAP(args.hv_code_cave_pa), shellcode_identity_and_jmp,
         sizeof(shellcode_identity_and_jmp));
}

void boot_linux(void) {
  patch_hv();

  // Common bootloader code
  install_hv_code();

  memcpy((void *)PHYS_TO_DMAP(0xC0000), (void *)g_vbios, 0x10000);

  // Enable DP phys link.
  dp_enable_link_phy(4, 30);

  // Initialize hdcp in mp3.
  mp3_initialize(0);
  mp3_set_hdcp_packet(0, 1);
  mp3_enable_output(0, 1);

  // Copy bzImage and initrd into contiguous memory.
  memcpy(&info, (void *)args.linux_info_va, sizeof(struct linux_info));

  info.n_tmrs = 0;
  if (args.fw_version >= 0x0500 && args.fw_version < 0x0800) {
    SceSblHvShm *shm = (SceSblHvShm *)PHYS_TO_DMAP(get_hv_shm());

    for (int i = 0; i < 64; i++) {
      if (shm->tmrPtStates[i].flags & 1) {
        info.tmrs[info.n_tmrs].start = shm->tmrPtStates[i].addr;
        info.tmrs[info.n_tmrs].end = shm->tmrPtStates[i].addr + shm->tmrPtStates[i].size;
        printf("tmr: %lx-%lx\n", info.tmrs[info.n_tmrs].start, info.tmrs[info.n_tmrs].end);
        info.n_tmrs++;
      }
    }
  }

  uintptr_t bzimage = info.bzimage;
  uintptr_t initrd = info.initrd;

  info.bzimage = cave_bzImage;
  info.initrd = cave_bzImage + ALIGN_UP(info.bzimage_size, PAGE_SIZE);

  memcpy((void *)PHYS_TO_DMAP(cave_linux_info), &info,
         sizeof(struct linux_info));
  memcpy((void *)PHYS_TO_DMAP(info.bzimage), (void *)bzimage,
         info.bzimage_size);
  memcpy((void *)PHYS_TO_DMAP(info.initrd), (void *)initrd, info.initrd_size);
}
