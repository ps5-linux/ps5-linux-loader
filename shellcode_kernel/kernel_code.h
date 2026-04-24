#ifndef KERNEL_CODE_H
#define KERNEL_CODE_H

#include <stdint.h>

#define cave 0x100000000ULL
#define cave_hv_paging cave
#define cave_hv cave_hv_paging + 0x3000
#define cave_linux cave_hv + 0x2000

#define PAGE_SIZE 4096
#define ALIGN_UP(size, align) (((size) + (align) - 1) & ~((align) - 1))

static int dp_enable_link_phy(int lanenum, int linkrate);
static void patch_hv(void);
void boot_linux(void);

extern int (*transmitter_control)(int cmd, void *control);
extern int (*mp3_initialize)(int vmid);
extern int (*mp3_invoke)(int cmd_id, void *req, void *rsp);

extern uint64_t g_vbios; // for main.c

#endif