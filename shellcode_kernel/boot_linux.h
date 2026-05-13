#ifndef BOOT_LINUX_H
#define BOOT_LINUX_H

#include <stdint.h>

#define ALIGN_UP(size, align) (((size) + (align) - 1) & ~((align) - 1))

static int dp_enable_link_phy(int lanenum, int linkrate);
static void install_hv_code(void);
void boot_linux(void);

extern int (*transmitter_control)(int cmd, void *control);
extern int (*mp3_initialize)(int vmid);
extern int (*mp3_invoke)(int cmd_id, void *req, void *rsp);

extern uint64_t g_vbios; // for main.c

#endif
