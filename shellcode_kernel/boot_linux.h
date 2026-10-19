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

/* Published for main.c to print from the region where UART output actually works (see mark_hex
 * in utils.c). boot_linux()'s own markers are invisible on this console, so anything it wants
 * reported has to be handed out here and printed after it returns. */
extern uint64_t g_step;           /* count of m() markers boot_linux() actually reached */
extern uint64_t g_rc_transmitter; /* return of dp_enable_link_phy(4, 30) */
extern uint64_t g_rc_voltage;     /* return of dp_set_voltage_and_preemphasis() -- the added call */
/* The PS5 OS's own HDMI operations, called from main.c so that a fatal one is reportable. */
int  ps5_hdmi_op_count(void);
void call_ps5_hdmi_op(int which);
int  ps5_bridge_read_raw(unsigned int reg, unsigned int n, unsigned char *out);
int  ps5_bridge_get(unsigned int reg, unsigned int n, unsigned char *out);
void ps5_bridge_probe(const char *when);  /* one-line lock report */
int  ps5_hdmi_bringup_call(void);
int  ps5_hdmi_ic_type(void);
int  ps5_hdmi_gate_flag(void);
void ps5_hdmi_init_call(void);
void call_ps5_display_bringup(void);   /* the PS5 OS's whole FLAVA3 bring-up, as one block */
extern uint64_t g_rc_mp3_init;    /* return of mp3_initialize(0) */
extern uint64_t g_rc_mp3_hdcp;    /* return of mp3_set_hdcp_packet(0, 1) */
extern uint64_t g_rc_mp3_output;  /* return of mp3_enable_output(0, 1) */

#endif
