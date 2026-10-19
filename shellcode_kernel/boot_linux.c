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

/* Handed to main.c, which prints them from the region where UART output demonstrably works.
 * boot_linux() cannot report these itself -- see mark_hex() in utils.c for why. */
uint64_t g_step;
uint64_t g_rc_transmitter, g_rc_voltage, g_rc_mp3_init, g_rc_mp3_hdcp, g_rc_mp3_output;
/* What the EMC asked for and what we actually programmed, for the one-line report. */
uint64_t g_dp_vspe_raw = 0xFF, g_dp_vswing, g_dp_preemph;

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

  /* NULL when the offset table has no FUN_TRANSMITTER_CONTROL (8.00/9.00 shipped
   * without it). Report rather than call ktext+0. */
  if (!transmitter_control) return -0x5101;
  return transmitter_control(DIG1TRANSMITTERCONTROL, &params);
}

/* Set the DP lane voltage swing / pre-emphasis.
 *
 * MISSING FROM THE UPSTREAM SEQUENCE, and it is the one thing the PS5 OS's own transmitter_control
 * callers do that this file never did. Disassembly of the PS5 caller at preslide 0x6A00A0, which
 * special-cases this action:
 *
 *     cmp  $0xb,%esi                     ; action == SET_VOLTAGE_AND_PREEMPASIS (11)
 *     mov  0x10(%rdi),%ecx ; shl $0x3,%ecx ; or 0xc(%rdi),%ecx
 *     mov  %cl,-0x4e(%rbp)               ; the mode_laneset byte = (vswing<<3)|preemph
 *     mov  %esi,-0x4f(%rbp)              ; the action byte
 *
 * So the union byte this file sets as `.digmode = 0` is really the lane-settings field. Enabling
 * the DP PHY without ever setting voltage/pre-emphasis lets the link train while the receiver
 * cannot recover a signal -- which matches "no signal at all" from a bridge whose DP link the DCN
 * reports as trained. Upstream defines TRANSMITTER_CONTROL_SET_VOLTAGE_AND_PREEMPASIS and never
 * calls it, and carries an unused `transmitter_args { lanenum, rate, pad, lane_setting_1,
 * lane_setting_2 }` that plainly belongs here.
 *
 * vswing/preemph are 0..7 each (3 bits apiece, per the shift-by-3 above). Sweep via
 * DP_VSWING / DP_PREEMPH if 0/0 does not take.
 */
/* The EMC publishes the required drive in the HDMI config reply; getHdmiConfiguration
 * (0x2BB8D0) caches it at this preslide and prints it as "DP VS/PE". On this devkit it
 * reads 0x21 on both 4.51 and 13.60 = (vswing 4, preemph 1). 0xFF means unavailable. */
#define PRESLIDE_DP_VSPE   0x2D5834EULL

#ifndef DP_VSWING
#define DP_VSWING  4        /* was 0 -- the weakest drive, and not what the EMC asks for */
#endif
#ifndef DP_PREEMPH
#define DP_PREEMPH 1        /* was 0 */
#endif

static int dp_set_voltage_and_preemphasis(int lanenum, int vswing, int preemph) {
  struct dig_transmitter_control_parameters_v1_6 params = {};
  params.phyid = 0;
  params.action = TRANSMITTER_CONTROL_SET_VOLTAGE_AND_PREEMPASIS;
  params.mode_laneset.dplaneset = (uint8_t)(((vswing & 0x7) << 3) | (preemph & 0x7));
  params.lanenum = lanenum;
  params.symclk_10khz = 0;

  /* NULL when the offset table has no FUN_TRANSMITTER_CONTROL (8.00/9.00 shipped
   * without it). Report rather than call ktext+0. */
  if (!transmitter_control) return -0x5101;
  return transmitter_control(DIG1TRANSMITTERCONTROL, &params);
}

/* ---------------------------------------------------------------------------------------------
 * Call the PS5 KERNEL'S OWN HDMI operations.
 *
 * The Linux driver is a REDUCED version of the PS5 OS's. Comparing the two kernels by their own
 * diagnostic strings: the 13.60 PS5 kernel names ~57 HDMI operations (configParamFlava3Pre,
 * Start EMC HDMI service, resetVideoIF, Init Video, Video Basic Config, Hdmi OutputMode,
 * Video Mute Control, sceSetWaitPwOnSequence, configDpLinkTraining, ...) while the Linux vmlinux
 * has only a handful -- and is missing every one of those. That is a concrete, code-backed list of
 * what the PS5 OS does around the FLAVA3 that our boot never did, and it fits a bridge that is
 * identified, configured, fed a perfectly trained DP stream (4 lanes, HBR3, symbol lock), and
 * still emits no TMDS.
 *
 * Rather than transcribe each operation's ICC message (they set a dozen payload fields, and a
 * hand-built message is simply ignored -- verified: sweeping op codes returns all-zero payloads),
 * CALL the PS5 OS's own implementations. The shellcode runs in that kernel, so they are right
 * there. Offsets are preslide, derived from the 13.60 kernel by mapping each operation's own
 * "[HDMI ERROR] ... : ICC Query Failed" string back to the function that emits it.
 *
 * ktext is recovered from printf, whose preslide offset 0x25D410 is already verified -- this
 * avoids touching the args struct. Hdmi OutputMode's prologue reads no argument registers before
 * its first call, so it is called as void(void); the others are called the same way and are
 * reported individually so a fault names its culprit.
 * ------------------------------------------------------------------------------------------- */
#define PRESLIDE_FUN_PRINTF        0x25D410ULL
#define PRESLIDE_START_EMC_HDMI    0x968DF0ULL   /* "Start EMC HDMI service"   */
#define PRESLIDE_INIT_VIDEO        0x4B6AF0ULL   /* "Init Video"               */
#define PRESLIDE_VIDEO_BASIC_CFG   0x4B2570ULL   /* "Video Basic Config" / "configParamFlava3Pre" */
#define PRESLIDE_HDMI_OUTPUT_MODE  0x4B1FE0ULL   /* "Hdmi OutputMode"          */
#define PRESLIDE_VIDEO_MUTE_CTRL   0x4B1E80ULL   /* "Video Mute Control"       */
#define PRESLIDE_RESET_VIDEO_IF    0x4B4370ULL   /* "resetVideoIF"             */
#define PRESLIDE_GET_DP_LINK_STAT  0x969D50ULL   /* "Get DP Link Status"       */

static uint64_t ktext_base(void) { return (uint64_t)(unsigned long)printf - PRESLIDE_FUN_PRINTF; }

/* The six PS5 OS HDMI operations, in the order the PS5 OS would bring the path up.
 *
 * They are CALLED FROM main.c, not from here. A counter printed after boot_linux() returns is
 * useless when a fatal op kills the boot mid-function -- it never returns, so nothing is printed
 * (that is exactly what the last attempt showed). main.c's region is the one where printf
 * demonstrably reaches the host, so the ops are invoked from there, each announced by name first.
 */
/* ARGUMENTS, read off the PS5 OS's own call sites -- every one of them lives in a single function
 * around preslide 0xB57xxx, which IS the PS5 OS's display bring-up routine:
 *
 *   Start EMC HDMI service <- 0xB57A89:  mov $0x1,%edi ; call
 *   Init Video             <- 0xB57E21:  (no argument set)
 *   Video Basic Config     <- 0x4B24A2:  mov $0x1,%edi ; call
 *   Hdmi OutputMode        <- 0xB5773E:  (no argument set)
 *   Video Mute Control     <- 0xB5755F:  xor %edi,%edi ; call   (0 = unmute)
 *
 * THIS IS WHY THE PREVIOUS BUILD DIED: called as void(void) they received whatever was in rdi.
 * Start EMC HDMI service does `mov %edi,%ebx ; cmp $0x1,%ebx` -- it acts on that value -- and
 * Video Mute Control reads edi too. Passing the real arguments is not cosmetic.
 *
 * resetVideoIF is dropped: it has no callers anywhere in the kernel, so it is not an entry point
 * the PS5 OS uses (inlined or dead), and calling an unproven entry is how the last two builds died.
 */
/* argc/arg2: most rows are one-argument calls, but not all of them are, and calling a
 * multi-argument kernel function through a blanket void(*)(int) leaves rsi holding
 * whatever happened to be in it. 0x968DF0 (Start EMC HDMI service) is
 *   __int64 (int a1, __int64 a2, int, int, int, int)
 * and its own call sites inside the 13.60 kernel pass esi = 0x7f0 == ICC_MSG_MAX_SIZE,
 * i.e. the ICC buffer size, so we were handing it garbage. argc == 0 keeps the legacy
 * one-argument behaviour, so every other row stays byte-for-byte unchanged. */
struct ps5_op { uint64_t preslide; int arg; int argc; uint64_t arg2; };

/* THE PS5 OS's FLAVA3 DISPLAY BRING-UP, called as ONE BLOCK.
 *
 * Disassembling the PS5 kernel found the routine that does the whole job, and it is gated on the
 * IC type -- it runs only for IC type 2, i.e. exactly our chip:
 *
 *     0x80d67963  call 0x804cbc40                  get IC type
 *     0x80d67968  cmp  $0x2,%eax ; jne skip        <-- FLAVA3 only
 *     0x80d6796d  call 0x80d2ba50  }               HDCP/encryption region (0xB1Bxxx-0xB1Cxxx)
 *     0x80d67972  call 0x80d2c5b0  }  no arguments set at the call site
 *     0x80d67977  call 0x80d2c7c0  }
 *     0x80d6797c  call 0x80d2c900  }
 *     0x80d67981  call 0x8049cb20(0..3)            four per-domain enables
 *     0x80d679a6  call 0x804cbe60
 *     0x80d679af  call sceSetWaitPwOnSequence()    "power on sequence"
 *     0x80d679b4  call sceSetWaitPll()
 *     0x80d679b9  call 0x80b793b0
 *     0x80d679c2  call 0x80d2bb40
 *
 * Every one of those is upstream of what this file used to call, and four of them live in the
 * HDCP/encryption region -- which is exactly what a bridge would need before it will emit.
 *
 * WHY A BLOCK AND NOT INDIVIDUAL CALLS: this routine lives inside a 4-argument function
 * (mov %edi,%r12d / mov %rsi,%r14 / mov %edx,%r15d / mov %ecx,%ebx at its entry) that has ZERO
 * direct callers -- it is registered as a callback and invoked indirectly, so its arguments cannot
 * be read from a call site. Calling it as void(void) is what killed two earlier builds.
 *
 * But the body itself touches NO arguments and NO stack (only calls, compares and globals), so it
 * can be entered directly at the body. Its last instruction is `pop %rbp; ret`, so one push makes
 * its own return work: push rbp; call <body>  ->  body's `pop %rbp` restores our rbp and its `ret`
 * lands back here. That runs the entire sequence, in the PS5 OS's order, with none of its four
 * arguments needed. */
/* The shim that entered the routine's body mid-function PANICKED -- the body does depend on
 * something from its prologue that is not visible from the body alone. Do not reintroduce it.
 * Everything below is the same sequence, called normally, one operation at a time. */
static const struct ps5_op ps5_hdmi_ops[] = {
  /* --- first half of the routine, before the IC-type check --- */
  { 0x2BB8D0ULL, 0 },
  { 0x2BBB20ULL, 0 },
  { 0x2BBC70ULL, 0 },
  { 0x2BBE30ULL, 0 },   /* gate -- PS5 proceeds only if this returns 1 */
  { 0xBAECD0ULL, 0 },
  { 0x28B970ULL, 0 },
  { 0x6D4F00ULL, 0 },
  { 0xA8F0D0ULL, 0 },
  { 0x4B12D0ULL, 0 },   /* "Set BackToUnplugged Sequence" */
  { 0x4B14C0ULL, 0 },
  { 0x2BBC40ULL, 0 },   /* returns the IC type */

  /* --- the FLAVA3-only block (IC type 2). Four of these live in the HDCP/encryption region,
   *     which is where a bridge would need to be told it may emit. All zero-argument: the PS5 OS
   *     sets no argument at any of their call sites. --- */
  { 0xB1BA50ULL, 0 },
  { 0xB1C5B0ULL, 0 },
  { 0xB1C7C0ULL, 0 },
  { 0xB1C900ULL, 0 },
  { 0x28CB20ULL, 0 },   /* per-domain enable 0 */
  { 0x28CB20ULL, 1 },   /*                    1 */
  { 0x28CB20ULL, 2 },   /*                    2 */
  { 0x28CB20ULL, 3 },   /*                    3 */
  { 0x2BBE60ULL, 0 },
  { 0x4B1690ULL, 0 },   /* sceSetWaitPwOnSequence */
  { 0x4B1810ULL, 0 },   /* sceSetWaitPll          */
  /* THREE ENTRIES REMOVED HERE -- 0xB1C3B0, 0xB9B4A0, 0xB1BEF0. THEY ARE NOT FUNCTIONS.
   *
   * This is the hang that killed every 13.x wake, found offline (2026-10-13 late) against
   * I:\americana\...\x86_kernel.elf.
   *
   * Each of the three, disassembled at its own address, opens by writing through a register it
   * never sets -- and not a parameter register either:
   *
   *   0xB1C3B0:  41 c7 46 02 00 00 66 41   movl $0x46660000, 0x2(%r14)
   *   0xB9B4A0:  00 48 8b 0b 48 89 08 f6   add  %cl, -0x75(%rax)     <- mid-instruction
   *   0xB1BEF0:  66 41 89 46 08            mov  %ax, 0x8(%r14)
   *
   * %r14 and %rax are not argument registers, so a real function entry could not begin this way.
   * Searching backwards for the nearest `55 48 89 e5` prologue puts them +112, +1232 and +624
   * bytes INSIDE other functions. The other six FLAVA3-block addresses (0xB1BA50, 0xB1C5B0,
   * 0xB1C7C0, 0xB1C900, 0xB1BB40, 0x6DA070) all carry a clean prologue AT offset 0.
   *
   * So calling them jumps mid-function with whatever happens to be in %r14/%rax and writes
   * through it -- a wild store, which is exactly the "no output at all" hang. They match working
   * rule 5 precisely: they are false call targets read out of a misaligned disassembly of the
   * routine at preslide 0x6D7610.
   *
   * PROBE A (known-good 12 + rows 1-11, i.e. skipping these) BOOTED LINUX on 2026-10-13 22:34,
   * which is the hardware confirmation that removing them is the right direction.
   *
   * Do NOT re-add them without re-deriving them from an ALIGNED disassembly of that routine, and
   * verify the address carries a prologue at offset 0 before it is called.
   *
   * Kept here, commented, so the three addresses are not lost: 0xB1C3B0, 0xB9B4A0, 0xB1BEF0. */
  { 0xB1BB40ULL, 0 },

  /* --- tail of the routine --- */
  { 0x6DA070ULL, 0 },

  /* --- the configuration operations proven to work already --- */
  /* a2 = 0x7f0 (ICC_MSG_MAX_SIZE), which this function's own callers in the kernel
   * pass as esi. Previously omitted entirely, so rsi held leftover garbage. */
  { 0x968DF0ULL, 1, 2, 0x7f0ULL },   /* Start EMC HDMI service */
  { 0x4B6AF0ULL, 0 },   /* Init Video             */
  { 0x4B2570ULL, 1 },   /* Video Basic Config     */
  { 0x4B1FE0ULL, 0 },   /* Hdmi OutputMode        */
  { 0x4B1E80ULL, 0 },   /* Video Mute Control (0 = unmute) */
};

/* BISECT LEVER (added 2026-10-13, late).
 *
 * The per-op `SCK>5h-op-N-ok` markers are NOT a usable readout: the shellcode's output during
 * this window loses most of its bytes to the PS5 OS console driver writing the same UART, and in
 * every run on record only ONE marker survived -- always the last index before `ps5-ops-done`
 * (op-5-ok twice, op-12-ok once). So a marker tells you the LAST op that ran, never which one
 * killed it.
 *
 * What IS reliable is the binary outcome: does Linux boot, or not. That makes the bisect a binary
 * search over the op COUNT rather than over markers:
 *
 *     make -C shellcode_kernel EXTRA_CFLAGS=-DPS5_OP_LIMIT=16
 *     make            # relinks the loader with the regenerated blob
 *
 * Defaults to 0 = "the whole table", so an untouched build is byte-for-byte unchanged. 0 is also
 * what a stray -DPS5_OP_LIMIT=0 gives, which is why 0 means FULL and not "run nothing".
 */
#ifndef PS5_OP_LIMIT
#define PS5_OP_LIMIT 0
#endif

int ps5_hdmi_op_count(void) {
  int all = (int)(sizeof(ps5_hdmi_ops) / sizeof(ps5_hdmi_ops[0]));
#if PS5_OP_LIMIT > 0
  return PS5_OP_LIMIT < all ? PS5_OP_LIMIT : all;
#else
  return all;
#endif
}

/* OP SKIP MASK -- bit i (0-based) set => op i+1 is CALLED. Default: all of them.
 *
 * PS5_OP_LIMIT above can only express a PREFIX, and the recovered known-good build was a SUBSET,
 * not a prefix (CONTEXT §9s: the 12 ops that booted Linux are current rows 16-22 and 28-32). So a
 * prefix cap cannot ask the one question worth asking -- "do the 20 rows that have never been in a
 * booting build, on their own, still boot?" A mask can:
 *
 *   make -C shellcode_kernel EXTRA_CFLAGS=-DPS5_OP_MASK=0x07C07FFF   # the 20 suspects only
 *   make -C shellcode_kernel EXTRA_CFLAGS=-DPS5_OP_MASK=0xF83F8000   # the 12 known-good, control
 *   make                                                            # all 32 (default)
 *
 * The two masks above are exact complements (0xF83F8000 | 0x07C07FFF == 0xFFFFFFFF), which is worth
 * checking before trusting a result: it is the one arithmetic slip that would silently test the
 * wrong set. A masked-out op is skipped silently; main.c's loop still prints its op-N markers, so
 * the indices keep their meaning.
 *
 * With the default, the extra test is compiled OUT entirely -- an untouched build is unchanged. */
#ifndef PS5_OP_MASK
#define PS5_OP_MASK 0xFFFFFFFFu
#endif

/* ---- READ THE BRIDGE IN THE RESUME WINDOW (build with -DPS5_BRIDGE_PROBE) ---- */
#define PRESLIDE_ICC_QUERY   0xA3F490ULL   /* (query, reply), kernel icc_query */
#define PRESLIDE_ICC_QBUF    0x968DA0ULL   /* (1) -> query buffer  */
#define PRESLIDE_ICC_RBUF    0x968DC0ULL   /* (1) -> reply buffer  */
#define ICC_BUF_SIZE         2032          /* 0x7F0, what 0x968DE0() returns */

/* One i2c major 1 / minor 1 block read, printed. Returns the ICC status byte, or -1
 * if the query itself failed. */
int ps5_bridge_get(unsigned int reg, unsigned int n, unsigned char *out) {
  int st = ps5_bridge_read_raw(reg, n, out);
  return st;
}

int ps5_bridge_read_raw(unsigned int reg, unsigned int n, unsigned char *out) {
  unsigned char *(*get_q)(int) =
      (unsigned char *(*)(int))(unsigned long)(ktext_base() + PRESLIDE_ICC_QBUF);
  unsigned char *(*get_r)(int) =
      (unsigned char *(*)(int))(unsigned long)(ktext_base() + PRESLIDE_ICC_RBUF);
  int (*icc)(unsigned char *, unsigned char *) =
      (int (*)(unsigned char *, unsigned char *))(unsigned long)(ktext_base() +
                                                                PRESLIDE_ICC_QUERY);
  unsigned char *q = get_q(1);
  unsigned char *r = get_r(1);
  unsigned int i2c_len = 4 + 4 + 4;   /* icc_i2c_msg + i2c_cmd_hdr + 4-byte payload */
  int rc;

  if (!q || !r)
    return -1;
  for (unsigned int i = 0; i < ICC_BUF_SIZE; i++)
    q[i] = 0;

  q[1] = 0x10;                 /* service_id = HDMI          */
  q[2] = 0; q[3] = 0;          /* msg_type = 0               */
  q[8] = (unsigned char)(12 + i2c_len);   /* length, low  */
  q[9] = (unsigned char)((12 + i2c_len) >> 8);

  /* icc_i2c_msg { u8 code; u16 length; u8 count; } then i2c_cmd_hdr + payload */
  q[12] = 1;                               /* code  */
  q[13] = (unsigned char)i2c_len;          /* length low  */
  q[14] = (unsigned char)(i2c_len >> 8);
  q[15] = 1;                               /* count */
  q[16] = 1;                               /* major = 1 */
  q[17] = 4 + 4;                           /* hdr length = sizeof(hdr) + payload */
  q[18] = 1;                               /* minor = 1 */
  q[19] = 1;                               /* count */
  q[20] = (unsigned char)n;                /* payload: bytes to read */
  q[21] = (unsigned char)(reg >> 8);
  q[22] = (unsigned char)(reg & 0xff);
  q[23] = 0;

  rc = icc(q, r);
  if (rc)
    return -1;
  /* reply: 12-byte header, status at +12, values from +20 */
  if (out)
    for (unsigned int i = 0; i < n; i++)
      out[i] = r[20 + i];
  return r[12];
}

/* The lock indicator: measured stream timing and the lock bits. On 4.51 with a picture
 * 0x6070 reads 98 08 65 04 (h total 2200, v total 1125) and 0x60f9 reads 0x1b; on 13.60
 * under Linux both read zero. */
void ps5_bridge_probe(const char *when) {
  unsigned char v705f[1] = {0}, v6070[4] = {0}, v60f9[1] = {0}, v6208[4] = {0};
  int s1, s2, s3, s4;

  /* The resume console drops all but the last line, so read everything quietly and then
   * emit a SINGLE line. 0x705f is the control: it is known writable and readable, so a
   * sane value there proves the ICC path works and the zeros elsewhere are real. */
  s1 = ps5_bridge_get(0x705f, 1, v705f);
  s2 = ps5_bridge_get(0x6070, 4, v6070);
  s3 = ps5_bridge_get(0x60f9, 1, v60f9);
  s4 = ps5_bridge_get(0x6208, 4, v6208);

  printf("SCK>BR %s vspe=%02x vs=%d pe=%d phy_rc=%d vs_rc=%d | "
         "705f(%d)=%02x 6070(%d)=%02x%02x%02x%02x 60f9(%d)=%02x 6208(%d)=%02x%02x%02x%02x"
         " | LOCK=%s\n",
         when,
         (unsigned int)g_dp_vspe_raw, (int)g_dp_vswing, (int)g_dp_preemph,
         (int)(int64_t)g_rc_transmitter, (int)(int64_t)g_rc_voltage,
         s1, v705f[0],
         s2, v6070[0], v6070[1], v6070[2], v6070[3],
         s3, v60f9[0],
         s4, v6208[0], v6208[1], v6208[2], v6208[3],
         (v60f9[0] == 0x1b || v6070[0] || v6070[1]) ? "YES" : "no");
}

void call_ps5_hdmi_op(int which) {
  void (*fn)(int);
  if (which < 0 || which >= ps5_hdmi_op_count())
    return;
#if PS5_OP_MASK != 0xFFFFFFFFu
  if (!(((unsigned long long)PS5_OP_MASK >> which) & 1ULL))
    return;
#endif
  fn = (void (*)(int))(unsigned long)(ktext_base() + ps5_hdmi_ops[which].preslide);
  if (ps5_hdmi_ops[which].argc == 2) {
    void (*fn2)(int, uint64_t) =
        (void (*)(int, uint64_t))(unsigned long)(ktext_base() +
                                                ps5_hdmi_ops[which].preslide);
    fn2(ps5_hdmi_ops[which].arg, ps5_hdmi_ops[which].arg2);
    return;
  }
  fn(ps5_hdmi_ops[which].arg);
}

/* ---- THE OS'S OWN BRING-UP ROUTINE, CALLED WHOLE  (build with -DPS5_HDMI_BRINGUP_CALL) ----
 *
 * CONTEXT §9w. The 29-row table above is a FLATTENING of the PS5 OS routine at preslide
 * 0xB578E0, and the flattening is lossy in ways that matter:
 *
 *   - 0xB578E0 gates on three conditions the table cannot express: `cmp eax,1` after
 *     0x2BBE30, `cmp [0x3D24218],1`, and the IC-type `cmp eax,2` after 0x2BBC40 that guards
 *     the whole FLAVA3 block. Calling the callees flat runs that block unconditionally.
 *   - the table omits 0x9693B0 (Read Aksv) and the routine's final 0x968EF0 (Ctrl Event).
 *   - §9u removed "0xB9B4A0" as a non-function; the routine actually calls 0x99B4A0. The
 *     entry was a digit transposition, so a real call was dropped on a correct premise.
 *
 * The routine takes NO arguments -- it loads its context from the global at preslide
 * 0x3D21868 and hands it to 0x926120, whose first use is `test byte [rdi+0xEE],0x20`.
 * A null context therefore FAULTS, which is why the guard below is not optional.
 *
 * Both the routine and that head call are byte-identical in the retail and devkit 13.60
 * images (findings/AUDIT-devkit-vs-retail-offsets-13.60.md), so this builds for either.
 *
 * UNPROVEN ON HARDWARE: whether the context global is populated during the resume window.
 * The guard turns "not yet populated" into a clean rc=-1 instead of a panic. */
#define PS5_HDMI_BRINGUP_FN   0xB578E0ULL
#define PS5_HDMI_BRINGUP_CTX  0x3D21868ULL

int ps5_hdmi_bringup_call(void) {
  uint64_t ctx = *(volatile uint64_t *)(unsigned long)(ktext_base() + PS5_HDMI_BRINGUP_CTX);

  if (ctx == 0)
    return -1;

  ((void (*)(void))(unsigned long)(ktext_base() + PS5_HDMI_BRINGUP_FN))();
  return 0;
}

/* ---- THE FULL INIT ROUTINE  (build with -DPS5_HDMI_INIT_CALL) ----
 *
 * 0xB578E0 (above) ran on the devkit at 2026-10-14 00:43 and returned rc=0 -- the context
 * global WAS populated in the resume window and the routine executed -- and the panel stayed
 * black. 0xB578E0 is the resume-LITE path: it never starts the EMC HDMI service.
 *
 * 0xB579F0 is the full one, and it is the true counterpart of 4.51's single working routine
 * 0xAAE3B0 (CONTEXT 9w). Its call sequence:
 *
 *   EMC FW Version (0x969000) ; cmp eax,1 -> gate on the whole body
 *   Service Version / Config Service Version / Get HDMI Configuration / IC type
 *   *** Start EMC HDMI service (0x968DF0) ***      <- absent from 0xB578E0 entirely
 *   Set BackToUnplugged x2 / FLAVA3 block / 28CB20 x4
 *   sceSetWaitPwOnSequence / sceSetWaitPll / Read Aksv
 *   Ctrl HDCP (0xB1BF80) / Ctrl Event (0x968EF0)   <- 4.51's tail, exactly
 *
 * Zero-argument: the only global it touches up front is the stack canary. No ctx guard is
 * needed or possible -- unlike 0xB578E0 it does not load a context pointer at all.
 *
 * The two reported values are pure getters, verified as `mov eax,[global] ; ret`:
 *   0x2BBC40 = HDMI IC type (FLAVA3 == 2; the FLAVA3 block is gated on it)
 *   0x2BBE30 = the flag 0xB578E0 gates on with `cmp eax,1`
 * Printing them before and after says whether the sequence saw a live HDMI block at all, which
 * rc alone cannot. Byte-identical in retail and devkit 13.60 images. */
#define PS5_HDMI_INIT_FN      0xB579F0ULL
#define PS5_HDMI_IC_TYPE_FN   0x2BBC40ULL
#define PS5_HDMI_GATE_FN      0x2BBE30ULL

int ps5_hdmi_ic_type(void) {
  return ((int (*)(void))(unsigned long)(ktext_base() + PS5_HDMI_IC_TYPE_FN))();
}

int ps5_hdmi_gate_flag(void) {
  return ((int (*)(void))(unsigned long)(ktext_base() + PS5_HDMI_GATE_FN))();
}

void ps5_hdmi_init_call(void) {
  ((void (*)(void))(unsigned long)(ktext_base() + PS5_HDMI_INIT_FN))();
}

static int mp3_set_hdcp_packet(int be, int mode) {
  mp3_req[0] = be;
  mp3_req[1] = mode;
  if (!mp3_invoke) return -0x5102;
  return mp3_invoke(21, mp3_req, mp3_rsp);
}

static int mp3_enable_output(int be, int mode) {
  mp3_req[0] = be;
  mp3_req[1] = mode;
  if (!mp3_invoke) return -0x5103;
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

  /* Keep the HV trampoline (patch_hv()'s shellcode_identity_and_jmp, written AT
   * args.hv_code_cave_pa) mapped after the `mov cr3` it itself executes. The 5 entries above
   * only cover 0-5GB; on PS5 Pro, hv_code_cave_pa is ~38GB (region base + 0x800000 +
   * 0x6F00), well outside that -- without this, the CPU faults on the very next instruction
   * fetch after the CR3 switch, with no handler (identity map has no fault path), which
   * triple-faults the whole console. This is the actual cause of the "pulses then shuts off"
   * crash on Pro even after the H/code-base/movabs fixes above (2026-10-18, cross-checked
   * against github.com/ps5-linux/ps5-linux-loader PR #47, tested working on real retail Pro). */
  uint64_t cave_index = args.hv_code_cave_pa >> 30;
  if (cave_index >= l3_size) {
    *(uint64_t *)PHYS_TO_DMAP(l40_l3_addr + cave_index * 8) =
        (cave_index << 30) | 0x83;
  }

  // Install shellcode_hv
  memcpy((void *)PHYS_TO_DMAP(cave_hv_code), shellcode_hv_bin,
         shellcode_hv_bin_len);
}

void patch_hv(void) {
  /* PS5 Pro's HV code cave sits near 38GB physical -- the original `mov rax, imm32`
   * encoding below sign/zero-extends only a 32-bit immediate, so it silently truncated the
   * address and `jmp rax` landed on garbage on Pro (the actual cause behind repeated
   * console hard-crashes on wake, found 2026-10-18 by cross-checking against
   * github.com/ps5-linux/ps5-linux-loader PR #47, which hit and fixed the exact same bug).
   * Devkit/base's cave_pa (~0x628xxxxx) fits in 32 bits, so this branch keeps the original
   * encoding there -- zero behavior change on already-working consoles. */
  if (args.hv_code_cave_pa > 0x7fffffffULL) {
    uint8_t shellcode_jmp[] = {0x48, 0xB8, 0xAA, 0xAA, 0xAA,
                               0xAA, 0xAA, 0xAA, 0xAA, 0xAA, // movabs rax, imm64
                               0xFF, 0xE0};                   // jmp rax
    *(uint64_t *)(&shellcode_jmp[2]) = args.hv_code_cave_pa;
    memcpy((void *)PHYS_TO_DMAP(args.hv_handle_vmexit_pa), shellcode_jmp,
           sizeof(shellcode_jmp));
  } else {
    // Jump to shellcode final identity mapping
    uint8_t shellcode_jmp[] = {0x48, 0xC7, 0xC0, 0xAA,
                               0xAA, 0xAA, 0xAA, // mov rax, 0xAAAAAAAA
                               0xFF, 0xE0};      // jmp rax

    // Update code cave in hv 1:1 region
    *(uint32_t *)(&shellcode_jmp[3]) = (uint32_t)args.hv_code_cave_pa;

    // Just patch the VMEXIT handler directly, avoiding all checks
    memcpy((void *)PHYS_TO_DMAP(args.hv_handle_vmexit_pa), shellcode_jmp,
           sizeof(shellcode_jmp));
  }

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

/* Diagnostic markers: straight to the UART TX register, so they are visible even before the
 * kernel console is up. The console powers OFF on the wake, so the last marker printed is the
 * step that kills it -- that is the whole point of this instrumentation. */
/* Also counts steps, so main.c can report how far this function got even though none of these
 * markers are actually visible on the wire. */
static void m(const char *s) {
  g_step++;
  printf("%s", s);   /* PRINTFPROBE: was puts_uart (no-op under PS5_NO_MARKS); printf is live */
}

/* Report a RETURN VALUE on the UART, not just "we got here".
 *
 * Every display bring-up call in this function had its return value discarded, so a rejected mp3
 * command or a failed ATOM transmitter command looked exactly like success -- and this project has
 * been bitten by silent failures repeatedly. dp_enable_link_phy is an ATOM command-table
 * interpreter keyed on the cmd byte, so 0x4C not resolving in the PS5's VIBIOS (113-AMDOBR-016)
 * would return an error here and say nothing.
 *
 * Written by hand rather than via printf(): the markers below are known to reach the UART because
 * puts_uart pokes the TX register directly, whereas the kernel console path needs the
 * KERNEL_UART_OVERRIDE patch to have taken.
 */
static void m_hex(const char *label, uint64_t v) {
  char buf[64];
  int i = 0, j;
  while (label[i] && i < 38) { buf[i] = label[i]; i++; }
  buf[i++] = '=';
  buf[i++] = '0';
  buf[i++] = 'x';
  for (j = 15; j >= 0; j--) {
    int nib = (int)((v >> (j * 4)) & 0xF);
    buf[i++] = (char)(nib < 10 ? '0' + nib : 'a' + nib - 10);
  }
  buf[i++] = '\n';
  buf[i] = 0;
  puts_uart(args.dmap_base, (const uint8_t *)buf);
}

/* The DP link has to be up before anything that acts on it. Upstream calls mp3_initialize()
 * immediately after enabling the link with no wait at all, so the HDCP/output commands may have
 * been running against a link that was not yet there -- which would be another silent no-op.
 * Spun on rdtsc; this part is ~3.5 GHz and 100 ms is far coarser than that estimate's error. */
static void delay_ms(uint32_t ms) {
  uint32_t lo, hi;
  uint64_t start, now;
  __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
  start = ((uint64_t)hi << 32) | lo;
  do {
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    now = ((uint64_t)hi << 32) | lo;
  } while (now - start < (uint64_t)ms * 3500000ULL);
}

void boot_linux(void) {
  int rc;
  m("SCK>B0-enter\n");
  patch_hv();
  m("SCK>B1-patch_hv-done\n");

  // Common bootloader code
  install_hv_code();
  m("SCK>B2-install_hv_code-done\n");

  memcpy((void *)PHYS_TO_DMAP(0xC0000), (void *)g_vbios, 0x10000);
  m("SCK>B3-vbios-done\n");

  // Enable DP phys link. Reached via the THUNK at 0x39B3B0, not the raw 0xC0EAA0 -- see the note
  // on .FUN_TRANSMITTER_CONTROL in offsets.c: the call is indirect, and this project has already
  // established that an indirect call must land on the thunk (FUN_SMP_NO_RENDEVOUS_BARRIER).
  rc = dp_enable_link_phy(4, 30);
  g_rc_transmitter = (uint64_t)(int64_t)rc;
  m_hex("SCK>B4-dp-link-rc", g_rc_transmitter);

  /* THE GAP: without this the link can train while the FLAVA3's receiver cannot recover a signal.
   * See the note on dp_set_voltage_and_preemphasis() above. */
#ifdef PS5_NO_VSWING
  /* BISECT (2026-10-14): our fork panics on 4.51 with `Fatal trap 31: security exception` at
   * resume, where upstream boots with video. Rung 1c (our loader + upstream's shellcode_kernel)
   * BOOTED WITH VIDEO, so the fault is in this shellcode. This ATOM transmitter command
   * (action 11, SET_VOLTAGE_AND_PREEMPASIS) is the only new hardware command we added -- upstream
   * defines the constant and never issues it. This flag takes it out. */
  g_rc_voltage = 0xD15AB1EDULL;
#else
  {
    /* The EMC publishes the required drive; getHdmiConfiguration caches it. 0xFF means it
     * said "unavailable", in which case fall back to the compile-time values. */
    unsigned char vspe =
        *(volatile unsigned char *)(unsigned long)(ktext_base() + PRESLIDE_DP_VSPE);
    int vs = DP_VSWING, pe = DP_PREEMPH;

    if (vspe != 0xFF) {
      vs = (vspe >> 3) & 7;
      pe = vspe & 7;
    }
    g_dp_vspe_raw = vspe;
    g_dp_vswing = (uint64_t)vs;
    g_dp_preemph = (uint64_t)pe;
    rc = dp_set_voltage_and_preemphasis(4, vs, pe);
  }
  g_rc_voltage = (uint64_t)(int64_t)rc;
  m_hex("SCK>B4a-vswing-rc", g_rc_voltage);
#endif

  // Let the link actually come up before the calls that act on it.
  delay_ms(100);
  m("SCK>B4b-delay-done\n");

  // Initialize hdcp in mp3.
  rc = mp3_initialize ? mp3_initialize(0) : -0x5104;
  g_rc_mp3_init = (uint64_t)(int64_t)rc;
  m_hex("SCK>B5a-mp3init-rc", g_rc_mp3_init);
  rc = mp3_set_hdcp_packet(0, 1);
  g_rc_mp3_hdcp = (uint64_t)(int64_t)rc;
  m_hex("SCK>B5b-hdcp-rc", g_rc_mp3_hdcp);
  rc = mp3_enable_output(0, 1);
  g_rc_mp3_output = (uint64_t)(int64_t)rc;
  m_hex("SCK>B5c-output-rc", g_rc_mp3_output);
  m("SCK>B5-mp3-done\n");

  /* The PS5 OS's own HDMI bring-up -- the part the Linux driver does not do.
   *
   * BISECT: the previous build called all six of these and the console never reached Linux
   * (pulsing blue, no boot, nothing after the S3 suspend in the log). So exactly one of them is
   * fatal. This build calls ONLY Hdmi OutputMode -- the op most directly responsible for enabling
   * the output, and the only one whose prologue I read by hand and confirmed takes no arguments
   * (push rbp; mov rbp,rsp; push r15,r14,rbx,rax; call ... -- no rdi/rsi read before the first
   * call). If the boot fails with this alone, this call is the culprit. If it boots, the other
   * five go back one per cycle.
   *
   * The rest stay defined above so re-enabling one is a single line:
   *   call_ps5_op("SCK>B7b-start-emc-hdmi\n",   PRESLIDE_START_EMC_HDMI);
   *   call_ps5_op("SCK>B7c-init-video\n",       PRESLIDE_INIT_VIDEO);
   *   call_ps5_op("SCK>B7d-video-basic-cfg\n",  PRESLIDE_VIDEO_BASIC_CFG);
   *   call_ps5_op("SCK>B7e-reset-video-if\n",   PRESLIDE_RESET_VIDEO_IF);
   *   call_ps5_op("SCK>B7g-video-mute-ctrl\n",  PRESLIDE_VIDEO_MUTE_CTRL);
   */
  /* The PS5 OS HDMI operations are invoked from main.c instead -- see the note on
   * ps5_hdmi_ops[] above: a fatal op here would kill the boot before anything could be reported. */

  // Copy bzImage and initrd into contiguous memory.
  memcpy(&info, (void *)args.linux_info_va, sizeof(struct linux_info));
  m("SCK>B6-linux_info-copied\n");

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
  m("SCK>B7-linux_info-staged\n");
  memcpy((void *)PHYS_TO_DMAP(info.bzimage), (void *)bzimage,
         info.bzimage_size);
  m("SCK>B8-bzimage-copied\n");
  memcpy((void *)PHYS_TO_DMAP(info.initrd), (void *)initrd, info.initrd_size);
  m("SCK>B9-initrd-copied\n");
}
