#include "display_ops_1160.h"
#include "shellcode_kernel_args.h"
#include "utils.h"
#include <stddef.h>

/*
 * The 13.60 wake blob runs a table of kernel display calls after the
 * VBIOS/DP/MP3 handoff and before the final SMP rendezvous. These are the
 * matching 11.60 functions, in the same order and with the same 0x18-byte
 * records. Every call takes arg1_edi, mode 2 calls also take arg2_rsi.
 */
_Static_assert(sizeof(ps5_display_op_1160) == 0x18,
               "display-op record layout changed");

const ps5_display_op_1160 ps5_display_ops_1160[29] = {
    {0x00362730, 0, 0, 0},
    {0x00362980, 0, 0, 0},
    {0x00362AD0, 0, 0, 0},
    {0x00362C90, 0, 0, 0},
    {0x00C16F70, 0, 0, 0},
    {0x00333410, 0, 0, 0},
    {0x00751F20, 0, 0, 0},
    {0x00B01800, 0, 0, 0},
    {0x005381C0, 0, 0, 0},
    {0x005383B0, 0, 0, 0},
    {0x00362AA0, 0, 0, 0},
    {0x00B88B80, 0, 0, 0},
    {0x00B896F0, 0, 0, 0},
    {0x00B89900, 0, 0, 0},
    {0x00B89A40, 0, 0, 0},
    {0x00334460, 0, 0, 0},
    {0x00334460, 1, 0, 0},
    {0x00334460, 2, 0, 0},
    {0x00334460, 3, 0, 0},
    {0x00362CC0, 0, 0, 0},
    {0x00538580, 0, 0, 0},
    {0x00538700, 0, 0, 0},
    {0x00B88C70, 0, 0, 0},
    {0x007585F0, 0, 0, 0},
    {0x009DC910, 1, 2, 0x7F0},
    {0x0053D9F0, 0, 0, 0},
    {0x00539460, 1, 0, 0},
    {0x00538ED0, 0, 0, 0},
    {0x00538D70, 0, 0, 0},
};

/* 11.00, 11.20 and 11.40 homologs. */
const ps5_display_op_1160 ps5_display_ops_1100[29] = {
    {0x00362B10, 0, 0, 0}, {0x00362D60, 0, 0, 0}, {0x00362EB0, 0, 0, 0},
    {0x00363070, 0, 0, 0}, {0x00C167C0, 0, 0, 0}, {0x003337F0, 0, 0, 0},
    {0x00751DB0, 0, 0, 0}, {0x00B01070, 0, 0, 0}, {0x00538050, 0, 0, 0},
    {0x00538240, 0, 0, 0}, {0x00362E80, 0, 0, 0}, {0x00B883D0, 0, 0, 0},
    {0x00B88F40, 0, 0, 0}, {0x00B89150, 0, 0, 0}, {0x00B89290, 0, 0, 0},
    {0x00334840, 0, 0, 0}, {0x00334840, 1, 0, 0}, {0x00334840, 2, 0, 0},
    {0x00334840, 3, 0, 0}, {0x003630A0, 0, 0, 0}, {0x00538410, 0, 0, 0},
    {0x00538590, 0, 0, 0}, {0x00B884C0, 0, 0, 0}, {0x00758480, 0, 0, 0},
    {0x009DC2D0, 1, 2, 0x7F0}, {0x0053D880, 0, 0, 0}, {0x005392F0, 1, 0, 0},
    {0x00538D60, 0, 0, 0}, {0x00538C00, 0, 0, 0},
};

const ps5_display_op_1160 ps5_display_ops_1120[29] = {
    {0x00362B10, 0, 0, 0}, {0x00362D60, 0, 0, 0}, {0x00362EB0, 0, 0, 0},
    {0x00363070, 0, 0, 0}, {0x00C167C0, 0, 0, 0}, {0x003337F0, 0, 0, 0},
    {0x00751DB0, 0, 0, 0}, {0x00B01070, 0, 0, 0}, {0x00538050, 0, 0, 0},
    {0x00538240, 0, 0, 0}, {0x00362E80, 0, 0, 0}, {0x00B883D0, 0, 0, 0},
    {0x00B88F40, 0, 0, 0}, {0x00B89150, 0, 0, 0}, {0x00B89290, 0, 0, 0},
    {0x00334840, 0, 0, 0}, {0x00334840, 1, 0, 0}, {0x00334840, 2, 0, 0},
    {0x00334840, 3, 0, 0}, {0x003630A0, 0, 0, 0}, {0x00538410, 0, 0, 0},
    {0x00538590, 0, 0, 0}, {0x00B884C0, 0, 0, 0}, {0x00758480, 0, 0, 0},
    {0x009DC2D0, 1, 2, 0x7F0}, {0x0053D880, 0, 0, 0}, {0x005392F0, 1, 0, 0},
    {0x00538D60, 0, 0, 0}, {0x00538C00, 0, 0, 0},
};

const ps5_display_op_1160 ps5_display_ops_1140[29] = {
    {0x00363510, 0, 0, 0}, {0x00363760, 0, 0, 0}, {0x003638B0, 0, 0, 0},
    {0x00363A70, 0, 0, 0}, {0x00C173B0, 0, 0, 0}, {0x003341F0, 0, 0, 0},
    {0x007527C0, 0, 0, 0}, {0x00B01C60, 0, 0, 0}, {0x00538A60, 0, 0, 0},
    {0x00538C50, 0, 0, 0}, {0x00363880, 0, 0, 0}, {0x00B88FC0, 0, 0, 0},
    {0x00B89B30, 0, 0, 0}, {0x00B89D40, 0, 0, 0}, {0x00B89E80, 0, 0, 0},
    {0x00335240, 0, 0, 0}, {0x00335240, 1, 0, 0}, {0x00335240, 2, 0, 0},
    {0x00335240, 3, 0, 0}, {0x00363AA0, 0, 0, 0}, {0x00538E20, 0, 0, 0},
    {0x00538FA0, 0, 0, 0}, {0x00B890B0, 0, 0, 0}, {0x00758E90, 0, 0, 0},
    {0x009DCE90, 1, 2, 0x7F0}, {0x0053E290, 0, 0, 0}, {0x00539D00, 1, 0, 0},
    {0x00539770, 0, 0, 0}, {0x00539610, 0, 0, 0},
};

typedef uint64_t (*display_op1_fn)(uint32_t);
typedef uint64_t (*display_op2_fn)(uint32_t, uint64_t);

// Kept out of line so each kernel call is a tail jump, as in the 13.60 blob.
__attribute__((noinline)) static uint64_t
dispatch_ps5_display_op_1160(uint32_t index) {
  if (index >= 29)
    return 0;

  const ps5_display_op_1160 *op;
  switch (args.fw_version) {
  case 0x1100: op = &ps5_display_ops_1100[index]; break;
  case 0x1120: op = &ps5_display_ops_1120[index]; break;
  case 0x1140: op = &ps5_display_ops_1140[index]; break;
  default:     op = &ps5_display_ops_1160[index]; break;
  }
  const ps5_display_op_1160 *op = &ps5_display_ops_1160[index];
  const uintptr_t target = args.ktext + op->ktext_offset;

  if (op->mode == 2)
    return ((display_op2_fn)target)(op->arg1_edi, op->arg2_rsi);
  return ((display_op1_fn)target)(op->arg1_edi);
}

void run_ps5_display_ops_1160(void) {
  for (uint32_t index = 0; index < 29; index++) {
    printf("11.60 display op %u starting\n", index + 1);
    dispatch_ps5_display_op_1160(index);
    printf("11.60 display op %u returned\n", index + 1);
  }
}
