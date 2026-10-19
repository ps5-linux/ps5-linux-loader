#include "main.h"
#include "boot_linux.h"
#include "hv_defeat_0304.h"
#include "utils.h"
#include <stddef.h>

shellcode_kernel_args args = {0};

// We are being called instead of AcpiSetFirmwareWakingVector
__attribute__((section(".entry_point"))) uint32_t main(uint64_t add1,
                                                       uint64_t add2) {
  // We will do main checks on .text only with a reference to .data
  volatile shellcode_kernel_args *args_ptr =
      (volatile shellcode_kernel_args
           *)0x11AA11AA11AA11AA; // To be replaced with proper address in .kdata

  // "Hide" the pointer from the optimizer
  __asm__ volatile("" : "+r"(args_ptr));

  /* FIRST, before touching anything else: prove we were entered at all.
   *
   * The ROP has already opened the UART gate, and reading args_ptr->dmap_base is a dmap read,
   * which is always safe. Everything after this point can fault on a page-permission problem:
   * activate_uart() writes args_ptr->kernel_uart_override, which lives IN .text, so if
   * remove_xotext() did not actually make .text writable on 13.60 that write #PFs on the IST
   * stack and the console triple-faults with no output -- exactly what we observe. */
  mark(args_ptr, "SCK>0-entered\n");

  // We don't have required information - Abort
  if ((args_ptr->fun_printf & 0xFFFF) == 0) {
    return -1;
  }

  /* PRINTFPROBE2: live entry marker via the kernel's own printf (args->fun_printf), BEFORE
   * activate_uart. If this reaches the host, the kernel shellcode was entered and the kernel
   * console is usable at resume entry -- so a later silence localises to activate_uart or beyond.
   * fun_printf validity was just checked above. */
  ((void (*)(const char *, ...))args_ptr->fun_printf)("SCK>ENTRY-main-reached\n");

  activate_uart(args_ptr);
  mark(args_ptr, "SCK>1-uart\n");

  if ((0x0300 <= args_ptr->fw_version) && (args_ptr->fw_version < 0x0500)) {
    if (hv_defeat_0304(args_ptr))
      return -1;
  } else if ((0x0500 <= args_ptr->fw_version) &&
             (args_ptr->fw_version < 0x0800)) {
    // Already escaped.
  } else if ((0x1300 <= args_ptr->fw_version) &&
             (args_ptr->fw_version < 0x1400)) {
    /* 13.x -- already escaped, exactly like 05.00-07.61 above: the DR0 breakpoint on the
     * kernel's own AP-start call started the AP at the carrier page, and the AP payload
     * cleared NESTED_CTRL.NP_ENABLE (see source/hv_defeat_13xx.c). Nothing to do here, so fall
     * through to the common boot path below.
     *
     * WITHOUT this branch 0x1360 fell into the `else` and RETURNED IMMEDIATELY. Because the
     * ROP JUMPS into this shellcode rather than calling it, that `return` popped the IST7 ROP
     * stack -- which is the "screen went blue, then the console powered off completely" failure
     * on every wake. The loader's own dispatch handled 13.x (source/main.c); this one did not.
     *
     * boot_linux() needs no 13.x constants: it is firmware-agnostic apart from one TMR block
     * that 13.x deliberately skips. get_hv_shm() returns -1 for 13.x because that physical
     * address was never derived -- and it does not need to be, because with NP_ENABLE clear the
     * TMRs stop applying (§2), so n_tmrs = 0 is correct here and not a stopgap. */
  } else {
    return 0;
  }

  mark(args_ptr, "SCK>2-fw-dispatch-passed\n");

  // Now we can R/W on .text
  init_global_pointers(args_ptr);
  printf("SCK>3-globals\n");            /* PRINTFPROBE: live via kernel printf */

  // Disable CFI to allow smp_rendezvous.
  *(uint8_t *)args_ptr->kernel_cfi_check = 0xC3;
  printf("SCK>4-cfi-patched\n");        /* PRINTFPROBE */

  boot_linux();

  /* Report from HERE, not from inside boot_linux(). This is the only region where the shellcode's
   * UART output demonstrably works -- across every run on record, only SCK>5 and SCK>6 have ever
   * reached the host, while SCK>0..4 and all of boot_linux()'s B0..B9 produced nothing, because
   * putc_uart() drops any byte whose TX busy bit does not set in time. So boot_linux() publishes
   * its return codes and its step count, and they are printed here. */
  /* printf, NOT mark(): mark() writes the UART TX register directly and loses most of its bytes to
   * the PS5 OS kernel's console driver writing the same UART during the resume. printf goes through
   * the kernel console and has always survived -- including from this exact spot. */
  printf("SCK>5-boot-linux-RETURNED\n");
  printf("SCK>5a-steps-reached=0x%llx\n", (unsigned long long)g_step);
  printf("SCK>5b-transmitter-rc=0x%llx\n", (unsigned long long)g_rc_transmitter);
  printf("SCK>5f-vswing-rc=0x%llx\n", (unsigned long long)g_rc_voltage);
  printf("SCK>5c-mp3init-rc=0x%llx\n", (unsigned long long)g_rc_mp3_init);
  printf("SCK>5d-hdcp-rc=0x%llx\n", (unsigned long long)g_rc_mp3_hdcp);
  printf("SCK>5e-output-rc=0x%llx\n", (unsigned long long)g_rc_mp3_output);

  /* *** EVERY OFFSET IN THIS REGION IS A 13.60 PRESLIDE. ***
   *
   * ps5_hdmi_ops[], PS5_HDMI_INIT_FN, PS5_HDMI_BRINGUP_FN, PRESLIDE_DP_VSPE and
   * ktext_base() itself all belong to 13.60. ktext_base() is printf minus
   * PRESLIDE_FUN_PRINTF, and that constant is 13.60's 0x25D410; on 7.61 FUN_PRINTF is
   * 0x2A05F8, so ktext_base() comes out 0x431E8 too high and every call here lands on
   * garbage. Running it unconditionally is why our fork could not boot 7.61 at all,
   * via EITHER hv route, while the stock loader booted it with a picture.
   *
   * PS5_NO_HDMI_OPS additionally skips it ON 13.x, which has never been tested: every
   * 13.60 boot on record ran these ops (or the equivalent PS5_HDMI_INIT_CALL /
   * BRINGUP_CALL path), and 7.61 -- which skips them entirely -- SHOWS A PICTURE.
   * They were added to FIX the black screen, so testing their removal is overdue. */
#ifdef PS5_NO_HDMI_OPS
  if (0) {
#else
  if (0x1300 <= args_ptr->fw_version && args_ptr->fw_version < 0x1400) {
#endif
  /* The PS5 OS's own HDMI operations -- the ones the Linux driver does not have at all.
   *
   * Invoked HERE, not inside boot_linux(): a fatal op would kill the boot before boot_linux()
   * returned, so nothing it printed or counted afterwards would ever be seen (that is what the
   * previous two attempts did). This region is the one where printf demonstrably reaches the host,
   * so each op is ANNOUNCED BY NAME FIRST -- if the console dies, the last name printed identifies
   * the op that did it, and one cycle fully localises the fault. */
  printf("SCK>5h-ps5-ops-begin\n");
  for (int i = 0; i < ps5_hdmi_op_count(); i++) {
    printf("SCK>5h-op-%d-starting\n", i + 1);
    call_ps5_hdmi_op(i);
    printf("SCK>5h-op-%d-ok\n", i + 1);
  }
  printf("SCK>5h-ps5-ops-done\n");
  } else {
    printf("SCK>5h-skipped: HDMI ops are 13.60-only offsets, fw=0x%x\n",
           args_ptr->fw_version);
  }
  printf("Linux prepared OK\n");

  printf("Good Bye VM :)\n");
  mark(args_ptr, "SCK>6-rendezvous-starting\n");
  smp_rendezvous(smp_no_rendevous_barrier, vmmcall_dummy,
                 smp_no_rendevous_barrier, NULL);
  mark(args_ptr, "SCK>7-rendezvous-RETURNED\n");

  printf("We shouldn't be here :(\n");
  return 0;
}
