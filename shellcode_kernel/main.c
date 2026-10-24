#include "main.h"
#include "boot_linux.h"
#if !defined(FW_13XX_PORT) && !defined(FW_1160)
#include "hv_defeat_0304.h"
#endif
#if defined(FW_1160)
#include "display_ops_1160.h"
#include "shellcode_kernel_args_validate.h"
#endif
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

  // We don't have required information - Abort
  if ((args_ptr->fun_printf & 0xFFFF) == 0) {
    return -1;
  }

#if defined(FW_13XX_PORT)
  if (args_ptr->fw_version < 0x1200 || args_ptr->fw_version >= 0x1400)
    return -1;
  activate_uart(args_ptr);
#elif defined(FW_1160)
  if (validate_shellcode_kernel_args_1160(args_ptr))
    return -1;
  activate_uart(args_ptr);
#else
  activate_uart(args_ptr);
  if ((0x0300 <= args_ptr->fw_version) && (args_ptr->fw_version < 0x0500)) {
    if (hv_defeat_0304(args_ptr))
      return -1;
  } else if ((0x0500 <= args_ptr->fw_version) &&
             (args_ptr->fw_version < 0x0800)) {
    // Already escaped.
  } else if (args_ptr->fw_version == 0x1320 || args_ptr->fw_version == 0x1360) {
    // Already escaped.
  } else {
    return 0;
  }
#endif

  // Now we can R/W on .text
  init_global_pointers(args_ptr);

  // Disable CFI to allow smp_rendezvous.
  *(uint8_t *)args_ptr->kernel_cfi_check = 0xC3;

  boot_linux();
#if defined(FW_1160)
  run_ps5_display_ops_1160();
#endif
  printf("Linux prepared OK\n");

  printf("Good Bye VM :)\n");
  smp_rendezvous(smp_no_rendevous_barrier, vmmcall_dummy,
                 smp_no_rendevous_barrier, NULL);

  printf("We shouldn't be here :(\n");
  return 0;
}
