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

  // We don't have required information - Abort
  if ((args_ptr->fun_printf & 0xFFFF) == 0) {
    return -1;
  }

  activate_uart(args_ptr);

  if ((0x0300 <= args_ptr->fw_version) && (args_ptr->fw_version < 0x0500)) {
    if (hv_defeat_0304(args_ptr))
      return -1;
  } else if ((0x0500 <= args_ptr->fw_version) &&
             (args_ptr->fw_version < 0x0800)) {
    // Already escaped.
  } else {
    return 0;
  }

  // Now we can R/W on .text
  init_global_pointers(args_ptr);

  // Disable CFI to allow smp_rendezvous.
  *(uint8_t *)args_ptr->kernel_cfi_check = 0xC3;

  boot_linux();
  printf("Linux prepared OK\n");

  printf("Good Bye VM :)\n");
  smp_rendezvous(smp_no_rendevous_barrier, vmmcall_dummy,
                 smp_no_rendevous_barrier, NULL);

  printf("We shouldn't be here :(\n");
  return 0;
}
