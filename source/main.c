#include "hv_defeat_13xx.h"
#include "loader.h"
#include "prepare_resume.h"
#include "utils.h"
#include <unistd.h>

int main(void) {
  if (setup_env()) {
    notify("Something went wrong while initiating.\nPlease make sure your fw "
           "is supported.");
    return -1;
  }

  if (fetch_linux(&linux_i)) {
    notify("Something went wrong while installing linux files.\n");
    return -1;
  }

  void *shellcode_kernel;
  size_t shellcode_kernel_len;
  if (prepare_resume(&shellcode_kernel, &shellcode_kernel_len)) {
    notify("Something went wrong while preparing resume.\n");
    return -1;
  }

  /* The HV patch addresses are NOT optional and are NOT covered by offsets_present().
   * boot_linux.c patches the hypervisor's vmexit handler with
   *     memcpy(PHYS_TO_DMAP(args.hv_handle_vmexit_pa), shellcode_jmp, ...)
   * so a table that leaves HV_HANDLE_VMEXIT_PA at 0 would write that jmp into physical page
   * zero. Refuse here instead -- a table derived from x86_kernel.elf alone CANNOT contain
   * this value, because it lives in the hypervisor image. */
  if (!env_offset.HV_HANDLE_VMEXIT_PA || !env_offset.HV_CODE_CAVE_PA) {
    notify("fw %x: HV patch addresses missing from the offset table "
           "(HV_HANDLE_VMEXIT_PA=%lx HV_CODE_CAVE_PA=%lx).\n"
           "These live in the HYPERVISOR image, not x86_kernel.elf, and cannot be derived "
           "from the kernel. Refusing to arm rather than patching physical page 0.",
           fw, (unsigned long)env_offset.HV_HANDLE_VMEXIT_PA,
           (unsigned long)env_offset.HV_CODE_CAVE_PA);
    goto err;
  }

  /* 13.60 only (base + Pro, differentiated at runtime by SoC id inside hv_defeat_13xx).
   * Hook the kernel's own AP-start call (khook) rather than exploiting an MSR intercept.
   * See source/hv_defeat_13xx.c for the route and source/offsets.c off_1360 for the fields;
   * the function refuses to arm unless all required offsets are present. */
  if ((0x1300 <= fw) && (fw < 0x1400)) {
    if (hv_defeat_13xx(shellcode_kernel, shellcode_kernel_len))
      goto err;
  } else {
    goto err;
  }

  notify("Finished preparation. Going to rest mode in 5 seconds.\nPlease wait "
         "for the orange light to stop "
         "blinking and then wakeup to Linux :)\n");

  sleep(5);
  enter_rest_mode();

  while (1) {
    sleep(30);
  }

  return 0;

err:
  notify("Something went wrong while defeating Hypervisor.\nPlease make sure "
         "your fw is supported.");
  return -1;
}
