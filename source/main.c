#include "hv_defeat_0304.h"
#include "hv_defeat_0506.h"
#include "hv_defeat_0607.h"
#include "hv_defeat_1160.h"
#include "config.h"
#include "hv_defeat_13xx.h"
#include "loader.h"
#include "prepare_resume.h"
#include "utils.h"
#include <unistd.h>

// 11.60 keeps page tables from this process linked into PID 1 once the Linux
// files are staged, so it must not exit after that.
static int fail_after_staging(void) {
  if (PS5_FW_IS_11XX(fw)) {
  if (fw == 0x1160) {
    notify("Linux files are still staged. Cold reboot before trying again.\n");
    while (1)
      sleep(30);
  }
  return -1;
}

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
    return fail_after_staging();
  }

  if ((0x0300 <= fw) && (fw < 0x0500)) {
    if (hv_defeat_0304(shellcode_kernel, shellcode_kernel_len))
      goto err;
  } else if ((0x0500 <= fw) && (fw < 0x0650)) {
    if (hv_defeat_0506(shellcode_kernel, shellcode_kernel_len))
      goto err;
  } else if ((0x0650 <= fw) && (fw < 0x0800)) {
    if (hv_defeat_0607(shellcode_kernel, shellcode_kernel_len))
      goto err;
  } else if (fw == 0x1300 || fw == 0x1320 || fw == 0x1340 || fw == 0x1342 || fw == 0x1360) {
    if (hv_defeat_13xx(shellcode_kernel, shellcode_kernel_len))
      goto err;
  } else if (PS5_FW_IS_11XX(fw)) {
  } else if (fw == 0x1160) {
    if (hv_defeat_1160(shellcode_kernel, shellcode_kernel_len))
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
  return fail_after_staging();
}
