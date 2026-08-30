#include "config_0250.h"
#include "hv_defeat_0250.h"
#include "hv_defeat_0304.h"
#include "hv_defeat_0506.h"
#include "hv_defeat_0607.h"
#include "loader.h"
#include "loader_0250.h"
#include "prepare_0250.h"
#include "prepare_resume.h"
#include "staging_0250.h"
#include "utils.h"
#include <errno.h>
#include <string.h>
#include <unistd.h>

static __attribute__((noreturn)) void stop_0250(void) {
  for (;;)
    __asm__ volatile("pause");
}

static int rollback_0250(void) {
  if (staging_0250_rollback()) {
    notify("Firmware 2.50 staging rollback failed; cold reboot required.\n");
    stop_0250();
  }
  return -1;
}

static int boot_0250(void) {
  if (staging_0250_begin() || fetch_linux_0250(&linux_i) ||
      prepare_kernel_stage_0250()) {
    notify("Firmware 2.50 Linux staging failed.\n");
    return rollback_0250();
  }

  struct linux_info mapped = {0};
  uint8_t vbios[2] = {0};
  if (kernel_copyout(linux_i.linux_info, &mapped, sizeof(mapped)) ||
      memcmp(&mapped, &linux_i, sizeof(mapped)) ||
      kernel_copyout(ktext + env_offset.G_VBIOS, vbios, sizeof(vbios)) ||
      vbios[0] != 0x55 || vbios[1] != 0xAA) {
    notify("Firmware 2.50 final validation failed.\n");
    return rollback_0250();
  }

  notify("Preparing firmware 2.50 hypervisor handoff.\n");
  if (hv_defeat_0250()) {
    notify("Firmware 2.50 hypervisor preparation failed.\n");
    return rollback_0250();
  }

  long result = syscall(0x11, kernel_cave_shellcode, (uint64_t)fw << 16);
  notify("Firmware 2.50 kernel handoff returned: result=%ld errno=%d\n", result,
         errno);
  stop_0250();
}

int main(void) {
  if (setup_env()) {
    notify("Something went wrong while initiating.\nPlease make sure your fw "
           "is supported.");
    return -1;
  }

  if (fw == 0x0250)
    return boot_0250();

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

  if ((0x0300 <= fw) && (fw < 0x0500)) {
    if (hv_defeat_0304(shellcode_kernel, shellcode_kernel_len))
      goto err;
  } else if ((0x0500 <= fw) && (fw < 0x0650)) {
    if (hv_defeat_0506(shellcode_kernel, shellcode_kernel_len))
      goto err;
  } else if ((0x0650 <= fw) && (fw < 0x0800)) {
    if (hv_defeat_0607(shellcode_kernel, shellcode_kernel_len))
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
