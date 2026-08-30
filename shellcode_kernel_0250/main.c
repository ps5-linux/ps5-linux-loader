#include "main.h"
#include "boot_linux.h"
#include "../include/config_0250.h"
#include "utils.h"

shellcode_kernel_args args = {0};
void (*smp_rendezvous)(void (*setup_func)(void *), void (*action_func)(void *),
                       void (*teardown_func)(void *), void *arg);
void (*smp_no_rendevous_barrier)(void *);

static int canonical_kernel_pointer(uint64_t value) {
  return (value >> 48) == 0xFFFF;
}

__attribute__((section(".entry_point"))) uint32_t main(uint64_t td,
                                                       uint64_t uap) {
  (void)td;
  (void)uap;
  volatile shellcode_kernel_args *args_ptr =
      (volatile shellcode_kernel_args *)0x11AA11AA11AA11AAULL;
  __asm__ volatile("" : "+r"(args_ptr));

  if (args_ptr->fw_version != 0x0250 ||
      !canonical_kernel_pointer(args_ptr->ktext) ||
      !canonical_kernel_pointer(args_ptr->dmap_base) ||
      !canonical_kernel_pointer(args_ptr->fun_smp_rendezvous) ||
      !canonical_kernel_pointer(args_ptr->fun_smp_no_rendevous_barrier) ||
      !canonical_kernel_pointer(args_ptr->g_vbios) ||
      args_ptr->linux_info_va != kernel_cave_linux_info ||
      !args_ptr->hv_entry_cave_pa ||
      (args_ptr->hv_entry_cave_pa & 0xFFF) ||
      args_ptr->hv_entry_cave_pa >= 0x1000000000ULL ||
      ((args_ptr->ktext | args_ptr->dmap_base) & 0x3FFF))
    return 0x2501;

  init_global_pointers(args_ptr);
  activate_uart_0250();
  uart_marker("[K25:01]\n");

  int result = prepare_linux_0250();
  if (result) {
    uart_marker("[K25:E1]\n");
    return (uint32_t)result;
  }
  uart_marker("[K25:02]\n");

  result = install_hv_entry_0250();
  if (result) {
    uart_marker("[K25:E2]\n");
    return (uint32_t)result;
  }
  uart_marker("[K25:03]\n");

  result = final_handoff_0250();
  uart_marker("[K25:E3]\n");
  return (uint32_t)result;
}
