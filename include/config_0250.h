#ifndef CONFIG_0250_H
#define CONFIG_0250_H

#define PAGE_SIZE 0x4000ULL

#define cave 0x100000000ULL
#define cave_hv_paging cave
#define cave_hv_identity_pdpt (cave_hv_paging + 0x1000ULL)
#define cave_hv_transition_pdpt (cave_hv_paging + 0x2000ULL)
#define cave_hv_transition_pd (cave_hv_paging + 0x3000ULL)
#define cave_hv_transition_pt (cave_hv_paging + 0x4000ULL)
#define cave_hv_idt (cave_hv_paging + 0x5000ULL)
#define cave_hv_gdt (cave_hv_paging + 0x6000ULL)
#define cave_hv_audit (cave_hv_paging + 0x7000ULL)
#define cave_hv_code (cave_hv_paging + 0x8000ULL)
#define cave_linux_files (cave_hv_paging + 0xC000ULL)
#define cave_linux_info cave_linux_files
#define cave_bzImage (cave_linux_info + PAGE_SIZE)

#define HV_AUDIT_CALLBACK_MASK 0
#define HV_AUDIT_ENTRY_MASK 1
#define HV_AUDIT_RETURN_MASK 2

#define hv_base_rsp (cave + 0x10000000ULL)
#define hv_stack_size 0x1000ULL
#define hv_stack_floor (hv_base_rsp - hv_stack_size)

#define kernel_cave 0xFFFF800000000000ULL
#define kernel_cave_shellcode kernel_cave
#define kernel_stage_budget 0x10000ULL
#define kernel_cave_linux_info (kernel_cave_shellcode + kernel_stage_budget)
#define kernel_cave_bzImage (kernel_cave_linux_info + PAGE_SIZE)
#define kernel_hv_entry_cave_offset 0x44000ULL

#define VRAM_SIZE (512ULL * 1024 * 1024)
#define CMD_LINE                                                               \
  "root=/dev/sda2 rw rootwait console=tty0 console=ttyTitania0 "               \
  "mitigations=off idle=halt pci=pcie_bus_perf "                               \
  "iommu=pt module_blacklist=ccp modprobe.blacklist=ccp"

#endif
