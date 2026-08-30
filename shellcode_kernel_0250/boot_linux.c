#include "boot_linux.h"
#include "../include/config_0250.h"
#include "../include/linux.h"
#include "../shellcode_hv_0250/shellcode_hv_0250.h"
#include "main.h"
#include "utils.h"
#include <stdint.h>

#define HV_JUMP_TABLE 0x245BEE0ULL
#define HV_JUMP_TABLE_HYPERCALL_4 0x70ULL
#define HV_JUMP_TABLE_ORIGINAL_4 0xFE684824U
#define HV_CODE_BUDGET 0x2000ULL
#define VBIOS_DEST_PA 0xC0000ULL
#define VBIOS_SIZE 0x10000ULL
#define UART_TX_PA 0xC1010104ULL
#define HV_ENTRY_DMAP_TX_A 3
#define HV_ENTRY_DMAP_TX_B 26
#define KERNEL_HANDOFF_CAVE_OFFSET (kernel_hv_entry_cave_offset + 0x100ULL)
#define KERNEL_HANDOFF_BUDGET 0x100ULL
#define HANDOFF_AUDIT_MARKER 0x1122334455667788ULL
#define HANDOFF_ENTRY_MARKER 0x8877665544332211ULL
#define ALIGN_UP(value, alignment)                                             \
  (((value) + (alignment) - 1) & ~((alignment) - 1))

extern const uint8_t handoff_template_start[]
    __attribute__((visibility("hidden")));
extern const uint8_t handoff_template_end[]
    __attribute__((visibility("hidden")));

__asm__(".pushsection .text.handoff_template,\"ax\",@progbits\n"
        ".global handoff_template_start\n"
        ".hidden handoff_template_start\n"
        "handoff_template_start:\n"
        "movabs $0x1122334455667788, %r12\n"
        "movabs $0x8877665544332211, %r13\n"
        "mov $1, %eax\n"
        "cpuid\n"
        "shr $24, %ebx\n"
        "and $0xff, %ebx\n"
        "mov $1, %ebp\n"
        "mov %ebx, %ecx\n"
        "shl %cl, %ebp\n"
        "lock or %ebp, 0(%r12)\n"
        "1:\n"
        "clflush 0(%r13)\n"
        "mfence\n"
        "cmpl $0xfdbe8120, 0(%r13)\n"
        "jne 2f\n"
        "lock or %ebp, 4(%r12)\n"
        "2:\n"
        "mov $4, %eax\n"
        "vmmcall\n"
        "lock or %ebp, 8(%r12)\n"
        "pause\n"
        "jmp 1b\n"
        ".global handoff_template_end\n"
        ".hidden handoff_template_end\n"
        "handoff_template_end:\n"
        ".popsection\n");

static struct linux_info info;

_Static_assert(cave_hv_paging == 0x100000000ULL,
               "L0 identity CR3 changed");
_Static_assert(cave_hv_code == 0x100008000ULL,
               "L0 shellcode address changed");
_Static_assert(cave_hv_audit + 0x1000ULL == cave_hv_code,
               "handoff audit page layout changed");
_Static_assert((uint32_t)(kernel_hv_entry_cave_offset - HV_JUMP_TABLE) ==
                   0xFDBE8120U,
               "global handoff dispatch target changed");
_Static_assert(cave_hv_code + HV_CODE_BUDGET <= cave_linux_info,
               "L0 shellcode overlaps Linux metadata");

static const uint8_t hv_entry_stub_template[] = {
    0xFA,                                     /* cli */
    0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,   /* movabs dmap UART TX, %rax */
    0xC7, 0x00, 'A', 0, 0, 0,                /* dispatch reached */
    0x0F, 0x01, 0x15, 0x39, 0, 0, 0,       /* lgdt 0x39(%rip) */
    0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,   /* movabs dmap UART TX, %rax */
    0xC7, 0x00, 'B', 0, 0, 0,                /* GDT loaded */
    0x48, 0xB8,                               /* movabs $0x100000000, %rax */
    0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x0F, 0x22, 0xD8,                         /* mov %rax, %cr3 */
    0x48, 0xB8, 0x04, 0x01, 0x01, 0xC1,     /* movabs physical UART TX, %rax */
    0x00, 0x00, 0x00, 0x00,
    0xC7, 0x00, 'C', 0, 0, 0,                /* identity CR3 active */
    0x48, 0xB8, 0x00, 0x80, 0x00, 0x00,     /* movabs L0 RIP, %rax */
    0x01, 0x00, 0x00, 0x00,
    0xFF, 0xE0,                               /* jmp *%rax */
    0x27, 0x00,                               /* GDT limit */
    0x00, 0x60, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, /* GDT base */
};
_Static_assert(sizeof(hv_entry_stub_template) == 91,
               "traced L0 entry stub changed");

static const uint64_t l0_gdt[] = {
    0,
    0,
    0x00AF9A000000FFFFULL,
    0x00CF92000000FFFFULL,
    0x00AF9A000000FFFFULL,
};

static int add_overflows(uint64_t start, uint64_t size, uint64_t limit) {
  return size > limit || start > limit - size;
}

static int replace_unique_qword(uint8_t *data, uint64_t len, uint64_t marker,
                                uint64_t replacement) {
  uint32_t matches = 0;
  for (uint64_t i = 0; i + sizeof(marker) <= len; i++) {
    uint64_t value;
    copy_bytes(&value, data + i, sizeof(value));
    if (value == marker) {
      copy_bytes(data + i, &replacement, sizeof(replacement));
      matches++;
    }
  }
  return matches == 1 ? 0 : -1;
}

static int install_hv_code(void) {
  if (shellcode_hv_0250_bin_len == 0 ||
      shellcode_hv_0250_bin_len > HV_CODE_BUDGET)
    return -0x2510;

  uint64_t *pml4 = (uint64_t *)phys_to_dmap(cave_hv_paging);
  uint64_t *identity_pdpt =
      (uint64_t *)phys_to_dmap(cave_hv_identity_pdpt);
  uint64_t *transition_pdpt =
      (uint64_t *)phys_to_dmap(cave_hv_transition_pdpt);
  uint64_t *transition_pd =
      (uint64_t *)phys_to_dmap(cave_hv_transition_pd);
  uint64_t *transition_pt =
      (uint64_t *)phys_to_dmap(cave_hv_transition_pt);
  uint64_t transition_va = args.ktext + kernel_hv_entry_cave_offset;
  uint64_t pml4_index = (transition_va >> 39) & 0x1FF;
  uint64_t pdpt_index = (transition_va >> 30) & 0x1FF;
  uint64_t pd_index = (transition_va >> 21) & 0x1FF;
  uint64_t pt_index = (transition_va >> 12) & 0x1FF;
  const uint64_t entries[] = {
      0x0000000000000083ULL,
      0x0000000040000083ULL,
      0x0000000080000083ULL,
      0x00000000C0000083ULL,
      0x0000000100000083ULL,
  };

  if (pml4_index == 0 || !args.hv_entry_cave_pa ||
      (args.hv_entry_cave_pa & 0xFFF))
    return -0x2511;

  zero_bytes(pml4, 0x5000);
  pml4[0] = cave_hv_identity_pdpt + 3;
  for (uint32_t i = 0; i < sizeof(entries) / sizeof(entries[0]); i++)
    identity_pdpt[i] = entries[i];
  pml4[pml4_index] = cave_hv_transition_pdpt + 3;
  transition_pdpt[pdpt_index] = cave_hv_transition_pd + 3;
  transition_pd[pd_index] = cave_hv_transition_pt + 3;
  transition_pt[pt_index] = args.hv_entry_cave_pa + 3;
  if (pml4[0] != cave_hv_identity_pdpt + 3 ||
      !bytes_equal(identity_pdpt, entries, sizeof(entries)) ||
      pml4[pml4_index] != cave_hv_transition_pdpt + 3 ||
      transition_pdpt[pdpt_index] != cave_hv_transition_pd + 3 ||
      transition_pd[pd_index] != cave_hv_transition_pt + 3 ||
      transition_pt[pt_index] != args.hv_entry_cave_pa + 3)
    return -0x2512;

  void *gdt = (void *)phys_to_dmap(cave_hv_gdt);
  zero_bytes(gdt, 0x1000);
  copy_bytes(gdt, l0_gdt, sizeof(l0_gdt));
  if (!bytes_equal(gdt, l0_gdt, sizeof(l0_gdt)))
    return -0x2513;

  void *audit = (void *)phys_to_dmap(cave_hv_audit);
  zero_bytes(audit, 0x1000);
  for (uint32_t i = 0; i < 3; i++) {
    if (((volatile uint32_t *)audit)[i] != 0)
      return -0x2515;
  }

  void *destination = (void *)phys_to_dmap(cave_hv_code);
  zero_bytes(destination, HV_CODE_BUDGET);
  copy_bytes(destination, shellcode_hv_0250_bin,
             shellcode_hv_0250_bin_len);
  if (!bytes_equal(destination, shellcode_hv_0250_bin,
                   shellcode_hv_0250_bin_len))
    return -0x2514;
  return 0;
}

int prepare_linux_0250(void) {
  int result = install_hv_code();
  if (result)
    return result;

  const uint8_t *vbios = (const uint8_t *)args.g_vbios;
  if (vbios[0] != 0x55 || vbios[1] != 0xAA)
    return -0x2520;
  void *vbios_dest = (void *)phys_to_dmap(VBIOS_DEST_PA);
  copy_bytes(vbios_dest, vbios, VBIOS_SIZE);
  if (!bytes_equal(vbios_dest, vbios, VBIOS_SIZE))
    return -0x2521;

  copy_bytes(&info, (const void *)args.linux_info_va, sizeof(info));
  if (!info.bzimage || !info.initrd || info.bzimage_size < 0x400 ||
      !info.initrd_size)
    return -0x2522;

  uint64_t source_bzimage = info.bzimage;
  uint64_t source_initrd = info.initrd;
  info.bzimage = cave_bzImage;
  info.initrd = cave_bzImage + ALIGN_UP(info.bzimage_size, PAGE_SIZE);
  info.n_tmrs = 0;

  if (info.initrd < info.bzimage ||
      add_overflows(info.bzimage, info.bzimage_size, hv_stack_floor) ||
      add_overflows(info.initrd, info.initrd_size, hv_stack_floor))
    return -0x2523;

  void *info_dest = (void *)phys_to_dmap(cave_linux_info);
  void *bzimage_dest = (void *)phys_to_dmap(info.bzimage);
  void *initrd_dest = (void *)phys_to_dmap(info.initrd);
  copy_bytes(bzimage_dest, (const void *)source_bzimage, info.bzimage_size);
  copy_bytes(initrd_dest, (const void *)source_initrd, info.initrd_size);
  copy_bytes(info_dest, &info, sizeof(info));

  if (!bytes_equal(bzimage_dest, (const void *)source_bzimage,
                   info.bzimage_size) ||
      !bytes_equal(initrd_dest, (const void *)source_initrd,
                   info.initrd_size) ||
      !bytes_equal(info_dest, &info, sizeof(info)))
    return -0x2524;
  return 0;
}

int install_hv_entry_0250(void) {
  volatile uint32_t *entry =
      (volatile uint32_t *)(args.ktext + HV_JUMP_TABLE +
                            HV_JUMP_TABLE_HYPERCALL_4);
  volatile uint8_t *cave_ptr =
      (volatile uint8_t *)(args.ktext + kernel_hv_entry_cave_offset);
  volatile uint8_t *handoff_ptr =
      (volatile uint8_t *)(args.ktext + KERNEL_HANDOFF_CAVE_OFFSET);
  uint64_t handoff_len =
      (uint64_t)(handoff_template_end - handoff_template_start);

  if (*entry != HV_JUMP_TABLE_ORIGINAL_4 || handoff_len == 0 ||
      handoff_len > KERNEL_HANDOFF_BUDGET)
    return -0x2530;
  for (uint32_t i = 0; i < sizeof(hv_entry_stub_template); i++) {
    if (cave_ptr[i] != 0xCC)
      return -0x2531;
  }
  for (uint32_t i = 0; i < handoff_len; i++) {
    if (handoff_ptr[i] != 0xCC)
      return -0x2533;
  }

  uint8_t hv_entry_stub[sizeof(hv_entry_stub_template)];
  copy_bytes(hv_entry_stub, hv_entry_stub_template,
             sizeof(hv_entry_stub_template));
  uint64_t dmap_uart_tx = args.dmap_base + UART_TX_PA;
  copy_bytes(hv_entry_stub + HV_ENTRY_DMAP_TX_A, &dmap_uart_tx,
             sizeof(dmap_uart_tx));
  copy_bytes(hv_entry_stub + HV_ENTRY_DMAP_TX_B, &dmap_uart_tx,
             sizeof(dmap_uart_tx));

  uint8_t handoff[KERNEL_HANDOFF_BUDGET];
  zero_bytes(handoff, sizeof(handoff));
  copy_bytes(handoff, handoff_template_start, handoff_len);
  uint64_t audit_dmap = args.dmap_base + cave_hv_audit;
  uint64_t entry_va = args.ktext + HV_JUMP_TABLE +
                      HV_JUMP_TABLE_HYPERCALL_4;
  if (replace_unique_qword(handoff, handoff_len, HANDOFF_AUDIT_MARKER,
                           audit_dmap) ||
      replace_unique_qword(handoff, handoff_len, HANDOFF_ENTRY_MARKER,
                           entry_va))
    return -0x2534;

  copy_bytes((void *)cave_ptr, hv_entry_stub, sizeof(hv_entry_stub));
  copy_bytes((void *)handoff_ptr, handoff, handoff_len);
  __asm__ volatile("mfence" : : : "memory");
  if (!bytes_equal((const void *)cave_ptr, hv_entry_stub,
                   sizeof(hv_entry_stub)) ||
      !bytes_equal((const void *)handoff_ptr, handoff, handoff_len))
    return -0x2532;
  return 0;
}

int final_handoff_0250(void) {
  volatile uint32_t *entry =
      (volatile uint32_t *)(args.ktext + HV_JUMP_TABLE +
                            HV_JUMP_TABLE_HYPERCALL_4);
  int64_t target = (int64_t)kernel_hv_entry_cave_offset -
                   (int64_t)HV_JUMP_TABLE;
  if (target != (int64_t)(int32_t)target ||
      *entry != HV_JUMP_TABLE_ORIGINAL_4)
    return -0x2540;

  uart_marker("[K25:04]\n");
  *entry = (uint32_t)(int32_t)target;
  __asm__ volatile("mfence" : : : "memory");
  if (*entry != (uint32_t)(int32_t)target) {
    *entry = HV_JUMP_TABLE_ORIGINAL_4;
    return -0x2541;
  }

  smp_rendezvous(smp_no_rendevous_barrier,
                 (void (*)(void *))(args.ktext + KERNEL_HANDOFF_CAVE_OFFSET),
                 smp_no_rendevous_barrier, 0);
  *entry = HV_JUMP_TABLE_ORIGINAL_4;
  __asm__ volatile("mfence" : : : "memory");
  if (*entry != HV_JUMP_TABLE_ORIGINAL_4)
    return -0x2543;
  return -0x2542;
}
