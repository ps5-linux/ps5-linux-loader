#include "utils.h"
#include "shellcode_kernel_args.h"
#include <cpuid.h>

extern shellcode_kernel_args args;

uint64_t PHYS_TO_DMAP(uint64_t pa) { return args.dmap_base + pa; }

void memcpy(void *dest, void *src, uint64_t len) {
  uint8_t *d = (uint8_t *)dest;
  const uint8_t *s = (const uint8_t *)src;
  for (uint64_t i = 0; i < len; i++) {
    d[i] = s[i];
  }
}

uint64_t read_cr3(void) {
  uint64_t cr3;
  __asm__ volatile("mov %%cr3, %0" : "=r"(cr3) : :);
  return cr3;
}

uint64_t vtophys(uint64_t dmap, uint64_t va) {
  uint64_t cr3 = read_cr3();
  return vtophys_custom(dmap, va, cr3);
}

uint64_t vtophys_custom(uint64_t dmap, uint64_t va, uint64_t cr3_custom) {
  uint64_t table_phys = cr3_custom & 0xFFFFFFFF;

  for (int level = 0; level < 4; level++) {
    int shift = 39 - (level * 9);
    uint64_t idx = (va >> shift) & 0x1FF;
    uint64_t entry;
    uint64_t entry_va = dmap + PAGE_PA(table_phys) + idx * 8;

    entry = *(uint64_t *)entry_va;

    if (!PAGE_P(entry))
      return 0;

    if ((level == 1 || level == 2) && PAGE_PS(entry)) {
      uint64_t page_size = P_SIZE(level);
      return PAGE_PA(entry) | (va & (page_size - 1));
    }

    if (level == 3)
      return PAGE_PA(entry) | (va & 0xFFF);

    table_phys = PAGE_PA(entry);
  }
  return 0;
}

uint32_t putc_uart(uint64_t dmap, uint8_t tx_byte) {
  volatile uint32_t *uart_tx = (uint32_t *)(dmap + 0xc1010104ULL);
  volatile uint32_t *uart_busy = (uint32_t *)(dmap + 0xc101010cULL);
  uint64_t timeout = 0xFFFFFFFF;
  do {
    timeout--;
    if (timeout == 0)
      break;
  } while (((*uart_busy) & 0x20) == 0);

  if (timeout == 0)
    return -1;

  *uart_tx = (uint32_t)tx_byte & 0xFF;
  return 0;
}

int puts_uart(uint64_t dmap, const uint8_t *msg) {
#ifdef PS5_NO_MARKS
  /* BISECT (2026-10-14): our fork panics on 4.51 with `Fatal trap 31: security exception` at
   * resume where upstream boots with video. Rung 1c (upstream's shellcode_kernel) booted, so the
   * fault is ours; 1b cleared the UART-gate value and 1d cleared the ATOM vswing command. This is
   * the only group left: every m()/m_hex()/mark() ends here, poking the UART TX register
   * (dmap + 0xC1010104) directly during resume. Upstream never writes that register at all.
   * Compiling this out makes every marker a no-op while the rest of our shellcode stays intact. */
  (void)dmap; (void)msg;
  return 0;
#else
  uint32_t max = 255;
  int ret = 0;

  for (int i = 0; i < 255; i++) {
    if (msg[i] == '\0') {
      break;
    }
    if (msg[i] == '\n') {
      putc_uart(dmap, '\r');
    }
    ret = putc_uart(dmap, msg[i]);
  }

  return ret;
#endif
}

void activate_uart(volatile shellcode_kernel_args *args_ptr) {
  uint32_t *uart_va = (uint32_t *)(args_ptr->dmap_base + 0xC0115110ULL);
  *uart_va &= ~0x200;
  /* A table with no KERNEL_UART_OVERRIDE leaves this as ktext + 0 -- the kernel's ELF
   * HEADER -- because prepare_resume unconditionally adds ktext to the offset. Writing there
   * corrupts .text. Twenty-one derived tables have no value for this field, so check it:
   * the offset is a kernel VA, so anything not in the canonical kernel range is not real.
   * Losing the UART debug channel is free; corrupting .text is not. */
  uint32_t *override_char_va = (uint32_t *)args_ptr->kernel_uart_override;
#ifndef PS5_SKIP_UART_TEXT_WRITE
  if (args_ptr->kernel_uart_override > args_ptr->ktext + 0x1000) {
    *override_char_va = 0x0;
  }
#else
  (void)override_char_va;   /* PRINTFPROBE2: skip the .text write to test if it is the fault */
#endif

  /* THE LINE ABOVE DOES NOT OPEN THE GATE ON THIS CONSOLE, and that is why nothing from this
   * shellcode has ever appeared on the UART.
   *
   * 0xC0115110 is the UART gate and it is WRITE-ONLY: reading it returns 0. uart_on.elf's own
   * report measured exactly that ("BEFORE gate=0x0 ... gate <- 0x200 (write-only)") and opens
   * it by WRITING 0x200 (bit 9 SET). So the upstream `*uart_va &= ~0x200` reads 0, computes
   * 0 & ~0x200 == 0, and writes 0 -- leaving the gate CLOSED. After S3 clears the gate (which
   * it does) that means this shellcode is silent even when it is running perfectly.
   *
   * Write the value uart_on proved working, so the markers below can actually be seen. */
#ifdef PS5_UART_GATE_UPSTREAM
  /* Upstream's exact line, for A/B on firmwares where our SET of bit 9 is suspect.
   * 13.60 retail NEEDS the SET below (uart_on.elf measured the gate as write-only, reading 0),
   * but that was measured on 13.60 and is applied here unconditionally -- which is what this
   * flag exists to test. */
  *uart_va &= ~0x200;
#else
  *(volatile uint32_t *)(args_ptr->dmap_base + 0xC0115110ULL) = (1u << 9);
#endif
}

/* Diagnostic marker straight to the UART TX register (dmap + 0xC1010104) -- the same register
 * the uart_on beacon writes, so if the beacon is visible these are too. Bypasses the kernel
 * console entirely, so it works before init_global_pointers has run. */
void mark(volatile shellcode_kernel_args *args_ptr, const char *s) {
  puts_uart(args_ptr->dmap_base, (const uint8_t *)s);
}

/* mark() with a hex value, for reporting RETURN CODES.
 *
 * Why this has to exist at all: the shellcode's UART output is only reliable LATE. Across every
 * run so far, exactly two markers have ever reached the host -- "SCK>5-boot-linux-RETURNED" and
 * "SCK>6-rendezvous-starting", both emitted immediately after boot_linux() returns -- while
 * SCK>0..4 and every B0..B9 inside boot_linux() produced nothing. putc_uart() drops a byte whose
 * TX busy bit does not set within its timeout, so anything written before the transmitter is
 * ready is silently lost. A value printed from the working region is therefore the only value we
 * can actually read; printing it from where it is produced would be wasted. */
void mark_hex(volatile shellcode_kernel_args *args_ptr, const char *label, uint64_t v) {
  char buf[64];
  int i = 0, j;
  (void)args_ptr;
  while (label[i] && i < 38) { buf[i] = label[i]; i++; }
  buf[i++] = '=';
  buf[i++] = '0';
  buf[i++] = 'x';
  for (j = 15; j >= 0; j--) {
    int nib = (int)((v >> (j * 4)) & 0xF);
    buf[i++] = (char)(nib < 10 ? '0' + nib : 'a' + nib - 10);
  }
  buf[i] = 0;

  /* VIA printf, NOT puts_uart -- this is the fix for the missing diagnostics.
   *
   * puts_uart() writes the UART TX register directly, and during the resume it collides with the
   * PS5 OS kernel's own console driver, which is writing the same UART. That is why nearly every
   * marker has been lost: across runs, SCK>0-4 and all of boot_linux()'s B0-B9 NEVER appeared, and
   * one run delivered 1 of 6 values -- while `printf("Linux prepared OK")`, printed from this very
   * spot in main.c, has appeared in EVERY captured log. printf goes through the kernel's console
   * path with its lock, so it survives.
   *
   * Requires init_global_pointers() to have run (SCK>3), which it has by the time these are
   * printed. The format is kept as a literal %s of a pre-built string so no printf flag support is
   * assumed of the kernel's kvprintf. */
  printf("%s\n", buf);
}

void halt(void) { __asm__ __volatile__("hlt"); }

void init_global_pointers(volatile shellcode_kernel_args *args_ptr) {
  memcpy(&args, (void *)args_ptr, sizeof(args));

  printf = (void (*)(const char *, ...))args.fun_printf;
  smp_rendezvous = (void (*)(void (*)(void *), void (*)(void *),
                             void (*)(void *), void *))args.fun_smp_rendezvous;
  smp_no_rendevous_barrier =
      (void (*)(void *))args.fun_smp_no_rendevous_barrier;

  transmitter_control = (int (*)(int, void *))args.fun_transmitter_control;
  mp3_initialize = (int (*)(int))args.fun_mp3_initialize;
  mp3_invoke = (int (*)(int, void *, void *))args.fun_mp3_invoke;
  g_vbios = args.g_vbios;
}

uint8_t get_cpu(void) {
  uint32_t eax, ebx, ecx, edx;
  __get_cpuid(1, &eax, &ebx, &ecx, &edx);
  uint8_t cpu_id = (ebx >> 24) & 0xFF;
  return cpu_id;
}

void vmmcall_dummy(void *) {
  /* Marker first: this runs on every CPU from smp_rendezvous, and the VMMCALL below is what
   * triggers the patched hypercall handler (HV_HANDLE_VMEXIT_PA). Seeing these = we reached the
   * hand-off; the console dying here means the patch/trampoline at the code cave is wrong. */
  puts_uart(args.dmap_base, (const uint8_t *)"SCK>V\n");
  __asm__ volatile("mov $0x1, %rax \n"
                   "vmmcall \n"
                   "ret \n");
}
