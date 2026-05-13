#ifndef UTILS_H
#define UTILS_H
#include "boot_linux.h"
#include "shellcode_kernel_args.h"
#include <stdint.h>

extern void (*printf)(const char *format, ...);
extern void (*smp_rendezvous)(void (*setup_func)(void),
                              void (*action_func)(void),
                              void (*teardown_func)(void), void *arg);
extern void (*smp_no_rendevous_barrier)(void);
extern int (*transmitter_control)(int cmd, void *control);
extern int (*mp3_initialize)(int vmid);
extern int (*mp3_invoke)(int cmd_id, void *req, void *rsp);
extern uint64_t g_vbios;

// Defines for Page management
enum page_bits {
  P = 0,
  RW,
  US,
  PWT,
  PCD,
  A,
  D,
  PS,
  G,
  XO = 58,
  PK = 59,
  NX = 63
};

#define PG_B_P (1ULL << P)
#define PG_B_RW (1ULL << RW)
#define PAGE_P(x) (x & (1ULL << P))
#define PAGE_RW(x) (x & (1ULL << RW))
#define PAGE_PS(x) (x & (1ULL << PS))
#define PAGE_XO(x) (x & (1ULL << XO))
#define PAGE_CLEAR_XO(x) (x &= ~(1ULL << XO))
#define PAGE_CLEAR_G(x) (x &= ~(1ULL << G))
#define PAGE_SET_RW(x) (x |= (1ULL << RW))
#define PAGE_PA(x) (x & 0x000FFFFFFFFFF000ULL)
#define P_SIZE(l) ((l == 1) ? (1ULL << 30) : (1ULL << 21))

uint64_t read_cr3(void);
uint64_t vtophys(uint64_t dmap, uint64_t va);
uint64_t vtophys_custom(uint64_t dmap, uint64_t va, uint64_t cr3_custom);
uint64_t PHYS_TO_DMAP(uint64_t pa);
void memcpy(void *dest, void *src, uint64_t len);
uint32_t putc_uart(uint64_t dmap, uint8_t tx_byte);
int puts_uart(uint64_t dmap, const uint8_t *msg);
void activate_uart(volatile shellcode_kernel_args *args_ptr);
void halt(void);
void init_global_pointers(volatile shellcode_kernel_args *args_ptr);
void vmmcall_dummy(void);
#endif
