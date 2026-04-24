#ifndef UTILS_H
#define UTILS_H

#include "offsets.h"
#include <ps5/kernel.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>

int sceKernelGetCurrentCpu();
int sceKernelSendNotificationRequest(int, void *, size_t, int);

typedef struct _sysent {
  uint32_t n_arg;
  uint32_t pad;
  uint64_t sy_call;
  uint64_t sy_auevent;
  uint64_t sy_systrace_args;
  uint32_t sy_entry;
  uint32_t sy_return;
  uint32_t sy_flags;
  uint32_t sy_thrcnt;
} sysent;

typedef struct __flat_pmap {
  uint64_t mtx_name_ptr;
  uint64_t mtx_flags;
  uint64_t mtx_data;
  uint64_t mtx_lock;
  uint64_t pm_pml4;
  uint64_t pm_cr3;
} flat_pmap;

struct linux_info {
  uintptr_t bzimage;
  size_t bzimage_size;
  uintptr_t initrd;
  size_t initrd_size;
  size_t vram_size;
  char cmdline[2048];
  uintptr_t linux_info; // PA of linux_info
};

/** These vars are global for the payload to simplify things */
extern offset_list env_offset;    // Defined on utils.c
extern uint64_t ktext;            // Defined on utils.c
extern uint64_t kdata;            // Defined on utils.c
extern uint64_t dmap;             // Defined on utils.c
extern uint64_t cr3;              // Defined on utils.c
extern uint32_t fw;               // Defined on utils.c
extern uint64_t vmcb_pa[16];      // Defined on hv_defeat.c
extern struct linux_info linux_i; // Declared on main.c

static inline void kwrite(uint64_t ka, void *src, uint64_t len) {
  kernel_copyin(src, ka, len);
}

static inline void kwrite64(uint64_t dst, uint64_t val) {
  kernel_copyin(&val, dst, 8);
}

static inline void kwrite32(uint64_t dst, uint32_t val) {
  kernel_copyin(&val, dst, 4);
}

static inline void kwrite8(uint64_t dst, uint8_t val) {
  kernel_copyin(&val, dst, 1);
}

static inline void kread(uint64_t ka, void *dst, uint64_t len) {
  kernel_copyout(ka, dst, len);
}

static inline uint64_t kread64(uint64_t src) {
  uint64_t val;
  kernel_copyout(src, &val, 8);
  return val;
}

static inline uint32_t kread32(uint64_t src) {
  uint32_t val;
  kernel_copyout(src, &val, 4);
  return val;
}

static inline uint8_t kread8(uint64_t src) {
  uint8_t val;
  kernel_copyout(src, &val, 1);
  return val;
}

int set_offsets(void);
int init_global_vars(void);
uint64_t get_offset_va(uint64_t offset);

// Defines for Page management
#define ALIGN_UP(size, align) (((size) + (align) - 1) & ~((align) - 1))
#define INKERNEL(va) (va & 0xFFFF000000000000)

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

#define pmap_pml4e_index(va) ((va >> 39) & 0x1FF)
#define pmap_pdpe_index(va) ((va >> 30) & 0x1FF)
#define pmap_pde_index(va) ((va >> 21) & 0x1FF)
#define pmap_pte_index(va) ((va >> 12) & 0x1FF)

uint64_t va_to_pa_user(uint64_t va);
uint64_t va_to_pa_kernel(uint64_t va);
uint64_t va_to_pa_custom(uint64_t va, uint64_t cr3_custom);
uint64_t pa_to_dmap(uint64_t pa);
void page_chain_set_rw(uint64_t va);
uint64_t page_remove_global(uint64_t va);

uint64_t getpmap(uint64_t proc_ptr);
uint64_t get_pml4(uint64_t pmap);

int pin_to_core(int n);
int pin_to_first_available_core(void);
void unpin(void);
static inline void notify(uint8_t *msg) {
  struct {
    char pad[45];
    char msg[3075];
  } req;
  uint64_t len =
      strlen(msg) < (sizeof(req.msg) - 1) ? strlen(msg) : (sizeof(req.msg) - 1);
  memcpy(req.msg, msg, len);
  sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
}

#if DEBUG
#define DEBUG_PRINT(fmt, ...) printf(fmt, ##__VA_ARGS__)
#else
#define DEBUG_PRINT(fmt, ...)
#endif

#endif
