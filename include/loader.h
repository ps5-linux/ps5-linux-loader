#include "utils.h"
#include <stdint.h>

static uint64_t alloc_page(void);
static void install_page(uintptr_t pml4, vm_offset_t va, vm_paddr_t pa,
                         int bits);
void pte_store(uintptr_t ptep, uint64_t pte);
static int read_file(const char *path, void *buf, size_t bufsize);
static void trim_newline(char *s);
static size_t fetch_file(int port, void *buf, size_t bufsize);
int fetch_linux(struct linux_info *info);
