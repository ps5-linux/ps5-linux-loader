#ifndef LOADER_H
#define LOADER_H

#include "utils.h"
#include <stdint.h>

uint64_t alloc_page(void);
void install_page(uintptr_t pml4, vm_offset_t va, vm_paddr_t pa,
                         int bits);
void pte_store(uintptr_t ptep, uint64_t pte);
int read_file(const char *path, void *buf, size_t bufsize);
void trim_newline(char *s);
int fetch_linux(struct linux_info *info);

#endif