#ifndef STAGING_0250_H
#define STAGING_0250_H

#include <stdint.h>

int staging_0250_begin(void);
int staging_0250_rollback(void);
int staging_0250_map(uint64_t va, uint64_t pa);
int staging_0250_flush(void);
uint64_t staging_0250_alloc_page(void);
uint64_t staging_0250_user_pa(uint64_t va);
uint64_t staging_0250_kernel_pa(uint64_t va);

#endif
