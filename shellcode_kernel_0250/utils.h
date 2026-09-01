#ifndef UTILS_H
#define UTILS_H

#include "shellcode_kernel_args.h"
#include <stdint.h>

extern shellcode_kernel_args args;

uint64_t phys_to_dmap(uint64_t pa);
void copy_bytes(void *dest, const void *src, uint64_t len);
void zero_bytes(void *dest, uint64_t len);
int bytes_equal(const void *left, const void *right, uint64_t len);
void init_global_pointers(volatile shellcode_kernel_args *args_ptr);
void activate_uart_0250(void);
int uart_putc(uint8_t value);
int uart_puts(const char *value);
void uart_marker(const char *value);

#endif
