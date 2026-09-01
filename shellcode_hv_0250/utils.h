#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>

int uart_putc(uint8_t value);
int uart_puts(const char *value);
void activate_uart(void);
void uart_trace(uint8_t event, uint8_t cpu, uint32_t value);
void uart_emergency(const char *value);
void uart_exception_trace(uint8_t vector, uint8_t cpu, uint64_t rip,
                          uint64_t error);
void copy_bytes(void *dest, const void *src, uint64_t len);
int bytes_equal(const void *left, const void *right, uint64_t len);
void zero_bytes(void *dest, uint64_t len);
void disable_intr(void);
void halt(void);
uint64_t rdmsr(uint32_t msr);
void wrmsr(uint32_t msr, uint64_t value);
uint32_t atomic_add_32(volatile uint32_t *value, uint32_t add);
uint32_t atomic_or_32(volatile uint32_t *value, uint32_t bits);
uint32_t atomic_load_32(volatile uint32_t *value);
uint8_t get_cpu(void);

#endif
