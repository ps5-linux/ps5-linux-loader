#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>

/* HV/resume-context UART enable: NEGATES bit (1<<9) at PHYSICAL 0xC0115110.
 * Opposite polarity and addressing to the GameOS path, which SETs it via dmap.
 * Write-only register -- do not read back. Re-apply on every resume (sleep/wake). */
void activate_uart_hv(void);

uint32_t putc_uart(uint8_t tx_byte);
int printf(const uint8_t *msg);

void memcpy(void *dest, void *src, uint64_t len);
char *strcpy(char *dest, const char *src);
void *memset(void *s, int c, uint64_t n);

void disable_intr(void);
void halt(void);
uint64_t rdmsr(uint32_t msr);
void wrmsr(uint32_t msr, uint64_t val);
void atomic_add_32(volatile uint32_t *p, uint32_t v);
int atomic_cmpset_32(volatile uint32_t *dst, uint32_t exp, uint32_t src);
uint8_t get_cpu(void);

#endif
