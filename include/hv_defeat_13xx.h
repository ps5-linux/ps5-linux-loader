#ifndef HV_DEFEAT_13XX_H
#define HV_DEFEAT_13XX_H

#include <stddef.h>
#include <stdint.h>

uint64_t derive_h(void);
int hv_defeat_13xx(void *shellcode_kernel, size_t shellcode_kernel_len);

#endif
