#ifndef PREPARE_RESUME_H
#define PREPARE_RESUME_H
#include "utils.h"

extern struct linux_info linux_i;

int prepare_resume(void **shellcode_kernel, size_t *shellcode_kernel_len);
int kernel_pmap_invalidate_all(void);
uint64_t prepare_sck_args(void);
int update_sck_args_ptr(uint64_t shellcode, uint64_t args);
void hook_call_near(uint64_t hook, uint64_t dst);

#endif
