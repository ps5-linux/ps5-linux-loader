#ifndef PREPARE_RESUME_H
#define PREPARE_RESUME_H
#include "utils.h"

extern struct linux_info linux_i;

int prepare_resume(void);
int update_sck_data_ptr(void *sc, uint64_t dest_text, uint64_t dest_data);
void hook_call_near(uint64_t hook, uint64_t dst);
void prepare_sck_args(uint64_t dest_data);

#endif
