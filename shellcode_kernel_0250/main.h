#ifndef MAIN_H
#define MAIN_H

#include "shellcode_kernel_args.h"

extern void (*smp_rendezvous)(void (*setup_func)(void *),
                              void (*action_func)(void *),
                              void (*teardown_func)(void *), void *arg);
extern void (*smp_no_rendevous_barrier)(void *);

uint32_t main(uint64_t td, uint64_t uap);

#endif
