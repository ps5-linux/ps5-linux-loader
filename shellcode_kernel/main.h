#ifndef MAIN_H
#define MAIN_H
#include "shellcode_kernel_args.h"
#include <stdint.h>

void (*printf)(const char *format, ...);
void (*smp_rendezvous)(void (*setup_func)(void), void (*action_func)(void),
                       void (*teardown_func)(void), void *arg);
void (*smp_no_rendevous_barrier)(void);

uint32_t main(uint64_t add1, uint64_t add2);

#endif
