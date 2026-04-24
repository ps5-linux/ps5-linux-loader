#ifndef MAIN_H
#define MAIN_H
#include "shellcode_kernel_args.h"
#include <stdarg.h>
#include <stdint.h>
#include <sys/_cpuset.h>
#include <sys/_types.h>

void (*printf)(const char *format, ...);
uint32_t (*AcpiSetFirmwareWakingVector)(uint64_t PhysicalAddress,
                                        uint64_t PhysicalAddress64);
uint64_t (*kernel_va_to_pa)(uint64_t va);
uint32_t (*hv_iommu_set_buffers)(uint64_t cb2_pa, uint64_t cb3_pa,
                                 uint64_t eb_pa, uint64_t unk, int *n_devices);
uint32_t (*hv_iommu_wait_completion)(void);
void (*smp_rendezvous)(void (*setup_func)(void *), void (*action_func)(void *),
                       void (*teardown_func)(void *), void *arg);
void (*smp_rendezvous_cpus)(cpuset_t map, void (*setup_func)(void *),
                            void (*action_func)(void *),
                            void (*teardown_func)(void *), void *arg);
void (*smp_no_rendevous_barrier)(void);

// We are being called instead of AcpiSetFirmwareWakingVector from
// acpi_wakeup_machdep
uint32_t main(uint64_t add1, uint64_t add2);

uint64_t rdmsr(uint32_t msr);

// tmr via ecam b0d18f2
#ifndef ECAM_B0D18F2
#define ECAM_B0D18F2 (0xF0000000ULL + 0x18ULL * 0x8000 + 2 * 0x1000)
#define TMR_INDEX_OFF 0x80
#define TMR_DATA_OFF 0x84
#endif

// tmr layout (hardware)
#define TMR_BASE(n) ((n) * 0x10 + 0x00)
#define TMR_LIMIT(n) ((n) * 0x10 + 0x04)
#define TMR_CONFIG(n) ((n) * 0x10 + 0x08)
#define TMR_REQUESTORS(n) ((n) * 0x10 + 0x0C)
#define TMR_CFG_PERMISSIVE 0x3F07
#define MAX_TMR 22
#define MAX_SAVED_TMRS 8

uint32_t tmr_read(uint64_t dmap, uint32_t addr);
void tmr_write(uint64_t dmap, uint32_t addr, uint32_t val);

int tmr_relax(void);

// Command buffer MMIO offsets
#define IOMMU_MMIO_CB_HEAD 0xa000
#define IOMMU_MMIO_CB_TAIL 0xa008

// Queue constants
#define IOMMU_CB_SIZE 0x2000
#define IOMMU_CB_MASK (IOMMU_CB_SIZE - 1)
#define IOMMU_CMD_ENTRY_SIZE 0x10

// Submit a single 16-byte command and wait for completion
void iommu_submit_cmd(shellcode_kernel_args *args_ptr, uint64_t *cmd);
// Write 8 bytes to a physical address using IOMMU completion wait store
void iommu_write8_pa(shellcode_kernel_args *args_ptr, uint64_t pa,
                     uint64_t val);

void patch_vmcb(shellcode_kernel_args *args_ptr);

#define NULL (void *)0
void vmmcall_dummy(void);
void halt(void);

#endif