#ifndef HV_DEFEAT_13XX_H
#define HV_DEFEAT_13XX_H

#include <stddef.h>

/* Firmware 13.x hypervisor defeat.

 * Route (differs from 0304/0506/0607): hook the kernel's OWN AP-start call
 * (env_offset.KERNEL_SYM_HV_MP_STARTUP_CALL) with a DR0 execute breakpoint via khook,
 * rewrite its RSI/RDX so the AP starts at our carrier page instead of the kernel's
 * trampoline, and let the AP payload clear NESTED_CTRL.NP_ENABLE on all 16 VMCBs.
 *
 * Why this and not the older trick: hv_defeat_0607 relied on an MSR 0x1B APIC-base
 * intercept bug that was removed between 11.00 and 12.00. This route instead rides the
 * kernel's legitimate wake call, which fires inside acpi_wakeup's loop BEFORE
 * DISABLE_STARTUP_MP -- so it never races that ordering, and the core argument is already
 * legal and the one-shot bit still clear. See
 * HVXring0/findings/HANDOFF-khookprobe-hardware.md and
 * HVXring0/findings/VERIFY-reborn-offsets-13.60.md.
 *
 * Requires the AP payload (shellcode_ap) to have been built and included. */
int hv_defeat_13xx(void *shellcode_kernel, size_t shellcode_kernel_len);

#endif /* HV_DEFEAT_13XX_H */
