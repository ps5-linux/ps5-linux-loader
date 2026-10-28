#ifndef LOADER_STAGING_1160_H
#define LOADER_STAGING_1160_H

#include "linux.h"
#include <stddef.h>
#include <stdint.h>

/*
 * Publish the already-populated Linux input mappings in the PID-1 pmap with a
 * checked, journaled transaction.
 *
 * On success this takes ownership of both mappings and keeps their live
 * mappings, the linux_info backing page, and every new page table alive for
 * the rest/wake handoff. On an ordinary failure it restores every journaled
 * page-table write and leaves ownership with the caller. A rollback that fails
 * to verify is contained by holding until a cold reboot.
 */
int stage_linux_aliases_1160(const struct linux_info *info, void *bzimage,
                             size_t bzimage_mapping_size, void *initrd,
                             size_t initrd_mapping_size);
int take_sx_stack_page_10xx(uint64_t copy_lo, uint64_t copy_hi);

/* stage_linux_aliases_1160 returns this instead of -1 when it refused a page
 * table or the code cave inside the copy range. Those stay where they are
 * until a reboot, so running the loader again in the same boot cannot help. */
#define STAGING_REBOOT_FIRST_1160 (-2)

/* The #SX stack page that staging took and checked before writing anything,
 * or 0 if it did not. */
uint64_t sx_stack_page_1160(void);

/* Nonzero when the 16-KiB page at pa overlaps the page under the #SX stack
 * page, which the wake blob's stack reaches past 0x1040 bytes. */
int pa_under_sx_stack_1160(uint64_t pa);

#endif
