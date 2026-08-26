/* SPDX-License-Identifier: GPL-2.0 */
#ifndef ARCH_X86_KVM_NYX_STRICT_PT_TRACKING_INTERNAL_H
#define ARCH_X86_KVM_NYX_STRICT_PT_TRACKING_INTERNAL_H

#include "nyx_strict_pt_tracking.h"

#ifdef __KERNEL__
#include <linux/string.h>
#else
#include <string.h>
#endif

void *nyx_strict_pt_alloc_array(__u32 count, __u64 size);
void nyx_strict_pt_free(void *ptr);
void nyx_strict_pt_sort_u64(__u64 *items, __u32 count);
__u32 nyx_strict_pt_dedupe_u64(__u64 *items, __u32 count);
bool nyx_strict_pt_is_canonical(__u64 addr, __u8 va_bits);
__u32 nyx_strict_pt_find_free_slot(const struct nyx_strict_pt_tracker *tracker);
__s32 nyx_strict_pt_find_range_slot(const struct nyx_strict_pt_tracker *tracker,
	__u64 range_id);
__u64 nyx_strict_pt_active_mask(const struct nyx_strict_pt_tracker *tracker);
__u64 nyx_strict_pt_find_owner_mask(const struct nyx_strict_pt_tracker *tracker,
	__u64 gfn);
int nyx_strict_pt_alloc_sorted_unique(const __u64 *gfns, __u32 count,
	__u64 **uniq_out, __u32 *uniq_count_out);
int nyx_strict_pt_merge_owners(const struct nyx_strict_pt_owner *old,
	__u32 old_count, __u64 bit, const __u64 *new_gfns, __u32 new_count,
	struct nyx_strict_pt_owner **owners_out, __u32 *owner_count_out,
	__u64 **track_out, __u32 *track_count_out, __u64 **untrack_out,
	__u32 *untrack_count_out);

#endif
