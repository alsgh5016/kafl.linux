// SPDX-License-Identifier: GPL-2.0

#include "nyx_strict_pt_tracking.h"

#ifdef __KERNEL__
#include <linux/errno.h>
#else
#include <errno.h>
#endif

int nyx_strict_pt_data_tracker_needs_nx(
	const struct nyx_strict_pt_data_tracker *tracker, __u64 gfn,
	bool *needs_nx)
{
	__u32 lo = 0;
	__u32 hi;

	if (!tracker || !needs_nx)
		return -EINVAL;

	hi = tracker->owner_count;
	while (lo < hi) {
		__u32 mid = lo + ((hi - lo) >> 1);

		if (tracker->owners[mid].gfn < gfn)
			lo = mid + 1;
		else
			hi = mid;
	}

	if (lo < tracker->owner_count && tracker->owners[lo].gfn == gfn) {
		*needs_nx = !tracker->owners[lo].exec_ack;
		return 0;
	}

	return -ENOENT;
}

int nyx_strict_pt_data_tracker_ack_exec(
	struct nyx_strict_pt_data_tracker *tracker, __u64 gfn)
{
	__u32 lo = 0;
	__u32 hi;

	if (!tracker)
		return -EINVAL;

	hi = tracker->owner_count;
	while (lo < hi) {
		__u32 mid = lo + ((hi - lo) >> 1);

		if (tracker->owners[mid].gfn < gfn)
			lo = mid + 1;
		else
			hi = mid;
	}

	if (lo < tracker->owner_count && tracker->owners[lo].gfn == gfn) {
		if (tracker->owners[lo].exec_ack)
			return -EALREADY;
		tracker->owners[lo].exec_ack = 1;
		return 0;
	}

	return -ENOENT;
}

int nyx_strict_pt_tracker_resolve_exec(
	const struct nyx_strict_pt_tracker *tracker,
	const struct nyx_strict_pt_data_tracker *data_tracker,
	__u64 gva, __u64 gfn,
	struct nyx_strict_pt_exec_identity *identity)
{
	__u32 i;
	bool seen_gva = false;
	bool efault = false;

	if (!tracker || !data_tracker || !identity)
		return -EINVAL;

	for (i = 0; i < NYX_STRICT_PT_MAX_RANGES; i++) {
		if (!tracker->ranges[i].active || !data_tracker->slots[i].active)
			continue;
		if (tracker->ranges[i].range_id != data_tracker->slots[i].range_id)
			continue;

		if (gva >= tracker->ranges[i].gva_start && gva < tracker->ranges[i].gva_end) {
			__u64 offset = gva - tracker->ranges[i].gva_start;
			__u32 page_index = offset >> NYX_STRICT_PT_PAGE_SHIFT;

			seen_gva = true;

			if (page_index >= data_tracker->slots[i].gfn_count) {
				efault = true;
				continue;
			}

			if (data_tracker->slots[i].gfns[page_index] == gfn) {
				identity->range_id = tracker->ranges[i].range_id;
				identity->generation = tracker->ranges[i].generation;
				identity->page_index = page_index;
				return 0;
			}
		}
	}

	if (efault)
		return -EFAULT;
	if (seen_gva)
		return -ESTALE;

	return -ENOENT;
}
