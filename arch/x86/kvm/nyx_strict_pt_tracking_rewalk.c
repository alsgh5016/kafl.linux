// SPDX-License-Identifier: GPL-2.0

#include "nyx_strict_pt_tracking_internal.h"

#ifdef __KERNEL__
#include <linux/errno.h>
#else
#include <errno.h>
#endif

int nyx_strict_pt_tracker_reserve_generation(const struct nyx_strict_pt_tracker *tracker,
	__u64 range_id, __u64 *generation)
{
	__s32 slot;

	if (!tracker || !generation || !tracker->session_id || !range_id)
		return -EINVAL;
	slot = nyx_strict_pt_find_range_slot(tracker, range_id);
	if (slot < 0)
		return -ENOENT;
	if (tracker->ranges[slot].generation == ~0ULL)
		return -EOVERFLOW;
	*generation = tracker->ranges[slot].generation + 1;
	return 0;
}

int nyx_strict_pt_tracker_prepare_rewalk(const struct nyx_strict_pt_tracker *tracker,
	__u64 session_id, __u64 range_id, __u64 generation,
	const __u64 *table_gfns, __u64 table_gfn_count,
	struct nyx_strict_pt_prepare *prepare)
{
	struct nyx_strict_pt_owner *owners;
	__u64 *uniq;
	__u64 *track;
	__u64 *untrack;
	__u64 bit;
	__u32 input_count;
	__u32 owner_count;
	__u32 track_count;
	__u32 untrack_count;
	__s32 slot;
	int err;

	nyx_strict_pt_tracker_abort(prepare);
	if (!tracker || !prepare || !tracker->session_id || !session_id ||
	    !range_id || !generation || !table_gfns || !table_gfn_count ||
	    table_gfn_count > ~(__u32)0U)
		return -EINVAL;
	if (session_id != tracker->session_id)
		return -ESTALE;
	slot = nyx_strict_pt_find_range_slot(tracker, range_id);
	if (slot < 0)
		return -ENOENT;
	if (generation <= tracker->ranges[slot].generation)
		return -EINVAL;
	err = nyx_strict_pt_alloc_sorted_unique(table_gfns, (__u32)table_gfn_count,
		&uniq, &input_count);
	if (err)
		return err;
	if (tracker->owner_count > ~(__u32)0U - input_count) {
		nyx_strict_pt_free(uniq);
		return -EOVERFLOW;
	}
	bit = 1ULL << (__u32)slot;
	err = nyx_strict_pt_merge_owners(tracker->owners, tracker->owner_count,
		bit, uniq, input_count, &owners, &owner_count, &track,
		&track_count, &untrack, &untrack_count);
	nyx_strict_pt_free(uniq);
	if (err)
		return err;
	prepare->kind = NYX_STRICT_PT_PREPARE_REWALK;
	prepare->slot = (__u32)slot;
	prepare->range = tracker->ranges[slot];
	prepare->range.generation = generation;
	prepare->range.pt_dirty = 0;
	prepare->owners = owners;
	prepare->owner_count = owner_count;
	prepare->track_gfns = track;
	prepare->track_count = track_count;
	prepare->untrack_gfns = untrack;
	prepare->untrack_count = untrack_count;
	return 0;
}
