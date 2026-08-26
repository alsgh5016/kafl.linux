// SPDX-License-Identifier: GPL-2.0

#include "nyx_strict_pt_tracking_internal.h"

#ifdef __KERNEL__
#include <linux/errno.h>
#else
#include <errno.h>
#endif

int nyx_strict_pt_tracker_begin_session(struct nyx_strict_pt_tracker *tracker,
	__u64 session_id)
{
	__u32 i;

	if (!tracker || !session_id || tracker->session_id || tracker->owners ||
	    tracker->owner_count || tracker->active_range_count)
		return -EINVAL;
	for (i = 0; i < NYX_STRICT_PT_MAX_RANGES; i++)
		if (tracker->ranges[i].active || tracker->ranges[i].pt_dirty)
			return -EINVAL;
	tracker->session_id = session_id;
	tracker->next_range_id = 1;

	return 0;
}

void nyx_strict_pt_tracker_publish(struct nyx_strict_pt_tracker *tracker,
	struct nyx_strict_pt_prepare *prepare)
{
	if (!tracker || !prepare || !prepare->kind)
		return;
	switch (prepare->kind) {
	case NYX_STRICT_PT_PREPARE_ADD:
	case NYX_STRICT_PT_PREPARE_REWALK:
		prepare->retired_owners = tracker->owners;
		tracker->owners = prepare->owners;
		tracker->owner_count = prepare->owner_count;
		tracker->ranges[prepare->slot] = prepare->range;
		if (prepare->kind == NYX_STRICT_PT_PREPARE_ADD) {
			tracker->active_range_count = prepare->active_range_count;
			tracker->next_range_id = prepare->next_range_id;
		}
		prepare->owners = NULL;
		break;
	case NYX_STRICT_PT_PREPARE_REMOVE:
		prepare->retired_owners = tracker->owners;
		tracker->owners = prepare->owners;
		tracker->owner_count = prepare->owner_count;
		memset(&tracker->ranges[prepare->slot], 0,
		       sizeof(tracker->ranges[prepare->slot]));
		tracker->active_range_count = prepare->active_range_count;
		prepare->owners = NULL;
		break;
	case NYX_STRICT_PT_PREPARE_CLEAR_SESSION:
		prepare->retired_owners = tracker->owners;
		tracker->owners = NULL;
		memset(tracker, 0, sizeof(*tracker));
		break;
	default:
		break;
	}
	if (prepare->kind)
		prepare->kind = prepare->kind;
}

void nyx_strict_pt_tracker_commit(struct nyx_strict_pt_tracker *tracker,
	struct nyx_strict_pt_prepare *prepare)
{
	if (!tracker || !prepare || !prepare->kind)
		return;
	nyx_strict_pt_tracker_publish(tracker, prepare);
	nyx_strict_pt_tracker_abort(prepare);
}

void nyx_strict_pt_tracker_abort(struct nyx_strict_pt_prepare *prepare)
{
	if (!prepare)
		return;
	nyx_strict_pt_free(prepare->retired_owners);
	nyx_strict_pt_free(prepare->owners);
	nyx_strict_pt_free(prepare->track_gfns);
	nyx_strict_pt_free(prepare->untrack_gfns);
	memset(prepare, 0, sizeof(*prepare));
}

void nyx_strict_pt_tracker_cleanup(struct nyx_strict_pt_tracker *tracker)
{
	if (!tracker)
		return;
	nyx_strict_pt_free(tracker->owners);
	memset(tracker, 0, sizeof(*tracker));
}

struct nyx_strict_pt_write_result nyx_strict_pt_tracker_classify_write(
	struct nyx_strict_pt_tracker *tracker, __u64 gpa_start, __u64 byte_count)
{
	struct nyx_strict_pt_write_result result = { 0 };
	__u64 gfn;
	__u64 last;
	__u64 last_gfn;
	__u64 mask = 0;

	if (!tracker || !tracker->session_id || !byte_count)
		return result;
	last = gpa_start + byte_count - 1;
	if (last < gpa_start)
		return result;
	gfn = gpa_start >> NYX_STRICT_PT_PAGE_SHIFT;
	last_gfn = last >> NYX_STRICT_PT_PAGE_SHIFT;
	for (;;) {
		mask |= nyx_strict_pt_find_owner_mask(tracker, gfn);
		if (gfn == last_gfn)
			break;
		gfn++;
	}
	mask &= nyx_strict_pt_active_mask(tracker);
	if (!mask)
		return result;
	for (gfn = 0; gfn < NYX_STRICT_PT_MAX_RANGES; gfn++)
		if (mask & (1ULL << gfn))
			tracker->ranges[gfn].pt_dirty = 1;
	result.session_id = tracker->session_id;
	result.range_mask = mask;

	return result;
}
