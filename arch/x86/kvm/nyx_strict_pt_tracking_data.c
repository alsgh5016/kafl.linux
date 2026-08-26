// SPDX-License-Identifier: GPL-2.0

#include "nyx_strict_pt_tracking_internal.h"

#ifdef __KERNEL__
#include <linux/errno.h>
#else
#include <errno.h>
#endif

int nyx_strict_pt_data_tracker_prepare(const struct nyx_strict_pt_data_tracker *tracker,
	__u32 slot, __u64 range_id, const __u64 *data_gfns, __u32 data_gfn_count,
	struct nyx_strict_pt_data_prepare *prepare)
{
	struct nyx_strict_pt_owner *owners;
	__u64 *ordered = NULL;
	__u64 *uniq = NULL;
	__u64 *track;
	__u64 *untrack;
	__u64 bit;
	__u32 uniq_count = 0;
	__u32 owner_count;
	__u32 track_count;
	__u32 untrack_count;
	bool active;
	bool clear;
	int err;

	nyx_strict_pt_data_tracker_abort(prepare);
	if (!tracker || !prepare || slot >= NYX_STRICT_PT_MAX_RANGES || !range_id)
		return -EINVAL;
	active = tracker->slots[slot].active;
	clear = active && tracker->slots[slot].range_id == range_id &&
		!data_gfns && !data_gfn_count;
	if (active && tracker->slots[slot].range_id != range_id)
		return -ESTALE;
	if (!clear && (!data_gfns || !data_gfn_count))
		return -EINVAL;
	if (!active && tracker->active_range_count >= NYX_STRICT_PT_MAX_RANGES)
		return -ENOSPC;
	if (tracker->owner_count > ~(__u32)0U - data_gfn_count)
		return -EOVERFLOW;
	if (data_gfn_count) {
		ordered = nyx_strict_pt_alloc_array(data_gfn_count, sizeof(*ordered));
		if (!ordered)
			return -ENOMEM;
		memcpy(ordered, data_gfns, (size_t)data_gfn_count * sizeof(*ordered));
		err = nyx_strict_pt_alloc_sorted_unique(data_gfns, data_gfn_count,
			&uniq, &uniq_count);
		if (err)
			goto err;
	}
	bit = 1ULL << slot;
	err = nyx_strict_pt_merge_owners(tracker->owners, tracker->owner_count,
		bit, uniq, uniq_count, &owners, &owner_count, &track,
		&track_count, &untrack, &untrack_count);
	if (err)
		goto err;
	prepare->slot = slot;
	prepare->active_range_count = tracker->active_range_count + !active - clear;
	prepare->snapshot.gfns = ordered;
	prepare->snapshot.gfn_count = data_gfn_count;
	prepare->snapshot.active = !clear;
	prepare->snapshot.range_id = clear ? 0 : range_id;
	prepare->owners = owners;
	prepare->owner_count = owner_count;
	prepare->track_gfns = track;
	prepare->track_count = track_count;
	prepare->untrack_gfns = untrack;
	prepare->untrack_count = untrack_count;
	nyx_strict_pt_free(uniq);
	return 0;
err:
	nyx_strict_pt_free(ordered);
	nyx_strict_pt_free(uniq);
	return err;
}

void nyx_strict_pt_data_tracker_publish(struct nyx_strict_pt_data_tracker *tracker,
	struct nyx_strict_pt_data_prepare *prepare)
{
	if (!tracker || !prepare)
		return;
	prepare->retired_owners = tracker->owners;
	prepare->retired_gfns = tracker->slots[prepare->slot].gfns;
	tracker->owners = prepare->owners;
	tracker->owner_count = prepare->owner_count;
	tracker->slots[prepare->slot] = prepare->snapshot;
	tracker->active_range_count = prepare->active_range_count;
	prepare->owners = NULL;
	prepare->snapshot.gfns = NULL;
}

void nyx_strict_pt_data_tracker_commit(struct nyx_strict_pt_data_tracker *tracker,
	struct nyx_strict_pt_data_prepare *prepare)
{
	if (!tracker || !prepare)
		return;
	nyx_strict_pt_data_tracker_publish(tracker, prepare);
	nyx_strict_pt_data_tracker_abort(prepare);
}

void nyx_strict_pt_data_tracker_abort(struct nyx_strict_pt_data_prepare *prepare)
{
	if (!prepare)
		return;
	nyx_strict_pt_free((void *)prepare->retired_gfns);
	nyx_strict_pt_free(prepare->retired_owners);
	nyx_strict_pt_free((void *)prepare->snapshot.gfns);
	nyx_strict_pt_free(prepare->owners);
	nyx_strict_pt_free(prepare->track_gfns);
	nyx_strict_pt_free(prepare->untrack_gfns);
	memset(prepare, 0, sizeof(*prepare));
}

void nyx_strict_pt_data_tracker_cleanup(struct nyx_strict_pt_data_tracker *tracker)
{
	__u32 i;

	if (!tracker)
		return;
	for (i = 0; i < NYX_STRICT_PT_MAX_RANGES; i++)
		nyx_strict_pt_free((void *)tracker->slots[i].gfns);
	nyx_strict_pt_free(tracker->owners);
	memset(tracker, 0, sizeof(*tracker));
}

bool nyx_strict_pt_data_tracker_owned(const struct nyx_strict_pt_data_tracker *tracker,
	__u64 gfn)
{
	__u32 lo = 0;
	__u32 hi;

	if (!tracker)
		return false;
	hi = tracker->owner_count;
	while (lo < hi) {
		__u32 mid = lo + ((hi - lo) >> 1);

		if (tracker->owners[mid].gfn < gfn)
			lo = mid + 1;
		else
			hi = mid;
	}
	return lo < tracker->owner_count && tracker->owners[lo].gfn == gfn;
}
