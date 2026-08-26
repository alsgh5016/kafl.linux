// SPDX-License-Identifier: GPL-2.0

#include "nyx_strict_pt_tracking_internal.h"

#ifdef __KERNEL__
#include <linux/errno.h>
#else
#include <errno.h>
#endif

static int nyx_strict_pt_validate_add(const struct nyx_strict_pt_tracker *tracker,
	const struct nyx_strict_pt_range_add_txn *add, const __u64 *gfns,
	__u64 gfn_count, __u32 *input_count)
{
	if (!tracker || !gfns || !input_count || !tracker->session_id || !gfn_count)
		return -EINVAL;
	if (nyx_strict_pt_validate_range_add_txn(add))
		return -EINVAL;
	if (add->session_id != tracker->session_id)
		return -ESTALE;
	if (tracker->active_range_count >= NYX_STRICT_PT_MAX_RANGES)
		return -ENOSPC;
	if (!tracker->next_range_id || tracker->next_range_id == ~0ULL ||
	    gfn_count > ~(__u32)0U)
		return -EOVERFLOW;
	*input_count = (__u32)gfn_count;
	if (tracker->owner_count > ~(__u32)0U - *input_count)
		return -EOVERFLOW;

	return 0;
}

int nyx_strict_pt_tracker_prepare_add(const struct nyx_strict_pt_tracker *tracker,
	const struct nyx_strict_pt_range_add_txn *add, const __u64 *gfns,
	__u64 gfn_count, struct nyx_strict_pt_prepare *prepare)
{
	struct nyx_strict_pt_owner *owners;
	__u64 *uniq;
	__u64 *track;
	__u64 bit;
	__u32 input_count;
	__u32 uniq_count;
	__u32 slot;
	__u32 i;
	__u32 j;
	__u32 k;
	__u32 t;
	int err;

	nyx_strict_pt_tracker_abort(prepare);
	if (!prepare)
		return -EINVAL;
	err = nyx_strict_pt_validate_add(tracker, add, gfns, gfn_count,
					 &input_count);
	if (err)
		return err;
	slot = nyx_strict_pt_find_free_slot(tracker);
	if (slot == NYX_STRICT_PT_MAX_RANGES)
		return -ENOSPC;
	uniq = nyx_strict_pt_alloc_array(input_count, sizeof(*uniq));
	track = nyx_strict_pt_alloc_array(input_count, sizeof(*track));
	if (!uniq || !track) {
		nyx_strict_pt_free(uniq);
		nyx_strict_pt_free(track);
		return -ENOMEM;
	}
	memcpy(uniq, gfns, (size_t)input_count * sizeof(*uniq));
	nyx_strict_pt_sort_u64(uniq, input_count);
	uniq_count = nyx_strict_pt_dedupe_u64(uniq, input_count);
	if (tracker->owner_count > ~(__u32)0U - uniq_count) {
		nyx_strict_pt_free(uniq);
		nyx_strict_pt_free(track);
		return -EOVERFLOW;
	}
	owners = nyx_strict_pt_alloc_array(tracker->owner_count + uniq_count,
					    sizeof(*owners));
	if (!owners) {
		nyx_strict_pt_free(uniq);
		nyx_strict_pt_free(track);
		return -ENOMEM;
	}
	bit = 1ULL << slot;
	for (i = 0, j = 0, k = 0, t = 0;
	     i < tracker->owner_count || j < uniq_count;) {
		if (j >= uniq_count ||
		    (i < tracker->owner_count && tracker->owners[i].gfn < uniq[j])) {
			owners[k++] = tracker->owners[i++];
			continue;
		}
		if (i < tracker->owner_count && tracker->owners[i].gfn == uniq[j]) {
			owners[k] = tracker->owners[i++];
			owners[k++].range_mask |= bit;
			j++;
			continue;
		}
		owners[k].gfn = uniq[j];
		owners[k++].range_mask = bit;
		track[t++] = uniq[j++];
	}
	prepare->kind = NYX_STRICT_PT_PREPARE_ADD;
	prepare->slot = slot;
	prepare->next_range_id = tracker->next_range_id + 1;
	prepare->range.range_id = tracker->next_range_id;
	prepare->range.generation = add->generation;
	prepare->range.gva_start = add->gva_start;
	prepare->range.gva_end = add->gva_end;
	prepare->range.active = 1;
	prepare->owners = owners;
	prepare->owner_count = k;
	prepare->active_range_count = tracker->active_range_count + 1;
	prepare->track_gfns = track;
	prepare->track_count = t;
	nyx_strict_pt_free(uniq);

	return 0;
}

int nyx_strict_pt_tracker_prepare_remove(const struct nyx_strict_pt_tracker *tracker,
	const struct nyx_strict_pt_range_remove_txn *remove,
	struct nyx_strict_pt_prepare *prepare)
{
	struct nyx_strict_pt_owner *owners;
	__u64 *untrack;
	__u64 bit;
	__s32 slot;
	__u32 i;
	__u32 k = 0;
	__u32 u = 0;

	nyx_strict_pt_tracker_abort(prepare);
	if (!tracker || !remove || !prepare || !tracker->session_id ||
	    !remove->session_id || !remove->range_id)
		return -EINVAL;
	if (remove->session_id != tracker->session_id)
		return -ESTALE;
	slot = nyx_strict_pt_find_range_slot(tracker, remove->range_id);
	if (slot < 0)
		return -ENOENT;
	owners = nyx_strict_pt_alloc_array(tracker->owner_count ?: 1,
					   sizeof(*owners));
	untrack = nyx_strict_pt_alloc_array(tracker->owner_count ?: 1,
				    sizeof(*untrack));
	if (!owners || !untrack) {
		nyx_strict_pt_free(owners);
		nyx_strict_pt_free(untrack);
		return -ENOMEM;
	}
	bit = 1ULL << (__u32)slot;
	for (i = 0; i < tracker->owner_count; i++) {
		__u64 mask = tracker->owners[i].range_mask & ~bit;

		if (!mask) {
			untrack[u++] = tracker->owners[i].gfn;
			continue;
		}
		owners[k] = tracker->owners[i];
		owners[k++].range_mask = mask;
	}
	prepare->kind = NYX_STRICT_PT_PREPARE_REMOVE;
	prepare->slot = (__u32)slot;
	prepare->owners = owners;
	prepare->owner_count = k;
	prepare->active_range_count = tracker->active_range_count - 1;
	prepare->untrack_gfns = untrack;
	prepare->untrack_count = u;

	return 0;
}

int nyx_strict_pt_tracker_prepare_clear_session(
	const struct nyx_strict_pt_tracker *tracker, __u64 session_id,
	struct nyx_strict_pt_prepare *prepare)
{
	__u32 i;

	nyx_strict_pt_tracker_abort(prepare);
	if (!tracker || !prepare || !tracker->session_id || !session_id)
		return -EINVAL;
	if (session_id != tracker->session_id)
		return -ESTALE;
	prepare->kind = NYX_STRICT_PT_PREPARE_CLEAR_SESSION;
	prepare->untrack_count = tracker->owner_count;
	if (!tracker->owner_count)
		return 0;
	prepare->untrack_gfns = nyx_strict_pt_alloc_array(tracker->owner_count,
						 sizeof(*prepare->untrack_gfns));
	if (!prepare->untrack_gfns)
		return -ENOMEM;
	for (i = 0; i < tracker->owner_count; i++)
		prepare->untrack_gfns[i] = tracker->owners[i].gfn;

	return 0;
}
