// SPDX-License-Identifier: GPL-2.0

#include "nyx_strict_pt_tracking_internal.h"

#ifdef __KERNEL__
#include <linux/errno.h>
#else
#include <errno.h>
#endif

int nyx_strict_pt_alloc_sorted_unique(const __u64 *gfns, __u32 count,
	__u64 **uniq_out, __u32 *uniq_count_out)
{
	__u64 *uniq = nyx_strict_pt_alloc_array(count, sizeof(*uniq));

	if (count && !uniq)
		return -ENOMEM;
	memcpy(uniq, gfns, (size_t)count * sizeof(*uniq));
	nyx_strict_pt_sort_u64(uniq, count);
	*uniq_out = uniq;
	*uniq_count_out = nyx_strict_pt_dedupe_u64(uniq, count);
	return 0;
}

int nyx_strict_pt_merge_owners(const struct nyx_strict_pt_owner *old,
	__u32 old_count, __u64 bit, const __u64 *new_gfns, __u32 new_count,
	struct nyx_strict_pt_owner **owners_out, __u32 *owner_count_out,
	__u64 **track_out, __u32 *track_count_out, __u64 **untrack_out,
	__u32 *untrack_count_out)
{
	struct nyx_strict_pt_owner *owners = nyx_strict_pt_alloc_array(old_count + new_count, sizeof(*owners));
	__u64 *track = nyx_strict_pt_alloc_array(new_count, sizeof(*track));
	__u64 *untrack = nyx_strict_pt_alloc_array(old_count, sizeof(*untrack));
	__u32 i = 0, j = 0, k = 0, t = 0, u = 0;

	if ((old_count + new_count && !owners) || (new_count && !track) ||
	    (old_count && !untrack)) {
		nyx_strict_pt_free(owners);
		nyx_strict_pt_free(track);
		nyx_strict_pt_free(untrack);
		return -ENOMEM;
	}
	while (i < old_count || j < new_count) {
		if (j >= new_count || (i < old_count && old[i].gfn < new_gfns[j])) {
			__u64 mask = old[i].range_mask & ~bit;

			if (mask) {
				owners[k] = old[i];
				owners[k++].range_mask = mask;
			} else {
				untrack[u++] = old[i].gfn;
			}
			i++;
			continue;
		}
		if (i < old_count && old[i].gfn == new_gfns[j]) {
			owners[k] = old[i];
			owners[k].range_mask = (old[i].range_mask & ~bit) | bit;
			owners[k].exec_ack = 0;
			k++;
			i++;
			j++;
			continue;
		}
		owners[k].gfn = new_gfns[j];
		owners[k].range_mask = bit;
		owners[k].exec_ack = 0;
		k++;
		track[t++] = new_gfns[j++];
	}
	*owners_out = owners;
	*owner_count_out = k;
	*track_out = track;
	*track_count_out = t;
	*untrack_out = untrack;
	*untrack_count_out = u;
	return 0;
}
