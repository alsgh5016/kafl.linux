// SPDX-License-Identifier: GPL-2.0

#include "nyx_strict_pt_tracking_internal.h"

#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/sort.h>
#else
#include <errno.h>
#include <stdlib.h>
static __u32 nyx_fail_allocs;
#endif

#ifndef __KERNEL__
void nyx_strict_pt_test_fail_next_allocations(__u32 count)
{
	nyx_fail_allocs = count;
}
#endif

void *nyx_strict_pt_alloc_array(__u32 count, __u64 size)
{
	if (!count)
		return NULL;
	if ((__u64)count > (~(size_t)0) / size)
		return NULL;
#ifdef __KERNEL__
	return kvcalloc((size_t)count, (size_t)size, GFP_KERNEL_ACCOUNT);
#else
	if (nyx_fail_allocs) {
		nyx_fail_allocs--;
		return NULL;
	}
	return calloc((size_t)count, (size_t)size);
#endif
}

void nyx_strict_pt_free(void *ptr)
{
	if (!ptr)
		return;
#ifdef __KERNEL__
	kvfree(ptr);
#else
	free(ptr);
#endif
}

static int nyx_strict_pt_u64_cmp(const void *lhs, const void *rhs)
{
	const __u64 *a = lhs;
	const __u64 *b = rhs;

	return (*a > *b) - (*a < *b);
}

void nyx_strict_pt_sort_u64(__u64 *items, __u32 count)
{
#ifdef __KERNEL__
	sort(items, count, sizeof(*items), nyx_strict_pt_u64_cmp, NULL);
#else
	qsort(items, count, sizeof(*items), nyx_strict_pt_u64_cmp);
#endif
}

__u32 nyx_strict_pt_dedupe_u64(__u64 *items, __u32 count)
{
	__u32 i;
	__u32 out = 0;

	for (i = 0; i < count; i++)
		if (!out || items[out - 1] != items[i])
			items[out++] = items[i];

	return out;
}

bool nyx_strict_pt_is_canonical(__u64 addr, __u8 va_bits)
{
	__u64 low_mask;
	__u64 sign_bit;
	__u64 low;

	if (va_bits != 48 && va_bits != 57)
		return false;
	low_mask = (1ULL << va_bits) - 1;
	sign_bit = 1ULL << (va_bits - 1);
	low = addr & low_mask;
	if (low & sign_bit)
		low |= ~low_mask;

	return low == addr;
}

int nyx_strict_pt_validate_range_add_txn(
	const struct nyx_strict_pt_range_add_txn *add)
{
	if (!add || !add->session_id || !add->generation ||
	    add->gva_start >= add->gva_end ||
	    ((add->gva_start | add->gva_end) & (NYX_STRICT_PT_PAGE_SIZE - 1)) ||
	    !nyx_strict_pt_is_canonical(add->gva_start, add->va_bits) ||
	    !nyx_strict_pt_is_canonical(add->gva_end - 1, add->va_bits))
		return -EINVAL;

	return 0;
}

__u32 nyx_strict_pt_find_free_slot(const struct nyx_strict_pt_tracker *tracker)
{
	__u32 i;

	for (i = 0; i < NYX_STRICT_PT_MAX_RANGES; i++)
		if (!tracker->ranges[i].active)
			return i;

	return NYX_STRICT_PT_MAX_RANGES;
}

__s32 nyx_strict_pt_find_range_slot(const struct nyx_strict_pt_tracker *tracker,
	__u64 range_id)
{
	__u32 i;

	for (i = 0; i < NYX_STRICT_PT_MAX_RANGES; i++)
		if (tracker->ranges[i].active &&
		    tracker->ranges[i].range_id == range_id)
			return (__s32)i;

	return -1;
}

__u64 nyx_strict_pt_active_mask(const struct nyx_strict_pt_tracker *tracker)
{
	__u32 i;
	__u64 mask = 0;

	for (i = 0; i < NYX_STRICT_PT_MAX_RANGES; i++)
		if (tracker->ranges[i].active)
			mask |= 1ULL << i;

	return mask;
}

__u64 nyx_strict_pt_find_owner_mask(const struct nyx_strict_pt_tracker *tracker,
	__u64 gfn)
{
	__u32 lo = 0;
	__u32 hi = tracker->owner_count;

	while (lo < hi) {
		__u32 mid = lo + ((hi - lo) >> 1);

		if (tracker->owners[mid].gfn < gfn)
			lo = mid + 1;
		else
			hi = mid;
	}

	if (lo < tracker->owner_count && tracker->owners[lo].gfn == gfn)
		return tracker->owners[lo].range_mask;

	return 0;
}

bool nyx_strict_pt_owner_overlaps_range(
	const struct nyx_strict_pt_tracker *tracker, __u64 gfn_start,
	__u64 gfn_count)
{
	__u64 gfn_end;
	__u32 lo = 0;
	__u32 hi;

	if (!tracker || !gfn_count)
		return false;

	gfn_end = gfn_start + gfn_count;
	if (gfn_end <= gfn_start)
		gfn_end = ~0ULL;

	hi = tracker->owner_count;
	while (lo < hi) {
		__u32 mid = lo + ((hi - lo) >> 1);

		if (tracker->owners[mid].gfn < gfn_start)
			lo = mid + 1;
		else
			hi = mid;
	}

	return lo < tracker->owner_count && tracker->owners[lo].gfn < gfn_end;
}
