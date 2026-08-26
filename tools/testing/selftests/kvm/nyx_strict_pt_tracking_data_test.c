// SPDX-License-Identifier: GPL-2.0

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "../../../../arch/x86/kvm/nyx_strict_pt_tracking.h"

#define EQ(a, b) do { uint64_t _a = (uint64_t)(a), _b = (uint64_t)(b); \
	if (_a != _b) fail_eq(__LINE__, #a, _a, _b); } while (0)
#define ERR(a, b) do { int _a = (a), _b = (b); if (_a != _b) fail_err(__LINE__, #a, _a, _b); } while (0)

static void fail_eq(int line, const char *expr, uint64_t actual, uint64_t expect)
{
	fprintf(stderr, "FAIL:%d: %s=0x%llx expected 0x%llx\n", line, expr,
		(unsigned long long)actual, (unsigned long long)expect);
	exit(1);
}

static void fail_err(int line, const char *expr, int actual, int expect)
{
	fprintf(stderr, "FAIL:%d: %s=%d expected %d\n", line, expr, actual, expect);
	exit(1);
}

static void commit_slot(struct nyx_strict_pt_data_tracker *tracker, __u32 slot,
	__u64 range_id, const __u64 *gfns, __u32 gfn_count)
{
	struct nyx_strict_pt_data_prepare prepare = { 0 };

	ERR(nyx_strict_pt_data_tracker_prepare(tracker, slot, range_id,
		gfns, gfn_count, &prepare), 0);
	nyx_strict_pt_data_tracker_commit(tracker, &prepare);
}

static void test_ordered_snapshot_with_aliases(void)
{
	struct nyx_strict_pt_data_tracker tracker = { 0 };
	struct nyx_strict_pt_data_prepare prepare = { 0 };
	__u64 data_gfns[] = { 40, 30, 40, 31 };

	ERR(nyx_strict_pt_data_tracker_prepare(&tracker, 0, 1,
		data_gfns, 4, &prepare), 0);
	EQ(prepare.snapshot.range_id, 1);
	EQ(prepare.snapshot.gfn_count, 4);
	EQ(prepare.snapshot.gfns[0], 40);
	EQ(prepare.snapshot.gfns[1], 30);
	EQ(prepare.snapshot.gfns[2], 40);
	EQ(prepare.snapshot.gfns[3], 31);
	EQ(prepare.owner_count, 3);
	EQ(prepare.owners[0].gfn, 30);
	EQ(prepare.owners[1].gfn, 31);
	EQ(prepare.owners[2].gfn, 40);
	EQ(prepare.track_count, 3);
	EQ(prepare.track_gfns[0], 30);
	EQ(prepare.track_gfns[1], 31);
	EQ(prepare.track_gfns[2], 40);
	nyx_strict_pt_data_tracker_commit(&tracker, &prepare);
	EQ(nyx_strict_pt_data_tracker_owned(&tracker, 31), 1);
	EQ(nyx_strict_pt_data_tracker_owned(&tracker, 99), 0);
	nyx_strict_pt_data_tracker_cleanup(&tracker);
}

static void test_sorted_global_owners_and_owner_deltas(void)
{
	struct nyx_strict_pt_data_tracker tracker = { 0 };
	struct nyx_strict_pt_data_prepare prepare = { 0 };
	const __u64 *live_slot;
	const __u64 *prepared_slot;
	struct nyx_strict_pt_owner *live_owners;
	struct nyx_strict_pt_owner *prepared_owners;
	__u64 first[] = { 40, 30, 40, 31 };
	__u64 second[] = { 50, 31 };
	__u64 shrink[] = { 31 };

	commit_slot(&tracker, 0, 1, first, 4);
	ERR(nyx_strict_pt_data_tracker_prepare(&tracker, 1, 2,
		second, 2, &prepare), 0);
	EQ(prepare.track_count, 1);
	EQ(prepare.track_gfns[0], 50);
	EQ(prepare.owner_count, 4);
	EQ(prepare.owners[0].gfn, 30);
	EQ(prepare.owners[0].range_mask, 1);
	EQ(prepare.owners[1].gfn, 31);
	EQ(prepare.owners[1].range_mask, 3);
	EQ(prepare.owners[2].gfn, 40);
	EQ(prepare.owners[2].range_mask, 1);
	EQ(prepare.owners[3].gfn, 50);
	EQ(prepare.owners[3].range_mask, 2);
	live_owners = tracker.owners;
	live_slot = tracker.slots[1].gfns;
	prepared_owners = prepare.owners;
	prepared_slot = prepare.snapshot.gfns;
	nyx_strict_pt_data_tracker_publish(&tracker, &prepare);
	EQ((uintptr_t)tracker.owners, (uintptr_t)prepared_owners);
	EQ((uintptr_t)tracker.slots[1].gfns, (uintptr_t)prepared_slot);
	EQ((uintptr_t)prepare.retired_owners, (uintptr_t)live_owners);
	EQ((uintptr_t)prepare.retired_gfns, (uintptr_t)live_slot);
	EQ((uintptr_t)prepare.owners, 0);
	EQ((uintptr_t)prepare.snapshot.gfns, 0);
	EQ(prepare.track_count, 1);
	nyx_strict_pt_data_tracker_abort(&prepare);
	EQ(prepare.slot, 0);
	ERR(nyx_strict_pt_data_tracker_prepare(&tracker, 0, 1,
		shrink, 1, &prepare), 0);
	EQ(prepare.track_count, 0);
	EQ(prepare.untrack_count, 2);
	EQ(prepare.untrack_gfns[0], 30);
	EQ(prepare.untrack_gfns[1], 40);
	EQ(prepare.owner_count, 2);
	EQ(prepare.owners[0].gfn, 31);
	EQ(prepare.owners[0].range_mask, 3);
	EQ(prepare.owners[1].gfn, 50);
	EQ(prepare.owners[1].range_mask, 2);
	nyx_strict_pt_data_tracker_commit(&tracker, &prepare);
	nyx_strict_pt_data_tracker_cleanup(&tracker);
}

struct tracker_snapshot {
	const void *owners;
	const void *slot0_gfns;
	const void *slot1_gfns;
	__u32 owner_count;
	__u32 active_range_count;
	__u32 slot0_count;
	__u32 slot1_count;
	__u64 slot0_range_id;
	__u64 slot1_range_id;
};

static struct tracker_snapshot snapshot_tracker(
	const struct nyx_strict_pt_data_tracker *tracker)
{
	struct tracker_snapshot snap = {
		.owners = tracker->owners,
		.slot0_gfns = tracker->slots[0].gfns,
		.slot1_gfns = tracker->slots[1].gfns,
		.owner_count = tracker->owner_count,
		.active_range_count = tracker->active_range_count,
		.slot0_count = tracker->slots[0].gfn_count,
		.slot1_count = tracker->slots[1].gfn_count,
		.slot0_range_id = tracker->slots[0].range_id,
		.slot1_range_id = tracker->slots[1].range_id,
	};

	return snap;
}

static void test_allocation_failure_leaves_live_tracker_unchanged(void)
{
	struct nyx_strict_pt_data_tracker tracker = { 0 };
	struct nyx_strict_pt_data_prepare prepare = { 0 };
	struct tracker_snapshot before;
	__u64 first[] = { 40, 30, 40, 31 };
	__u64 second[] = { 50, 31 };
	__u64 update[] = { 60, 31 };

	commit_slot(&tracker, 0, 1, first, 4);
	commit_slot(&tracker, 1, 2, second, 2);
	before = snapshot_tracker(&tracker);
	nyx_strict_pt_test_fail_next_allocations(1);
	ERR(nyx_strict_pt_data_tracker_prepare(&tracker, 1, 2,
		update, 2, &prepare), -ENOMEM);
	EQ((uintptr_t)tracker.owners, (uintptr_t)before.owners);
	EQ((uintptr_t)tracker.slots[0].gfns, (uintptr_t)before.slot0_gfns);
	EQ((uintptr_t)tracker.slots[1].gfns, (uintptr_t)before.slot1_gfns);
	EQ(tracker.owner_count, before.owner_count);
	EQ(tracker.active_range_count, before.active_range_count);
	EQ(tracker.slots[0].gfn_count, before.slot0_count);
	EQ(tracker.slots[1].gfn_count, before.slot1_count);
	EQ(tracker.slots[0].range_id, before.slot0_range_id);
	EQ(tracker.slots[1].range_id, before.slot1_range_id);
	nyx_strict_pt_data_tracker_abort(&prepare);
	nyx_strict_pt_data_tracker_cleanup(&tracker);
}

int main(void)
{
	test_ordered_snapshot_with_aliases();
	test_sorted_global_owners_and_owner_deltas();
	test_allocation_failure_leaves_live_tracker_unchanged();
	printf("nyx_strict_pt_tracking_data_test: ok\n");
	return 0;
}
