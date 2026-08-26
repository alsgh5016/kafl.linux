// SPDX-License-Identifier: GPL-2.0

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "../../../../arch/x86/kvm/nyx_strict_pt_tracking.h"

#define EQ(a, b) do { uint64_t _a = (uint64_t)(a), _b = (uint64_t)(b); \
	if (_a != _b) die_eq(__LINE__, #a, _a, _b); } while (0)
#define ERR(a, b) do { int _a = (a), _b = (b); if (_a != _b) die_err(__LINE__, #a, _a, _b); } while (0)

static void die_eq(int line, const char *expr, uint64_t actual, uint64_t expect)
{
	fprintf(stderr, "FAIL:%d: %s=0x%llx expected 0x%llx\n", line, expr,
		(unsigned long long)actual, (unsigned long long)expect);
	exit(1);
}

static void die_err(int line, const char *expr, int actual, int expect)
{
	fprintf(stderr, "FAIL:%d: %s=%d expected %d\n", line, expr, actual, expect);
	exit(1);
}

static void set_add(struct nyx_strict_pt_range_add_txn *add, __u64 session_id,
	__u64 gva_start, __u64 generation)
{
	add->session_id = session_id;
	add->gva_start = gva_start;
	add->gva_end = gva_start + NYX_STRICT_PT_PAGE_SIZE;
	add->generation = generation;
	add->va_bits = 48;
}

static void seed_tracker(struct nyx_strict_pt_tracker *tracker)
{
	struct nyx_strict_pt_prepare prepare = { 0 };
	struct nyx_strict_pt_range_add_txn add = { 0 };
	__u64 first[] = { 100, 101 };
	__u64 second[] = { 101, 102 };

	ERR(nyx_strict_pt_tracker_begin_session(tracker, 7), 0);
	set_add(&add, 7, 0x4000, 11);
	ERR(nyx_strict_pt_tracker_prepare_add(tracker, &add, first, 2, &prepare), 0);
	nyx_strict_pt_tracker_commit(tracker, &prepare);
	set_add(&add, 7, 0x8000, 22);
	ERR(nyx_strict_pt_tracker_prepare_add(tracker, &add, second, 2, &prepare), 0);
	nyx_strict_pt_tracker_commit(tracker, &prepare);
	tracker->ranges[0].pt_dirty = 1;
	tracker->ranges[1].pt_dirty = 1;
}

static void test_rewalk_no_change_selected_generation_only(void)
{
	struct nyx_strict_pt_tracker tracker = { 0 };
	struct nyx_strict_pt_prepare prepare = { 0 };
	__u64 table_gfns[] = { 100, 101 };
	__u64 generation = 0;

	seed_tracker(&tracker);
	ERR(nyx_strict_pt_tracker_reserve_generation(&tracker, 1, &generation), 0);
	EQ(generation, 12);
	ERR(nyx_strict_pt_tracker_prepare_rewalk(&tracker, 7, 1, generation,
		table_gfns, 2, &prepare), 0);
	EQ(prepare.track_count, 0);
	EQ(prepare.untrack_count, 0);
	EQ(prepare.range.range_id, 1);
	EQ(prepare.range.generation, 12);
	EQ(tracker.ranges[0].generation, 11);
	EQ(tracker.ranges[0].pt_dirty, 1);
	EQ(tracker.ranges[1].generation, 22);
	EQ(tracker.ranges[1].pt_dirty, 1);
	nyx_strict_pt_tracker_commit(&tracker, &prepare);
	EQ(tracker.ranges[0].generation, 12);
	EQ(tracker.ranges[0].pt_dirty, 0);
	EQ(tracker.ranges[1].generation, 22);
	EQ(tracker.ranges[1].pt_dirty, 1);
	nyx_strict_pt_tracker_cleanup(&tracker);
}

static void test_rewalk_added_and_removed_final_owner(void)
{
	struct nyx_strict_pt_tracker tracker = { 0 };
	struct nyx_strict_pt_prepare prepare = { 0 };
	struct nyx_strict_pt_owner *live_owners;
	struct nyx_strict_pt_owner *prepared_owners;
	__u64 table_gfns[] = { 101, 103 };
	__u64 generation = 0;

	seed_tracker(&tracker);
	ERR(nyx_strict_pt_tracker_reserve_generation(&tracker, 1, &generation), 0);
	ERR(nyx_strict_pt_tracker_prepare_rewalk(&tracker, 7, 1, generation,
		table_gfns, 2, &prepare), 0);
	EQ(prepare.track_count, 1);
	EQ(prepare.track_gfns[0], 103);
	EQ(prepare.untrack_count, 1);
	EQ(prepare.untrack_gfns[0], 100);
	EQ(prepare.owner_count, 3);
	EQ(prepare.owners[0].gfn, 101);
	EQ(prepare.owners[0].range_mask, 3);
	EQ(prepare.owners[1].gfn, 102);
	EQ(prepare.owners[1].range_mask, 2);
	EQ(prepare.owners[2].gfn, 103);
	EQ(prepare.owners[2].range_mask, 1);
	live_owners = tracker.owners;
	prepared_owners = prepare.owners;
	nyx_strict_pt_tracker_publish(&tracker, &prepare);
	EQ(tracker.owner_count, 3);
	EQ((uintptr_t)tracker.owners, (uintptr_t)prepared_owners);
	EQ((uintptr_t)tracker.owners == (uintptr_t)live_owners, 0);
	EQ((uintptr_t)prepare.retired_owners, (uintptr_t)live_owners);
	EQ((uintptr_t)prepare.owners, 0);
	EQ(prepare.track_count, 1);
	EQ(prepare.untrack_count, 1);
	EQ(tracker.owners[0].gfn, 101);
	EQ(tracker.owners[2].gfn, 103);
	nyx_strict_pt_tracker_abort(&prepare);
	EQ(prepare.kind, 0);
	nyx_strict_pt_tracker_cleanup(&tracker);
}

static void test_rewalk_removed_shared_owner(void)
{
	struct nyx_strict_pt_tracker tracker = { 0 };
	struct nyx_strict_pt_prepare prepare = { 0 };
	__u64 table_gfns[] = { 100 };
	__u64 generation = 0;

	seed_tracker(&tracker);
	ERR(nyx_strict_pt_tracker_reserve_generation(&tracker, 1, &generation), 0);
	ERR(nyx_strict_pt_tracker_prepare_rewalk(&tracker, 7, 1, generation,
		table_gfns, 1, &prepare), 0);
	EQ(prepare.track_count, 0);
	EQ(prepare.untrack_count, 0);
	EQ(prepare.owner_count, 3);
	EQ(prepare.owners[0].gfn, 100);
	EQ(prepare.owners[0].range_mask, 1);
	EQ(prepare.owners[1].gfn, 101);
	EQ(prepare.owners[1].range_mask, 2);
	EQ(prepare.owners[2].gfn, 102);
	EQ(prepare.owners[2].range_mask, 2);
	nyx_strict_pt_tracker_commit(&tracker, &prepare);
	EQ(tracker.owners[1].range_mask, 2);
	nyx_strict_pt_tracker_cleanup(&tracker);
}

static void test_generation_overflow(void)
{
	struct nyx_strict_pt_tracker tracker = { 0 };
	__u64 generation = 0;

	seed_tracker(&tracker);
	tracker.ranges[0].generation = ~0ULL;
	ERR(nyx_strict_pt_tracker_reserve_generation(&tracker, 1, &generation),
		-EOVERFLOW);
	nyx_strict_pt_tracker_cleanup(&tracker);
}

int main(void)
{
	test_rewalk_no_change_selected_generation_only();
	test_rewalk_added_and_removed_final_owner();
	test_rewalk_removed_shared_owner();
	test_generation_overflow();
	printf("nyx_strict_pt_tracking_rewalk_test: ok\n");
	return 0;
}
