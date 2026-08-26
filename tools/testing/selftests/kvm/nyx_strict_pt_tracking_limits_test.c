// SPDX-License-Identifier: GPL-2.0

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "nyx_strict_pt_tracking.h"

#define EXPECT_EQ(actual, expected) do { \
	uint64_t _actual = (uint64_t)(actual); \
	uint64_t _expected = (uint64_t)(expected); \
	if (_actual != _expected) { \
		fprintf(stderr, "FAIL:%d: %s=0x%llx expected 0x%llx\n", \
			__LINE__, #actual, (unsigned long long)_actual, \
			(unsigned long long)_expected); \
		exit(1); \
	} \
} while (0)

static void set_add(struct nyx_strict_pt_range_add_txn *add, __u64 session_id,
	__u64 gva_start, __u64 generation)
{
	add->session_id = session_id;
	add->gva_start = gva_start;
	add->gva_end = gva_start + NYX_STRICT_PT_PAGE_SIZE;
	add->generation = generation;
	add->va_bits = 48;
}

static void test_slot_exhaustion(void)
{
	struct nyx_strict_pt_tracker tracker = { 0 };
	struct nyx_strict_pt_prepare prepare = { 0 };
	struct nyx_strict_pt_range_add_txn add = { 0 };
	__u64 gfn = 9;
	__u32 i;

	EXPECT_EQ(nyx_strict_pt_tracker_begin_session(&tracker, 10), 0);
	for (i = 0; i < NYX_STRICT_PT_MAX_RANGES; i++) {
		set_add(&add, 10, 0x30000 + ((__u64)i << 12), i + 1);
		EXPECT_EQ(nyx_strict_pt_tracker_prepare_add(
			&tracker, &add, &gfn, 1, &prepare), 0);
		nyx_strict_pt_tracker_commit(&tracker, &prepare);
	}
	EXPECT_EQ(tracker.active_range_count, NYX_STRICT_PT_MAX_RANGES);
	EXPECT_EQ(nyx_strict_pt_tracker_prepare_add(
		&tracker, &add, &gfn, 1, &prepare), -ENOSPC);
	nyx_strict_pt_tracker_cleanup(&tracker);
}

static void test_id_and_owner_count_exhaustion(void)
{
	struct nyx_strict_pt_tracker tracker = { 0 };
	struct nyx_strict_pt_prepare prepare = { 0 };
	struct nyx_strict_pt_range_add_txn add = { 0 };
	__u64 gfn = 9;

	EXPECT_EQ(nyx_strict_pt_tracker_begin_session(&tracker, 20), 0);
	set_add(&add, 20, 0x50000, 1);
	tracker.next_range_id = ~0ULL;
	EXPECT_EQ(nyx_strict_pt_tracker_prepare_add(
		&tracker, &add, &gfn, 1, &prepare), -EOVERFLOW);
	tracker.next_range_id = 1;
	tracker.owner_count = ~(__u32)0U;
	EXPECT_EQ(nyx_strict_pt_tracker_prepare_add(
		&tracker, &add, &gfn, 1, &prepare), -EOVERFLOW);
	tracker.owner_count = 0;
	nyx_strict_pt_tracker_cleanup(&tracker);
}

static void test_allocation_failure(void)
{
	struct nyx_strict_pt_tracker tracker = { 0 };
	struct nyx_strict_pt_prepare prepare = { 0 };
	struct nyx_strict_pt_range_add_txn add = { 0 };
	__u64 gfns[] = { 5, 3, 5, 4, 3 };

	EXPECT_EQ(nyx_strict_pt_tracker_begin_session(&tracker, 1), 0);
	set_add(&add, 1, 0x4000, 11);
	nyx_strict_pt_test_fail_next_allocations(1);
	EXPECT_EQ(nyx_strict_pt_tracker_prepare_add(
		&tracker, &add, gfns, 5, &prepare), -ENOMEM);
	nyx_strict_pt_tracker_cleanup(&tracker);
}

static void test_public_range_validation(void)
{
	struct nyx_strict_pt_range_add_txn add = {
		.session_id = 1,
		.gva_start = 0x4000,
		.gva_end = 0x8000,
		.generation = 7,
		.va_bits = 48,
	};

	EXPECT_EQ(nyx_strict_pt_validate_range_add_txn(&add), 0);
	add.generation = 0;
	EXPECT_EQ(nyx_strict_pt_validate_range_add_txn(&add), -EINVAL);
	add.generation = 7;
	add.gva_start = 0x0000800000000000ULL;
	add.gva_end = add.gva_start + NYX_STRICT_PT_PAGE_SIZE;
	EXPECT_EQ(nyx_strict_pt_validate_range_add_txn(&add), -EINVAL);
}

static void test_owner_overlap_helper(void)
{
	struct nyx_strict_pt_tracker tracker = {
		.owner_count = 3,
	};
	struct nyx_strict_pt_owner owners[] = {
		{ .gfn = 10, .range_mask = 1 },
		{ .gfn = 12, .range_mask = 2 },
		{ .gfn = 20, .range_mask = 4 },
	};

	tracker.owners = owners;
	EXPECT_EQ(nyx_strict_pt_owner_overlaps_range(&tracker, 0, 10), 0);
	EXPECT_EQ(nyx_strict_pt_owner_overlaps_range(&tracker, 11, 2), 1);
	EXPECT_EQ(nyx_strict_pt_owner_overlaps_range(&tracker, 20, 1), 1);
	EXPECT_EQ(nyx_strict_pt_owner_overlaps_range(&tracker, 21, 4), 0);
}

int main(void)
{
	test_slot_exhaustion();
	test_id_and_owner_count_exhaustion();
	test_allocation_failure();
	test_public_range_validation();
	test_owner_overlap_helper();
	printf("nyx_strict_pt_tracking_limits_test: ok\n");
	return 0;
}
