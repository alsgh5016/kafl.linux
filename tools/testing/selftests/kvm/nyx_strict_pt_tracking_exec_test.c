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

static void test_initial_owned_gfn_needs_nx_and_ack(void)
{
	struct nyx_strict_pt_data_tracker tracker = { 0 };
	__u64 data_gfns[] = { 40, 30, 40, 31 };
	bool needs_nx = false;

	commit_slot(&tracker, 0, 1, data_gfns, 4);

	/* initial owned GFN needs NX */
	ERR(nyx_strict_pt_data_tracker_needs_nx(&tracker, 30, &needs_nx), 0);
	EQ(needs_nx, 1);

	/* unowned gives ENOENT */
	ERR(nyx_strict_pt_data_tracker_needs_nx(&tracker, 99, &needs_nx), -ENOENT);

	/* ACK makes it not need NX without changing range_mask */
	ERR(nyx_strict_pt_data_tracker_ack_exec(&tracker, 30), 0);
	ERR(nyx_strict_pt_data_tracker_needs_nx(&tracker, 30, &needs_nx), 0);
	EQ(needs_nx, 0);

	/* duplicate alias within one range (40) is physical GFN */
	ERR(nyx_strict_pt_data_tracker_needs_nx(&tracker, 40, &needs_nx), 0);
	EQ(needs_nx, 1);
	ERR(nyx_strict_pt_data_tracker_ack_exec(&tracker, 40), 0);
	ERR(nyx_strict_pt_data_tracker_needs_nx(&tracker, 40, &needs_nx), 0);
	EQ(needs_nx, 0);
	ERR(nyx_strict_pt_data_tracker_ack_exec(&tracker, 40), -EALREADY);

	nyx_strict_pt_data_tracker_cleanup(&tracker);
}

static void test_rearm_and_preserve(void)
{
	struct nyx_strict_pt_data_tracker tracker = { 0 };
	struct nyx_strict_pt_data_prepare prepare = { 0 };
	__u64 first[] = { 40, 30 };
	__u64 second[] = { 50, 30 };
	__u64 first_shrink[] = { 40 };
	__u64 third[] = { 90 };
	bool needs_nx = false;

	commit_slot(&tracker, 0, 1, first, 2);
	ERR(nyx_strict_pt_data_tracker_ack_exec(&tracker, 30), 0);

	/* same GFN across two ranges; adding/re-walking an owner rearms */
	commit_slot(&tracker, 1, 2, second, 2);
	ERR(nyx_strict_pt_data_tracker_needs_nx(&tracker, 30, &needs_nx), 0);
	EQ(needs_nx, 1); /* rearmed */

	/* ACK again */
	ERR(nyx_strict_pt_data_tracker_ack_exec(&tracker, 30), 0);
	ERR(nyx_strict_pt_data_tracker_ack_exec(&tracker, 40), 0);

	/* removing one alias preserves prior ACK for remaining ownership */
	commit_slot(&tracker, 0, 1, first_shrink, 1);
	ERR(nyx_strict_pt_data_tracker_needs_nx(&tracker, 30, &needs_nx), 0);
	EQ(needs_nx, 0); /* Still ACKed */

	/* unrelated range update preserves ACK */
	commit_slot(&tracker, 2, 3, third, 1);
	ERR(nyx_strict_pt_data_tracker_needs_nx(&tracker, 30, &needs_nx), 0);
	EQ(needs_nx, 0);
	ERR(nyx_strict_pt_data_tracker_needs_nx(&tracker, 40, &needs_nx), 0);
	EQ(needs_nx, 1);

	/* final removal eliminates ownership */
	ERR(nyx_strict_pt_data_tracker_prepare(&tracker, 1, 2, NULL, 0, &prepare), 0);
	nyx_strict_pt_data_tracker_commit(&tracker, &prepare);
	ERR(nyx_strict_pt_data_tracker_needs_nx(&tracker, 30, &needs_nx), -ENOENT);

	nyx_strict_pt_data_tracker_cleanup(&tracker);
}

static void test_alloc_failure_preserves(void)
{
	struct nyx_strict_pt_data_tracker tracker = { 0 };
	struct nyx_strict_pt_data_prepare prepare = { 0 };
	__u64 first[] = { 30 };
	__u64 second[] = { 40 };
	bool needs_nx = false;

	commit_slot(&tracker, 0, 1, first, 1);
	ERR(nyx_strict_pt_data_tracker_ack_exec(&tracker, 30), 0);

	nyx_strict_pt_test_fail_next_allocations(1);
	ERR(nyx_strict_pt_data_tracker_prepare(&tracker, 1, 2,
		second, 1, &prepare), -ENOMEM);

	/* allocation failure preserves live ACK and ownership */
	ERR(nyx_strict_pt_data_tracker_needs_nx(&tracker, 30, &needs_nx), 0);
	EQ(needs_nx, 0);

	nyx_strict_pt_data_tracker_cleanup(&tracker);
}

static void commit_tracker_slot(struct nyx_strict_pt_tracker *tracker, __u32 slot,
	__u64 range_id, __u64 gva_start, __u64 gva_end, __u64 generation)
{
	tracker->ranges[slot].active = 1;
	tracker->ranges[slot].range_id = range_id;
	tracker->ranges[slot].gva_start = gva_start;
	tracker->ranges[slot].gva_end = gva_end;
	tracker->ranges[slot].generation = generation;
}

static void test_exec_identity_resolution(void)
{
	struct nyx_strict_pt_tracker tracker = { 0 };
	struct nyx_strict_pt_data_tracker data = { 0 };
	struct nyx_strict_pt_exec_identity id = { 0 };
	__u64 gfns_r1[] = { 10, 20, 10 };
	__u64 gfns_r2[] = { 20, 30 };

	commit_tracker_slot(&tracker, 0, 100, 0x1000, 0x4000, 5);
	commit_slot(&data, 0, 100, gfns_r1, 3);

	commit_tracker_slot(&tracker, 1, 200, 0x4000, 0x6000, 6);
	commit_slot(&data, 1, 200, gfns_r2, 2);

	/* Out of range */
	ERR(nyx_strict_pt_tracker_resolve_exec(&tracker, &data, 0x0FFF, 10, &id), -ENOENT);
	ERR(nyx_strict_pt_tracker_resolve_exec(&tracker, &data, 0x6000, 30, &id), -ENOENT);

	/* Exact match */
	ERR(nyx_strict_pt_tracker_resolve_exec(&tracker, &data, 0x1005, 10, &id), 0);
	EQ(id.range_id, 100);
	EQ(id.generation, 5);
	EQ(id.page_index, 0);

	ERR(nyx_strict_pt_tracker_resolve_exec(&tracker, &data, 0x2000, 20, &id), 0);
	EQ(id.range_id, 100);
	EQ(id.generation, 5);
	EQ(id.page_index, 1);

	/* Mismatch */
	ERR(nyx_strict_pt_tracker_resolve_exec(&tracker, &data, 0x1000, 20, &id), -ESTALE);

	/* Duplicate alias */
	ERR(nyx_strict_pt_tracker_resolve_exec(&tracker, &data, 0x3000, 10, &id), 0);
	EQ(id.range_id, 100);
	EQ(id.page_index, 2);

	/* Shared across ranges */
	ERR(nyx_strict_pt_tracker_resolve_exec(&tracker, &data, 0x4000, 20, &id), 0);
	EQ(id.range_id, 200);
	EQ(id.generation, 6);
	EQ(id.page_index, 0);

	/* Inactive/Mismatched */
	tracker.ranges[0].active = 0;
	ERR(nyx_strict_pt_tracker_resolve_exec(&tracker, &data, 0x1000, 10, &id), -ENOENT);

	tracker.ranges[0].active = 1;
	data.slots[0].active = 0;
	ERR(nyx_strict_pt_tracker_resolve_exec(&tracker, &data, 0x1000, 10, &id), -ENOENT);

	data.slots[0].active = 1;
	data.slots[0].range_id = 999;
	ERR(nyx_strict_pt_tracker_resolve_exec(&tracker, &data, 0x1000, 10, &id), -ENOENT);

	/* Overlapping ranges deterministic selection (first active match in slot order) */
	data.slots[0].range_id = 100;
	commit_tracker_slot(&tracker, 2, 300, 0x1000, 0x2000, 7);
	commit_slot(&data, 2, 300, gfns_r1, 1);
	ERR(nyx_strict_pt_tracker_resolve_exec(&tracker, &data, 0x1000, 10, &id), 0);
	EQ(id.range_id, 100);

	tracker.ranges[0].gva_start = 0x5000;
	tracker.ranges[0].gva_end = 0x6000;

	tracker.ranges[1].gva_start = 0x5000;
	tracker.ranges[1].gva_end = 0x6000;

	ERR(nyx_strict_pt_tracker_resolve_exec(&tracker, &data, 0x5000, 20, &id), 0);
	EQ(id.range_id, 200);
	EQ(id.generation, 6);
	EQ(id.page_index, 0);

	ERR(nyx_strict_pt_tracker_resolve_exec(&tracker, &data, 0x5000, 99, &id), -ESTALE);

	nyx_strict_pt_data_tracker_cleanup(&data);
}

static void test_ack_rearmed_by_same_slot_republish(void)
{
	struct nyx_strict_pt_data_tracker tracker = { 0 };
	__u64 first[] = { 0x10, 0x20 };
	__u64 second[] = { 0x10, 0x30 };
	bool needs_nx = false;

	commit_slot(&tracker, 0, 1, first, 2);
	ERR(nyx_strict_pt_data_tracker_ack_exec(&tracker, 0x10), 0);
	ERR(nyx_strict_pt_data_tracker_needs_nx(&tracker, 0x10, &needs_nx), 0);
	EQ(needs_nx, 0);

	commit_slot(&tracker, 0, 1, second, 2);
	ERR(nyx_strict_pt_data_tracker_needs_nx(&tracker, 0x10, &needs_nx), 0);
	EQ(needs_nx, 1);

	nyx_strict_pt_data_tracker_cleanup(&tracker);
}

int main(void)
{
	test_initial_owned_gfn_needs_nx_and_ack();
	test_rearm_and_preserve();
	test_alloc_failure_preserves();
	test_exec_identity_resolution();
	test_ack_rearmed_by_same_slot_republish();
	printf("nyx_strict_pt_tracking_exec_test: ok\n");
	return 0;
}
