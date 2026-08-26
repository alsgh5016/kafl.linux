// SPDX-License-Identifier: GPL-2.0

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "nyx_strict_pt_tracking.h"

#define EQ(a, b) do { uint64_t _a = (uint64_t)(a), _b = (uint64_t)(b); \
	if (_a != _b) die2(__LINE__, #a, _a, _b); } while (0)
#define ERR(a, b) do { int _a = (a), _b = (b); if (_a != _b) die3(__LINE__, #a, _a, _b); } while (0)

static void die2(int line, const char *expr, uint64_t actual, uint64_t expect)
{
	fprintf(stderr, "FAIL:%d: %s=0x%llx expected 0x%llx\n", line, expr,
		(unsigned long long)actual, (unsigned long long)expect);
	exit(1);
}

static void die3(int line, const char *expr, int actual, int expect)
{
	fprintf(stderr, "FAIL:%d: %s=%d expected %d\n", line, expr, actual, expect);
	exit(1);
}

static void set_add(struct nyx_strict_pt_range_add_txn *add, __u64 session_id,
	__u64 gva_start, __u64 gva_end, __u64 generation, __u8 va_bits)
{
	add->session_id = session_id;
	add->gva_start = gva_start;
	add->gva_end = gva_end;
	add->generation = generation;
	add->va_bits = va_bits;
}

static void test_validation_and_canonicality(void)
{
	struct nyx_strict_pt_tracker tr = { 0 };
	struct nyx_strict_pt_prepare prep = { 0 };
	struct nyx_strict_pt_range_add_txn add = { 0 };
	__u64 dup[] = { 5, 3, 5, 4, 3 };

	ERR(nyx_strict_pt_tracker_begin_session(&tr, 0), -EINVAL);
	ERR(nyx_strict_pt_tracker_begin_session(&tr, 1), 0);
	ERR(nyx_strict_pt_tracker_begin_session(&tr, 2), -EINVAL);
	set_add(&add, 1, 0x4000, 0x7000, 11, 48);
	ERR(nyx_strict_pt_tracker_prepare_add(&tr, &add, dup, 0, &prep), -EINVAL);
	ERR(nyx_strict_pt_tracker_prepare_add(&tr, &add, dup, ~0ULL, &prep), -EOVERFLOW);
	add.session_id = 9;
	ERR(nyx_strict_pt_tracker_prepare_add(&tr, &add, dup, 5, &prep), -ESTALE);
	add.session_id = 1;
	add.gva_end = add.gva_start;
	ERR(nyx_strict_pt_tracker_prepare_add(&tr, &add, dup, 5, &prep), -EINVAL);
	add.gva_end = 0x7000;
	add.gva_start = 0x4100;
	ERR(nyx_strict_pt_tracker_prepare_add(&tr, &add, dup, 5, &prep), -EINVAL);
	add.gva_start = 0x0000800000000000ULL;
	add.gva_end = add.gva_start + 0x1000;
	ERR(nyx_strict_pt_tracker_prepare_add(&tr, &add, dup, 5, &prep), -EINVAL);
	add.gva_start = 0xff00000000000000ULL;
	add.gva_end = add.gva_start + 0x2000;
	add.va_bits = 57;
	ERR(nyx_strict_pt_tracker_prepare_add(&tr, &add, dup, 5, &prep), 0);
	EQ(prep.range.range_id, 1);
	EQ(prep.range.generation, 11);
	EQ(prep.track_count, 3);
	EQ(prep.owner_count, 3);
	EQ(prep.owners[0].gfn, 3);
	EQ(prep.owners[1].gfn, 4);
	EQ(prep.owners[2].gfn, 5);
	nyx_strict_pt_tracker_abort(&prep);
	nyx_strict_pt_tracker_cleanup(&tr);
}

static void test_transactional_add_abort(void)
{
	struct nyx_strict_pt_tracker tr = { 0 };
	struct nyx_strict_pt_prepare prep = { 0 };
	struct nyx_strict_pt_prepare keep = { 0 };
	struct nyx_strict_pt_range_add_txn add = { 0 };
	__u64 dup[] = { 5, 3, 5, 4, 3 };
	__u64 only[] = { 9 };

	ERR(nyx_strict_pt_tracker_begin_session(&tr, 1), 0);
	set_add(&add, 1, 0x4000, 0x7000, 11, 48);
	ERR(nyx_strict_pt_tracker_prepare_add(&tr, &add, dup, 5, &prep), 0);
	nyx_strict_pt_tracker_commit(&tr, &prep);
	EQ(tr.next_range_id, 2);
	EQ(tr.ranges[0].range_id, 1);
	EQ(tr.ranges[0].generation, 11);
	EQ(tr.owner_count, 3);
	set_add(&add, 1, 0xc000, 0xd000, 33, 48);
	ERR(nyx_strict_pt_tracker_prepare_add(&tr, &add, only, 1, &keep), 0);
	EQ(tr.active_range_count, 1);
	nyx_strict_pt_tracker_abort(&keep);
	EQ(tr.active_range_count, 1);
	EQ(tr.next_range_id, 2);
	nyx_strict_pt_tracker_cleanup(&tr);
}

static void test_overlapping_owner_merge_removal(void)
{
	struct nyx_strict_pt_tracker tr = { 0 };
	struct nyx_strict_pt_prepare prep = { 0 };
	struct nyx_strict_pt_range_add_txn add = { 0 };
	struct nyx_strict_pt_range_remove_txn rem = { 0 };
	__u64 dup[] = { 5, 3, 5, 4, 3 };
	__u64 overlap[] = { 6, 4, 5 };

	ERR(nyx_strict_pt_tracker_begin_session(&tr, 1), 0);
	set_add(&add, 1, 0x4000, 0x7000, 11, 48);
	ERR(nyx_strict_pt_tracker_prepare_add(&tr, &add, dup, 5, &prep), 0);
	nyx_strict_pt_tracker_commit(&tr, &prep);
	set_add(&add, 1, 0x8000, 0xb000, 22, 48);
	ERR(nyx_strict_pt_tracker_prepare_add(&tr, &add, overlap, 3, &prep), 0);
	EQ(prep.range.range_id, 2);
	EQ(prep.track_count, 1);
	EQ(prep.track_gfns[0], 6);
	EQ(prep.owners[1].range_mask, 3);
	EQ(prep.owners[2].range_mask, 3);
	nyx_strict_pt_tracker_commit(&tr, &prep);
	rem.session_id = 1;
	rem.range_id = 99;
	ERR(nyx_strict_pt_tracker_prepare_remove(&tr, &rem, &prep), -ENOENT);
	rem.session_id = 7;
	rem.range_id = 1;
	ERR(nyx_strict_pt_tracker_prepare_remove(&tr, &rem, &prep), -ESTALE);
	rem.session_id = 1;
	rem.range_id = 1;
	ERR(nyx_strict_pt_tracker_prepare_remove(&tr, &rem, &prep), 0);
	EQ(prep.owner_count, 3);
	EQ(prep.untrack_count, 1);
	EQ(prep.untrack_gfns[0], 3);
	nyx_strict_pt_tracker_commit(&tr, &prep);
	EQ(tr.active_range_count, 1);
	EQ(tr.owner_count, 3);
	EQ(tr.owners[0].gfn, 4);
	EQ(tr.owners[2].gfn, 6);
	rem.range_id = 2;
	ERR(nyx_strict_pt_tracker_prepare_remove(&tr, &rem, &prep), 0);
	EQ(prep.untrack_count, 3);
	EQ(prep.untrack_gfns[0], 4);
	EQ(prep.untrack_gfns[1], 5);
	EQ(prep.untrack_gfns[2], 6);
	nyx_strict_pt_tracker_commit(&tr, &prep);
	nyx_strict_pt_tracker_cleanup(&tr);
}

static void test_clear_session(void)
{
	struct nyx_strict_pt_tracker tr = { 0 };
	struct nyx_strict_pt_prepare prep = { 0 };
	struct nyx_strict_pt_range_add_txn add = { 0 };
	__u64 shared_a[] = { 10, 11 };
	__u64 shared_b[] = { 12, 11 };

	ERR(nyx_strict_pt_tracker_begin_session(&tr, 2), 0);
	set_add(&add, 2, 0x10000, 0x12000, 44, 48);
	ERR(nyx_strict_pt_tracker_prepare_add(&tr, &add, shared_a, 2, &prep), 0);
	nyx_strict_pt_tracker_commit(&tr, &prep);
	set_add(&add, 2, 0x14000, 0x16000, 55, 48);
	ERR(nyx_strict_pt_tracker_prepare_add(&tr, &add, shared_b, 2, &prep), 0);
	nyx_strict_pt_tracker_commit(&tr, &prep);
	ERR(nyx_strict_pt_tracker_prepare_clear_session(&tr, 9, &prep), -ESTALE);
	ERR(nyx_strict_pt_tracker_prepare_clear_session(&tr, 2, &prep), 0);
	EQ(prep.untrack_count, 3);
	EQ(prep.untrack_gfns[0], 10);
	EQ(prep.untrack_gfns[1], 11);
	EQ(prep.untrack_gfns[2], 12);
	nyx_strict_pt_tracker_commit(&tr, &prep);
	EQ(tr.session_id, 0);
	EQ(tr.active_range_count, 0);
	EQ(tr.owner_count, 0);
	nyx_strict_pt_tracker_cleanup(&tr);
}

static void test_write_classification_cross_page_overflow(void)
{
	struct nyx_strict_pt_tracker tr = { 0 };
	struct nyx_strict_pt_prepare prep = { 0 };
	struct nyx_strict_pt_range_add_txn add = { 0 };
	struct nyx_strict_pt_write_result wr;
	__u64 pair[] = { 100, 101 };

	ERR(nyx_strict_pt_tracker_begin_session(&tr, 3), 0);
	set_add(&add, 3, 0x20000, 0x22000, 66, 48);
	ERR(nyx_strict_pt_tracker_prepare_add(&tr, &add, pair, 2, &prep), 0);
	nyx_strict_pt_tracker_commit(&tr, &prep);
	wr = nyx_strict_pt_tracker_classify_write(&tr, (100ULL << 12) + 32, 16);
	EQ(wr.session_id, 3);
	EQ(wr.range_mask, 1);
	wr = nyx_strict_pt_tracker_classify_write(&tr, (100ULL << 12) + 4090, 32);
	EQ(wr.session_id, 3);
	EQ(wr.range_mask, 1);
	EQ(tr.ranges[0].pt_dirty, 1);
	wr = nyx_strict_pt_tracker_classify_write(&tr, ~0ULL - 2, 8);
	EQ(wr.session_id, 0);
	EQ(wr.range_mask, 0);
	wr = nyx_strict_pt_tracker_classify_write(&tr, (3ULL << 12), 1);
	EQ(wr.session_id, 0);
	EQ(wr.range_mask, 0);
	nyx_strict_pt_tracker_cleanup(&tr);
}

int main(void)
{
	test_validation_and_canonicality();
	test_transactional_add_abort();
	test_overlapping_owner_merge_removal();
	test_clear_session();
	test_write_classification_cross_page_overflow();
	printf("nyx_strict_pt_tracking_test: ok\n");
	return 0;
}
