/* SPDX-License-Identifier: GPL-2.0 */
#ifndef ARCH_X86_KVM_NYX_STRICT_PT_TRACKING_H
#define ARCH_X86_KVM_NYX_STRICT_PT_TRACKING_H

#ifndef __KERNEL__
#include <stdbool.h>
#include <stdint.h>

typedef uint8_t __u8;
typedef uint32_t __u32;
typedef uint64_t __u64;
typedef int32_t __s32;
#else
#include <linux/types.h>
#endif

#ifndef NYX_STRICT_PT_MAX_RANGES
#define NYX_STRICT_PT_MAX_RANGES 64U
#endif

#ifndef NYX_STRICT_PT_PAGE_SHIFT
#define NYX_STRICT_PT_PAGE_SHIFT 12U
#endif

#ifndef NYX_STRICT_PT_PAGE_SIZE
#define NYX_STRICT_PT_PAGE_SIZE (1ULL << NYX_STRICT_PT_PAGE_SHIFT)
#endif

struct nyx_strict_pt_owner {
	__u64 gfn;
	__u64 range_mask;
	__u8  exec_ack;
	__u8  reserved[7];
};

struct nyx_strict_pt_range_state {
	__u64 range_id;
	__u64 generation;
	__u64 gva_start;
	__u64 gva_end;
	__u32 active;
	__u32 pt_dirty;
};

struct nyx_strict_pt_tracker {
	__u64 session_id;
	__u64 next_range_id;
	struct nyx_strict_pt_owner *owners;
	__u32 owner_count;
	__u32 active_range_count;
	struct nyx_strict_pt_range_state ranges[NYX_STRICT_PT_MAX_RANGES];
};

struct nyx_strict_pt_range_add_txn {
	__u64 session_id;
	__u64 gva_start;
	__u64 gva_end;
	__u64 generation;
	__u8 va_bits;
	__u8 reserved[7];
};

struct nyx_strict_pt_range_remove_txn {
	__u64 session_id;
	__u64 range_id;
};

enum nyx_strict_pt_prepare_kind {
	NYX_STRICT_PT_PREPARE_NONE = 0,
	NYX_STRICT_PT_PREPARE_ADD,
	NYX_STRICT_PT_PREPARE_REWALK,
	NYX_STRICT_PT_PREPARE_REMOVE,
	NYX_STRICT_PT_PREPARE_CLEAR_SESSION,
};

struct nyx_strict_pt_prepare {
	__u32 kind;
	__u32 slot;
	__u64 next_range_id;
	struct nyx_strict_pt_range_state range;
	struct nyx_strict_pt_owner *owners;
	struct nyx_strict_pt_owner *retired_owners;
	__u32 owner_count;
	__u32 active_range_count;
	__u64 *track_gfns;
	__u32 track_count;
	__u64 *untrack_gfns;
	__u32 untrack_count;
};

struct nyx_strict_pt_data_slot {
	const __u64 *gfns;
	__u32 gfn_count;
	__u32 active;
	__u64 range_id;
};

struct nyx_strict_pt_data_tracker {
	struct nyx_strict_pt_data_slot slots[NYX_STRICT_PT_MAX_RANGES];
	struct nyx_strict_pt_owner *owners;
	__u32 owner_count;
	__u32 active_range_count;
};

struct nyx_strict_pt_data_prepare {
	__u32 slot;
	__u32 active_range_count;
	struct nyx_strict_pt_data_slot snapshot;
	struct nyx_strict_pt_owner *owners;
	struct nyx_strict_pt_owner *retired_owners;
	const __u64 *retired_gfns;
	__u32 owner_count;
	__u64 *track_gfns;
	__u32 track_count;
	__u64 *untrack_gfns;
	__u32 untrack_count;
};

/* Zero-initialize prepare objects before first use. */
/* Callers serialize prepare/commit with tracker mutation. */

struct nyx_strict_pt_write_result {
	__u64 session_id;
	__u64 range_mask;
};

int nyx_strict_pt_validate_range_add_txn(
	const struct nyx_strict_pt_range_add_txn *add);

int nyx_strict_pt_tracker_begin_session(struct nyx_strict_pt_tracker *tracker,
	__u64 session_id);
int nyx_strict_pt_tracker_prepare_add(const struct nyx_strict_pt_tracker *tracker,
	const struct nyx_strict_pt_range_add_txn *add, const __u64 *gfns,
	__u64 gfn_count, struct nyx_strict_pt_prepare *prepare);
int nyx_strict_pt_tracker_prepare_rewalk(
	const struct nyx_strict_pt_tracker *tracker, __u64 session_id,
	__u64 range_id, __u64 generation, const __u64 *table_gfns,
	__u64 table_gfn_count, struct nyx_strict_pt_prepare *prepare);
int nyx_strict_pt_tracker_prepare_remove(
	const struct nyx_strict_pt_tracker *tracker,
	const struct nyx_strict_pt_range_remove_txn *remove,
	struct nyx_strict_pt_prepare *prepare);
int nyx_strict_pt_tracker_prepare_clear_session(
	const struct nyx_strict_pt_tracker *tracker, __u64 session_id,
	struct nyx_strict_pt_prepare *prepare);
int nyx_strict_pt_tracker_reserve_generation(
	const struct nyx_strict_pt_tracker *tracker, __u64 range_id,
	__u64 *generation);
void nyx_strict_pt_tracker_publish(struct nyx_strict_pt_tracker *tracker,
	struct nyx_strict_pt_prepare *prepare);
void nyx_strict_pt_tracker_commit(struct nyx_strict_pt_tracker *tracker,
	struct nyx_strict_pt_prepare *prepare);
void nyx_strict_pt_tracker_abort(struct nyx_strict_pt_prepare *prepare);
void nyx_strict_pt_tracker_cleanup(struct nyx_strict_pt_tracker *tracker);
struct nyx_strict_pt_write_result nyx_strict_pt_tracker_classify_write(
	struct nyx_strict_pt_tracker *tracker, __u64 gpa_start, __u64 byte_count);
bool nyx_strict_pt_owner_overlaps_range(
	const struct nyx_strict_pt_tracker *tracker, __u64 gfn_start,
	__u64 gfn_count);
int nyx_strict_pt_data_tracker_prepare(
	const struct nyx_strict_pt_data_tracker *tracker, __u32 slot,
	__u64 range_id, const __u64 *data_gfns, __u32 data_gfn_count,
	struct nyx_strict_pt_data_prepare *prepare);
void nyx_strict_pt_data_tracker_publish(
	struct nyx_strict_pt_data_tracker *tracker,
	struct nyx_strict_pt_data_prepare *prepare);
void nyx_strict_pt_data_tracker_commit(
	struct nyx_strict_pt_data_tracker *tracker,
	struct nyx_strict_pt_data_prepare *prepare);
void nyx_strict_pt_data_tracker_abort(
	struct nyx_strict_pt_data_prepare *prepare);
void nyx_strict_pt_data_tracker_cleanup(
	struct nyx_strict_pt_data_tracker *tracker);
bool nyx_strict_pt_data_tracker_owned(
	const struct nyx_strict_pt_data_tracker *tracker, __u64 gfn);
int nyx_strict_pt_data_tracker_needs_nx(
	const struct nyx_strict_pt_data_tracker *tracker, __u64 gfn,
	bool *needs_nx);
int nyx_strict_pt_data_tracker_ack_exec(
	struct nyx_strict_pt_data_tracker *tracker, __u64 gfn);

struct nyx_strict_pt_exec_identity {
	__u64 range_id;
	__u64 generation;
	__u32 page_index;
};

int nyx_strict_pt_tracker_resolve_exec(
	const struct nyx_strict_pt_tracker *tracker,
	const struct nyx_strict_pt_data_tracker *data_tracker,
	__u64 gva, __u64 gfn,
	struct nyx_strict_pt_exec_identity *identity);

#ifndef __KERNEL__
void nyx_strict_pt_test_fail_next_allocations(__u32 count);
#endif

#endif
