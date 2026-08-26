// SPDX-License-Identifier: GPL-2.0

#include <linux/mm.h>

#include "nyx_strict_pt_runtime_internal.h"

bool nyx_strict_pt_runtime_counter_inc(__u64 *counter)
{
	if (WARN_ON_ONCE(!counter) || *counter == ~0ULL)
		return false;

	(*counter)++;
	return true;
}

void nyx_strict_pt_runtime_clear_pending_locked(
	struct nyx_strict_pt_runtime_tracker *runtime)
{
	lockdep_assert_held(&runtime->lock);
	nyx_strict_pt_exec_state_clear(&runtime->exec_state);
	runtime->control->policy.pending_exit = 0;
}

static bool nyx_strict_pt_runtime_prepare_contains_gfn(
	const struct nyx_strict_pt_data_prepare *prepare, __u64 gfn)
{
	__u32 i;

	if (!prepare)
		return false;

	for (i = 0; i < prepare->snapshot.gfn_count; i++)
		if (prepare->snapshot.gfns[i] == gfn)
			return true;

	return false;
}

void nyx_strict_pt_runtime_invalidate_pending_data_locked(
	struct nyx_strict_pt_runtime_tracker *runtime,
	const struct nyx_strict_pt_data_prepare *prepare, __u64 range_id)
{
	__u64 pending_gfn;

	lockdep_assert_held(&runtime->lock);
	if (!runtime->exec_state.pending)
		return;

	pending_gfn = runtime->exec_state.payload.gpa >> PAGE_SHIFT;
	if (runtime->exec_state.payload.range_id == range_id ||
	    nyx_strict_pt_runtime_prepare_contains_gfn(prepare, pending_gfn))
		nyx_strict_pt_runtime_clear_pending_locked(runtime);
}

void nyx_strict_pt_runtime_invalidate_pending_range_locked(
	struct nyx_strict_pt_runtime_tracker *runtime, __u64 range_id)
{
	lockdep_assert_held(&runtime->lock);
	if (runtime->exec_state.pending &&
	    runtime->exec_state.payload.range_id == range_id)
		nyx_strict_pt_runtime_clear_pending_locked(runtime);
}
