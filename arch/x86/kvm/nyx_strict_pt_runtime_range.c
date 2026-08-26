// SPDX-License-Identifier: GPL-2.0

#include <linux/slab.h>

#include "mmu.h"
#include "mmu/tdp_mmu.h"
#include "nyx_strict_pt_runtime_range_internal.h"

static bool nyx_strict_pt_runtime_add_stale(
	const struct nyx_strict_pt_runtime_tracker *runtime,
	const struct nyx_strict_pt_range_add_txn *add,
	const struct nyx_strict_pt_prepare *prepare,
	const struct nyx_strict_pt_owner *table_owners_snapshot,
	const struct nyx_strict_pt_owner *data_owners_snapshot)
{
	return runtime->invalidated ||
	       runtime->tracker.session_id != add->session_id ||
	       runtime->tracker.owners != table_owners_snapshot ||
	       runtime->data_tracker.owners != data_owners_snapshot ||
	       runtime->tracker.ranges[prepare->slot].active ||
	       runtime->tracker.ranges[prepare->slot].range_id ||
	       runtime->data_tracker.slots[prepare->slot].active ||
	       runtime->data_tracker.slots[prepare->slot].range_id ||
	       runtime->control->policy.state != KVM_NYX_STRICT_PT_ENABLED ||
	       runtime->control->policy.session_id != add->session_id;
}

int nyx_strict_pt_runtime_handle_range_add(
	struct kvm *kvm, struct kvm_nyx_strict_pt_control *control)
{
	struct nyx_strict_pt_runtime_tracker *runtime = kvm->arch.nyx_strict_pt_runtime;
	struct kvm_nyx_pt_walk_result walk;
	struct nyx_strict_pt_prepare prepare = { 0 };
	struct nyx_strict_pt_data_prepare data_prepare = { 0 };
	struct nyx_strict_pt_range_add_txn add = {
		.session_id = control->u.range_add.session_id,
		.gva_start = control->u.range_add.gva_start,
		.gva_end = control->u.range_add.gva_end,
		.generation = runtime->control->next_generation,
	};
	struct kvm_memory_slot *slot;
	struct nyx_strict_pt_owner *table_owners_snapshot;
	struct nyx_strict_pt_owner *data_owners_snapshot;
	struct kvm_vcpu *vcpu;
	__u64 *walk_gfns = NULL;
	__u64 *data_gfns = NULL;
	__u64 epoch;
	__u64 range_id;
	__u64 gva;
	__u32 page_count;
	__u32 max_walk_gfns;
	__u32 page_index = 0;
	__u32 walk_count = 0;
	__u32 added_count = 0;
	int srcu_idx;
	int ret;
	bool flush = false;
	bool invalidated = false;

	if (!add.generation || add.generation == ~0ULL ||
	    runtime->control->counters.ranges_added == ~0ULL)
		return -EOVERFLOW;
	ret = nyx_strict_pt_runtime_get_vcpu0(kvm, &vcpu, &add.va_bits);
	if (ret)
		return ret;
	ret = nyx_strict_pt_runtime_count_walk_gfns(&add, &page_count,
						     &max_walk_gfns);
	if (ret)
		return ret;
	ret = nyx_strict_pt_runtime_begin_epoch(runtime, &epoch);
	if (ret)
		return nyx_strict_pt_runtime_fail_closed(runtime, ret);
	walk_gfns = kvcalloc(max_walk_gfns, sizeof(*walk_gfns), GFP_KERNEL_ACCOUNT);
	if (!walk_gfns) {
		ret = -ENOMEM;
		goto out_end_epoch;
	}
	data_gfns = kvcalloc(page_count, sizeof(*data_gfns), GFP_KERNEL_ACCOUNT);
	if (!data_gfns) {
		ret = -ENOMEM;
		goto out_free_walk;
	}
	for (gva = add.gva_start; gva < add.gva_end; gva += NYX_STRICT_PT_PAGE_SIZE) {
		ret = kvm_mmu_nyx_strict_pt_walk(vcpu,
						 runtime->control->policy.target_cr3,
						 gva, &walk);
		if (ret || walk_count > max_walk_gfns - walk.table_count) {
			ret = ret ?: -EOVERFLOW;
			goto out_free_data;
		}
		memcpy(&walk_gfns[walk_count], walk.table_gfns,
		       walk.table_count * sizeof(*walk_gfns));
		walk_count += walk.table_count;
		data_gfns[page_index++] = walk.data_gfn;
	}
	ret = nyx_strict_pt_tracker_prepare_add(&runtime->tracker, &add,
						 walk_gfns, walk_count, &prepare);
	if (ret)
		goto out_free_data;
	range_id = prepare.range.range_id;
	table_owners_snapshot = runtime->tracker.owners;
	data_owners_snapshot = runtime->data_tracker.owners;
	ret = nyx_strict_pt_data_tracker_prepare(&runtime->data_tracker,
						 prepare.slot, range_id, data_gfns,
						 page_count, &data_prepare);
	if (ret)
		goto out_abort_add;
	for (; added_count < prepare.track_count; added_count++) {
		ret = kvm_write_track_add_gfn(kvm, (gfn_t)prepare.track_gfns[added_count]);
		if (ret)
			goto out_abort_add;
	}
	srcu_idx = srcu_read_lock(&kvm->srcu);
	write_lock(&kvm->mmu_lock);
	for (page_index = 0; page_index < data_prepare.snapshot.gfn_count; page_index++) {
		bool track_flush = false;

		slot = gfn_to_memslot(kvm,
				    (gfn_t)data_prepare.snapshot.gfns[page_index]);
		if (!slot) {
			ret = -EINVAL;
			goto out_unlock_add;
		}
		ret = kvm_tdp_mmu_nyx_strict_set_nx_gfn(kvm, slot,
					       (gfn_t)data_prepare.snapshot.gfns[page_index],
					       &track_flush);
		if (ret)
			goto out_unlock_add;
		flush |= track_flush;
	}
	spin_lock(&runtime->lock);
	if (nyx_strict_pt_runtime_add_stale(runtime, &add, &prepare,
		    table_owners_snapshot, data_owners_snapshot)) {
		invalidated = runtime->invalidated;
		spin_unlock(&runtime->lock);
		ret = invalidated ? -EIO : -ESTALE;
		goto out_unlock_add;
	}
	nyx_strict_pt_runtime_invalidate_pending_data_locked(runtime,
						    &data_prepare,
						    prepare.range.range_id);
	nyx_strict_pt_tracker_publish(&runtime->tracker, &prepare);
	nyx_strict_pt_data_tracker_publish(&runtime->data_tracker, &data_prepare);
	runtime->control->policy.active_ranges = runtime->tracker.active_range_count;
	runtime->control->counters.ranges_added++;
	control->u.range_add.range_id = range_id;
	runtime->control->next_generation = add.generation + 1;
	spin_unlock(&runtime->lock);
	nyx_strict_pt_runtime_release_mmu_locks(kvm, srcu_idx, flush);
	nyx_strict_pt_tracker_abort(&prepare);
	nyx_strict_pt_data_tracker_abort(&data_prepare);
	ret = 0;

out_free_data:
	kvfree(data_gfns);
out_free_walk:
	kvfree(walk_gfns);
out_end_epoch:
	nyx_strict_pt_runtime_end_epoch(runtime, epoch);
	return ret;

out_unlock_add:
	nyx_strict_pt_runtime_release_mmu_locks(kvm, srcu_idx, flush);
out_abort_add:
	nyx_strict_pt_runtime_rollback_added_tracks(kvm, &prepare, added_count);
	nyx_strict_pt_tracker_abort(&prepare);
	nyx_strict_pt_data_tracker_abort(&data_prepare);
	if (ret == -EIO)
		ret = nyx_strict_pt_runtime_fail_closed_session(runtime, ret);
	goto out_free_data;
}
