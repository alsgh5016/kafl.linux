// SPDX-License-Identifier: GPL-2.0

#include <linux/slab.h>

#include "mmu.h"
#include "mmu/page_track.h"
#include "mmu/tdp_mmu.h"
#include "nyx_strict_pt_runtime_rewalk_internal.h"

static int nyx_strict_pt_runtime_snapshot_rewalk(
	struct nyx_strict_pt_runtime_tracker *runtime, __u32 slot,
	struct nyx_strict_pt_rewalk_snapshot *snapshot)
{
	struct nyx_strict_pt_range_state *range;
	struct nyx_strict_pt_data_slot *data_slot;

	spin_lock(&runtime->lock);
	if (runtime->invalidated || !runtime->tracker.session_id ||
	    runtime->control->policy.state != KVM_NYX_STRICT_PT_ENABLED ||
	    !smp_load_acquire(&runtime->control->runtime_root.enabled)) {
		spin_unlock(&runtime->lock);
		return -EIO;
	}
	range = &runtime->tracker.ranges[slot];
	data_slot = &runtime->data_tracker.slots[slot];
	if (!range->active || !range->range_id || !data_slot->active ||
	    data_slot->range_id != range->range_id) {
		spin_unlock(&runtime->lock);
		return -ESTALE;
	}
	snapshot->table_owners = runtime->tracker.owners;
	snapshot->data_owners = runtime->data_tracker.owners;
	snapshot->data_gfns = data_slot->gfns;
	snapshot->session_id = runtime->tracker.session_id;
	snapshot->range_id = range->range_id;
	snapshot->gva_start = range->gva_start;
	snapshot->gva_end = range->gva_end;
	snapshot->generation = range->generation;
	snapshot->assigned_generation = runtime->control->next_generation;
	snapshot->target_cr3 = runtime->control->policy.target_cr3;
	snapshot->slot = slot;
	snapshot->bit = 1ULL << slot;
	snapshot->data_active = data_slot->active;
	spin_unlock(&runtime->lock);
	if (!snapshot->assigned_generation || snapshot->assigned_generation == ~0ULL)
		return -EOVERFLOW;
	if (snapshot->assigned_generation <= snapshot->generation)
		return -EINVAL;
	return 0;
}

static int nyx_strict_pt_runtime_rollback_rewalk_tracks(
	struct kvm *kvm, const struct nyx_strict_pt_prepare *prepare,
	__u32 added_count, __u32 removed_count)
{
	__u32 i;
	int first = 0;
	int ret;

	for (i = 0; i < removed_count; i++) {
		ret = kvm_write_track_add_gfn(kvm,
				(gfn_t)prepare->untrack_gfns[i]);
		if (!first && ret)
			first = ret;
	}
	while (added_count-- > 0) {
		ret = kvm_write_track_remove_gfn(kvm,
				(gfn_t)prepare->track_gfns[added_count]);
		if (!first && ret)
			first = ret;
	}
	return first;
}

static int nyx_strict_pt_runtime_finalize_rewalk(
	struct nyx_strict_pt_runtime_tracker *runtime,
	const struct nyx_strict_pt_rewalk_snapshot *snapshot,
	struct nyx_strict_pt_prepare *table_prepare,
	struct nyx_strict_pt_data_prepare *data_prepare)
{
	struct nyx_strict_pt_range_state *range;
	struct nyx_strict_pt_data_slot *data_slot;

	spin_lock(&runtime->lock);
	range = &runtime->tracker.ranges[snapshot->slot];
	data_slot = &runtime->data_tracker.slots[snapshot->slot];
	if (runtime->invalidated || runtime->tracker.session_id != snapshot->session_id ||
	    runtime->control->policy.state != KVM_NYX_STRICT_PT_ENABLED ||
	    runtime->control->policy.session_id != snapshot->session_id ||
	    !smp_load_acquire(&runtime->control->runtime_root.enabled) ||
	    runtime->control->next_generation != snapshot->assigned_generation ||
	    runtime->tracker.owners != snapshot->table_owners ||
	    runtime->data_tracker.owners != snapshot->data_owners ||
	    !range->active || range->range_id != snapshot->range_id ||
	    range->generation != snapshot->generation ||
	    range->gva_start != snapshot->gva_start ||
	    range->gva_end != snapshot->gva_end ||
	    data_slot->active != snapshot->data_active ||
	    data_slot->range_id != snapshot->range_id ||
	    data_slot->gfns != snapshot->data_gfns) {
		spin_unlock(&runtime->lock);
		return -ESTALE;
	}
	table_prepare->range.pt_dirty =
		(runtime->pending_range_mask & snapshot->bit) ? 1 : 0;
	nyx_strict_pt_runtime_invalidate_pending_data_locked(runtime, data_prepare,
						     snapshot->range_id);
	nyx_strict_pt_tracker_publish(&runtime->tracker, table_prepare);
	nyx_strict_pt_data_tracker_publish(&runtime->data_tracker, data_prepare);
	runtime->control->policy.active_ranges = runtime->tracker.active_range_count;
	runtime->control->next_generation = snapshot->assigned_generation + 1;
	runtime->inflight_range_mask &= ~snapshot->bit;
	spin_unlock(&runtime->lock);
	return 0;
}

int nyx_strict_pt_runtime_process_rewalk_slot(
	struct kvm_vcpu *vcpu, struct nyx_strict_pt_runtime_tracker *runtime,
	__u32 slot, __u8 va_bits)
{
	struct kvm_nyx_pt_walk_result walk;
	struct nyx_strict_pt_rewalk_snapshot snapshot = { 0 };
	struct nyx_strict_pt_prepare table_prepare = { 0 };
	struct nyx_strict_pt_data_prepare data_prepare = { 0 };
	struct nyx_strict_pt_range_add_txn add = { 0 };
	struct kvm_memory_slot *memslot;
	__u64 *walk_gfns = NULL;
	__u64 *data_gfns = NULL;
	__u64 gva;
	__u32 added_count = 0;
	__u32 removed_count = 0;
	__u32 page_count;
	__u32 max_walk_gfns;
	__u32 page_index;
	__u32 walk_count = 0;
	int srcu_idx = -1;
	int ret;
	bool flush = false;

	ret = nyx_strict_pt_runtime_snapshot_rewalk(runtime, slot, &snapshot);
	if (ret)
		goto out;
	add.session_id = snapshot.session_id;
	add.gva_start = snapshot.gva_start;
	add.gva_end = snapshot.gva_end;
	add.generation = snapshot.assigned_generation;
	add.va_bits = va_bits;
	ret = nyx_strict_pt_runtime_count_walk_gfns(&add, &page_count,
						     &max_walk_gfns);
	if (ret)
		goto out;
	walk_gfns = kvcalloc(max_walk_gfns, sizeof(*walk_gfns), GFP_KERNEL_ACCOUNT);
	data_gfns = kvcalloc(page_count, sizeof(*data_gfns), GFP_KERNEL_ACCOUNT);
	if (!walk_gfns || !data_gfns) {
		ret = -ENOMEM;
		goto out;
	}
	for (page_index = 0, gva = add.gva_start; gva < add.gva_end;
	     page_index++, gva += NYX_STRICT_PT_PAGE_SIZE) {
		ret = kvm_mmu_nyx_strict_pt_walk(vcpu, snapshot.target_cr3, gva, &walk);
		if (ret || walk_count > max_walk_gfns - walk.table_count) {
			ret = ret ?: -EOVERFLOW;
			goto out;
		}
		memcpy(&walk_gfns[walk_count], walk.table_gfns,
		       walk.table_count * sizeof(*walk_gfns));
		walk_count += walk.table_count;
		data_gfns[page_index] = walk.data_gfn;
	}
	ret = nyx_strict_pt_tracker_prepare_rewalk(&runtime->tracker,
			snapshot.session_id, snapshot.range_id,
			snapshot.assigned_generation, walk_gfns, walk_count,
			&table_prepare);
	if (ret)
		goto out;
	ret = nyx_strict_pt_data_tracker_prepare(&runtime->data_tracker, slot,
			snapshot.range_id, data_gfns, page_count, &data_prepare);
	if (ret)
		goto out;
	for (; added_count < table_prepare.track_count; added_count++) {
		ret = kvm_write_track_add_gfn(vcpu->kvm,
				(gfn_t)table_prepare.track_gfns[added_count]);
		if (ret)
			goto out_rollback;
	}
	for (; removed_count < table_prepare.untrack_count; removed_count++) {
		ret = kvm_write_track_remove_gfn(vcpu->kvm,
				(gfn_t)table_prepare.untrack_gfns[removed_count]);
		if (ret)
			goto out_rollback;
	}
	srcu_idx = srcu_read_lock(&vcpu->kvm->srcu);
	write_lock(&vcpu->kvm->mmu_lock);
	for (page_index = 0; page_index < data_prepare.snapshot.gfn_count; page_index++) {
		bool track_flush = false;

		memslot = gfn_to_memslot(vcpu->kvm,
				(gfn_t)data_prepare.snapshot.gfns[page_index]);
		if (!memslot) {
			ret = -EINVAL;
			goto out_unlock;
		}
		ret = kvm_tdp_mmu_nyx_strict_set_nx_gfn(vcpu->kvm, memslot,
				(gfn_t)data_prepare.snapshot.gfns[page_index],
				&track_flush);
		if (ret)
			goto out_unlock;
		flush |= track_flush;
	}
	ret = nyx_strict_pt_runtime_finalize_rewalk(runtime, &snapshot,
						    &table_prepare,
						    &data_prepare);
	if (ret)
		goto out_unlock;
	if (flush)
		kvm_flush_remote_tlbs(vcpu->kvm);
	write_unlock(&vcpu->kvm->mmu_lock);
	srcu_read_unlock(&vcpu->kvm->srcu, srcu_idx);
	ret = 0;
	goto out;

out_unlock:
	nyx_strict_pt_runtime_release_mmu_locks(vcpu->kvm, srcu_idx, flush);
out_rollback:
	(void)nyx_strict_pt_runtime_rollback_rewalk_tracks(vcpu->kvm,
						  &table_prepare,
						  added_count,
						  removed_count);
out:
	nyx_strict_pt_tracker_abort(&table_prepare);
	nyx_strict_pt_data_tracker_abort(&data_prepare);
	kvfree(data_gfns);
	kvfree(walk_gfns);
	return ret;
}
