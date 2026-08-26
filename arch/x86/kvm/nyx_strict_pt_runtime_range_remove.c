// SPDX-License-Identifier: GPL-2.0

#include "nyx_strict_pt_runtime_range_internal.h"

static bool nyx_strict_pt_runtime_range_remove_snapshots_match(
	const struct nyx_strict_pt_runtime_tracker *runtime,
	const struct nyx_strict_pt_prepare *prepare,
	const struct nyx_strict_pt_data_prepare *data_prepare,
	const struct nyx_strict_pt_owner *table_owners_snapshot,
	const struct nyx_strict_pt_owner *data_owners_snapshot, __u64 range_id)
{
	return runtime->tracker.owners == table_owners_snapshot &&
	       runtime->data_tracker.owners == data_owners_snapshot &&
	       runtime->tracker.ranges[prepare->slot].active &&
	       runtime->tracker.ranges[prepare->slot].range_id == range_id &&
	       runtime->data_tracker.slots[data_prepare->slot].active &&
	       runtime->data_tracker.slots[data_prepare->slot].range_id == range_id;
}

int nyx_strict_pt_runtime_handle_range_remove(
	struct kvm *kvm, struct kvm_nyx_strict_pt_control *control)
{
	struct nyx_strict_pt_runtime_tracker *runtime = kvm->arch.nyx_strict_pt_runtime;
	struct nyx_strict_pt_prepare prepare = { 0 };
	struct nyx_strict_pt_data_prepare data_prepare = { 0 };
	struct nyx_strict_pt_range_remove_txn remove = {
		.session_id = control->u.range_remove.session_id,
		.range_id = control->u.range_remove.range_id,
	};
	struct nyx_strict_pt_owner *table_owners_snapshot;
	struct nyx_strict_pt_owner *data_owners_snapshot;
	bool publish_removal = false;
	__u64 epoch;
	__u32 i;
	int ret;

	if (runtime->control->counters.ranges_removed == ~0ULL)
		return -EOVERFLOW;
	ret = nyx_strict_pt_runtime_begin_epoch(runtime, &epoch);
	if (ret)
		return nyx_strict_pt_runtime_fail_closed(runtime, ret);
	ret = nyx_strict_pt_tracker_prepare_remove(&runtime->tracker, &remove,
					    &prepare);
	if (ret)
		goto out_end_epoch;
	ret = nyx_strict_pt_data_tracker_prepare(&runtime->data_tracker,
					 prepare.slot, remove.range_id,
					 NULL, 0, &data_prepare);
	if (ret)
		goto out_abort;
	table_owners_snapshot = runtime->tracker.owners;
	data_owners_snapshot = runtime->data_tracker.owners;
	for (i = 0; i < prepare.untrack_count; i++) {
		ret = kvm_write_track_remove_gfn(kvm, (gfn_t)prepare.untrack_gfns[i]);
		if (ret == -EINVAL)
			continue;
		if (ret)
			goto out_fail_closed;
	}
	spin_lock(&runtime->lock);
	publish_removal = nyx_strict_pt_runtime_range_remove_snapshots_match(runtime,
							       &prepare,
							       &data_prepare,
							       table_owners_snapshot,
							       data_owners_snapshot,
							       remove.range_id);
	if (runtime->invalidated || runtime->tracker.session_id != remove.session_id ||
	    runtime->control->policy.state != KVM_NYX_STRICT_PT_ENABLED ||
	    runtime->control->policy.session_id != remove.session_id) {
		if (runtime->invalidated && publish_removal) {
			nyx_strict_pt_tracker_publish(&runtime->tracker, &prepare);
			nyx_strict_pt_data_tracker_publish(&runtime->data_tracker,
						     &data_prepare);
			runtime->control->policy.active_ranges =
				runtime->tracker.active_range_count;
		}
		spin_unlock(&runtime->lock);
		ret = -EIO;
		goto out_fail_closed;
	}
	if (!publish_removal) {
		spin_unlock(&runtime->lock);
		ret = -EIO;
		goto out_fail_closed;
	}
	nyx_strict_pt_runtime_invalidate_pending_range_locked(runtime,
						 remove.range_id);
	nyx_strict_pt_tracker_publish(&runtime->tracker, &prepare);
	nyx_strict_pt_data_tracker_publish(&runtime->data_tracker, &data_prepare);
	runtime->control->policy.active_ranges = runtime->tracker.active_range_count;
	runtime->control->counters.ranges_removed++;
	spin_unlock(&runtime->lock);
	nyx_strict_pt_tracker_abort(&prepare);
	nyx_strict_pt_data_tracker_abort(&data_prepare);
	nyx_strict_pt_runtime_end_epoch(runtime, epoch);
	return 0;

out_fail_closed:
	nyx_strict_pt_tracker_abort(&prepare);
	nyx_strict_pt_data_tracker_abort(&data_prepare);
	if (ret == -EIO)
		ret = nyx_strict_pt_runtime_fail_closed_session(runtime, ret);
out_end_epoch:
	nyx_strict_pt_runtime_end_epoch(runtime, epoch);
	return ret;

out_abort:
	nyx_strict_pt_tracker_abort(&prepare);
	nyx_strict_pt_data_tracker_abort(&data_prepare);
	goto out_end_epoch;
}
