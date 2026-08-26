// SPDX-License-Identifier: GPL-2.0

#include <linux/slab.h>
#include <linux/string.h>

#include "nyx_strict_pt_runtime_internal.h"

static bool nyx_strict_pt_runtime_data_tracker_has_state(
	const struct nyx_strict_pt_data_tracker *tracker)
{
	__u32 i;

	if (!tracker)
		return false;
	if (tracker->owners || tracker->owner_count || tracker->active_range_count)
		return true;
	for (i = 0; i < NYX_STRICT_PT_MAX_RANGES; i++)
		if (tracker->slots[i].active || tracker->slots[i].range_id ||
		    tracker->slots[i].gfns || tracker->slots[i].gfn_count)
			return true;

	return false;
}

static int nyx_strict_pt_runtime_remove_owners(struct kvm *kvm,
	const struct nyx_strict_pt_owner *owners, __u32 count, bool ignore_missing)
{
	__u32 i;

	for (i = 0; i < count; i++) {
		int ret = kvm_write_track_remove_gfn(kvm, (gfn_t)owners[i].gfn);

		if (!ret)
			continue;
		if (ignore_missing && ret == -EINVAL)
			continue;
		return ret;
	}

	return 0;
}

static void nyx_strict_pt_runtime_detach_data(
	struct nyx_strict_pt_data_tracker *tracker,
	const __u64 **detached_gfns,
	struct nyx_strict_pt_owner **detached_owners)
{
	__u32 i;

	*detached_owners = tracker->owners;
	for (i = 0; i < NYX_STRICT_PT_MAX_RANGES; i++)
		detached_gfns[i] = tracker->slots[i].gfns;
	memset(tracker, 0, sizeof(*tracker));
}

static void nyx_strict_pt_runtime_free_detached_data(
	const __u64 **detached_gfns,
	struct nyx_strict_pt_owner *detached_owners)
{
	__u32 i;

	for (i = 0; i < NYX_STRICT_PT_MAX_RANGES; i++)
		kvfree(detached_gfns[i]);
	kvfree(detached_owners);
}

int nyx_strict_pt_runtime_begin_session(
	struct nyx_strict_pt_runtime_tracker *runtime, __u64 session_id)
{
	int ret;

	spin_lock(&runtime->lock);
	if (nyx_strict_pt_runtime_data_tracker_has_state(&runtime->data_tracker)) {
		spin_unlock(&runtime->lock);
		return nyx_strict_pt_runtime_fail_closed(runtime, -EIO);
	}
	ret = nyx_strict_pt_tracker_begin_session(&runtime->tracker, session_id);
	if (!ret) {
		runtime->pending_range_mask = 0;
		runtime->inflight_range_mask = 0;
		nyx_strict_pt_runtime_clear_pending_locked(runtime);
	}
	spin_unlock(&runtime->lock);

	return ret;
}

int nyx_strict_pt_runtime_clear_session(
	struct nyx_strict_pt_runtime_tracker *runtime, bool ignore_missing)
{
	const __u64 *detached_gfns[NYX_STRICT_PT_MAX_RANGES] = { NULL };
	struct nyx_strict_pt_owner *detached_data_owners = NULL;
	struct nyx_strict_pt_owner *owners;
	__u32 owner_count;
	__u64 session_id;
	int ret;

	spin_lock(&runtime->lock);
	session_id = runtime->tracker.session_id;
	owners = runtime->tracker.owners;
	owner_count = runtime->tracker.owner_count;
	if (!session_id) {
		if (!nyx_strict_pt_runtime_data_tracker_has_state(&runtime->data_tracker)) {
			spin_unlock(&runtime->lock);
			return 0;
		}
		nyx_strict_pt_runtime_detach_data(&runtime->data_tracker,
			detached_gfns, &detached_data_owners);
		runtime->pending_range_mask = 0;
		runtime->inflight_range_mask = 0;
		nyx_strict_pt_runtime_clear_pending_locked(runtime);
		runtime->control->policy.active_ranges = 0;
		spin_unlock(&runtime->lock);
		nyx_strict_pt_runtime_free_detached_data(detached_gfns,
			detached_data_owners);
		return nyx_strict_pt_runtime_fail_closed(runtime, -EIO);
	}
	spin_unlock(&runtime->lock);

	ret = nyx_strict_pt_runtime_remove_owners(runtime->kvm, owners,
		owner_count, ignore_missing);
	if (ret)
		return ret;

	spin_lock(&runtime->lock);
	if (runtime->tracker.session_id != session_id ||
	    runtime->tracker.owners != owners) {
		spin_unlock(&runtime->lock);
		return -ESTALE;
	}
	nyx_strict_pt_runtime_detach_data(&runtime->data_tracker,
		detached_gfns, &detached_data_owners);
	memset(&runtime->tracker, 0, sizeof(runtime->tracker));
	runtime->pending_range_mask = 0;
	runtime->inflight_range_mask = 0;
	nyx_strict_pt_runtime_clear_pending_locked(runtime);
	runtime->control->policy.active_ranges = 0;
	spin_unlock(&runtime->lock);

	kvfree(owners);
	nyx_strict_pt_runtime_free_detached_data(detached_gfns,
		detached_data_owners);
	return 0;
}

void nyx_strict_pt_runtime_destroy(struct kvm *kvm)
{
	struct nyx_strict_pt_runtime_tracker *runtime;
	const __u64 *detached_gfns[NYX_STRICT_PT_MAX_RANGES] = { NULL };
	struct nyx_strict_pt_owner *detached_data_owners = NULL;
	struct nyx_strict_pt_owner *detached_tracker_owners;

	runtime = kvm->arch.nyx_strict_pt_runtime;
	if (!runtime)
		return;

	kvm->arch.nyx_strict_pt_runtime = NULL;
	kvm_page_track_unregister_internal_notifier(kvm, &runtime->notifier);
	spin_lock(&runtime->lock);
	runtime->invalidated = true;
	detached_tracker_owners = runtime->tracker.owners;
	nyx_strict_pt_runtime_detach_data(&runtime->data_tracker,
		detached_gfns, &detached_data_owners);
	memset(&runtime->tracker, 0, sizeof(runtime->tracker));
	runtime->pending_range_mask = 0;
	runtime->inflight_range_mask = 0;
	nyx_strict_pt_runtime_clear_pending_locked(runtime);
	spin_unlock(&runtime->lock);

	nyx_strict_pt_runtime_publish_disabled(runtime->control);
	kvfree(detached_tracker_owners);
	nyx_strict_pt_runtime_free_detached_data(detached_gfns,
		detached_data_owners);
	kfree(runtime);
}
