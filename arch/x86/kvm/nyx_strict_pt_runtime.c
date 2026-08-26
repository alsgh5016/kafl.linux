// SPDX-License-Identifier: GPL-2.0

#include <linux/slab.h>

#include "nyx_strict_pt_runtime_internal.h"

void nyx_strict_pt_runtime_operation_lock(struct kvm *kvm)
{
	struct nyx_strict_pt_runtime_tracker *runtime = kvm->arch.nyx_strict_pt_runtime;

	if (WARN_ON_ONCE(!runtime))
		return;

	mutex_lock(&runtime->operation_mutex);
}

void nyx_strict_pt_runtime_operation_unlock(struct kvm *kvm)
{
	struct nyx_strict_pt_runtime_tracker *runtime = kvm->arch.nyx_strict_pt_runtime;

	if (WARN_ON_ONCE(!runtime))
		return;

	lockdep_assert_held(&runtime->operation_mutex);
	mutex_unlock(&runtime->operation_mutex);
}

void nyx_strict_pt_runtime_publish_enabled(
	struct nyx_strict_pt_control_context *control)
{
	WRITE_ONCE(control->runtime_root.target_cr3, control->policy.target_cr3);
	smp_store_release(&control->runtime_root.enabled, 1);
}

void nyx_strict_pt_runtime_publish_disabled(
	struct nyx_strict_pt_control_context *control)
{
	smp_store_release(&control->runtime_root.enabled, 0);
}

int nyx_strict_pt_runtime_fail_closed(
	struct nyx_strict_pt_runtime_tracker *runtime, int err)
{
	spin_lock(&runtime->lock);
	nyx_strict_pt_runtime_clear_pending_locked(runtime);
	spin_unlock(&runtime->lock);
	nyx_strict_pt_control_fail_closed(runtime->control);
	nyx_strict_pt_runtime_publish_disabled(runtime->control);
	return err ? err : -EIO;
}

int nyx_strict_pt_runtime_begin_epoch(
	struct nyx_strict_pt_runtime_tracker *runtime, __u64 *epoch)
{
	__u64 next = READ_ONCE(runtime->control_epoch) + 1;

	if (!epoch || !next)
		return -EOVERFLOW;

	*epoch = next;
	smp_store_release(&runtime->control_epoch, next);
	kvm_make_all_cpus_request(runtime->kvm, KVM_REQ_NYX_STRICT_PT_UPDATE);
	return 0;
}

void nyx_strict_pt_runtime_end_epoch(
	struct nyx_strict_pt_runtime_tracker *runtime, __u64 epoch)
{
	smp_store_release(&runtime->completed_epoch, epoch);
	wake_up_all(&runtime->control_waitq);
}

static void nyx_strict_pt_runtime_track_write(
	gpa_t gpa, const u8 *new, int bytes,
	struct kvm_page_track_notifier_node *node)
{
	struct nyx_strict_pt_runtime_tracker *runtime;
	struct kvm_vcpu *vcpu;
	struct nyx_strict_pt_write_result result;
	bool kick = false;

	(void)new;
	if (bytes <= 0)
		return;

	runtime = container_of(node, struct nyx_strict_pt_runtime_tracker,
				       notifier);

	spin_lock(&runtime->lock);
	if (runtime->invalidated)
		goto out_unlock;

	result = nyx_strict_pt_tracker_classify_write(&runtime->tracker, gpa,
					      (__u64)bytes);
	if (result.range_mask) {
		runtime->pending_range_mask |= result.range_mask;
		runtime->pt_write_events++;
		kick = true;
	}

out_unlock:
	spin_unlock(&runtime->lock);
	if (!kick)
		return;

	vcpu = kvm_get_vcpu(runtime->kvm, 0);
	if (!vcpu)
		return;
	kvm_make_request(KVM_REQ_NYX_STRICT_PT_REWALK, vcpu);
	kvm_vcpu_kick(vcpu);
}

static void nyx_strict_pt_runtime_track_remove_region(
	gfn_t gfn, unsigned long nr_pages,
	struct kvm_page_track_notifier_node *node)
{
	struct nyx_strict_pt_runtime_tracker *runtime;
	struct kvm_vcpu *vcpu;
	bool kick = false;

	runtime = container_of(node, struct nyx_strict_pt_runtime_tracker,
				       notifier);

	spin_lock(&runtime->lock);
	if (!runtime->invalidated &&
	    nyx_strict_pt_owner_overlaps_range(&runtime->tracker, gfn, nr_pages)) {
		runtime->invalidated = true;
		nyx_strict_pt_runtime_publish_disabled(runtime->control);
		kick = true;
	}
	spin_unlock(&runtime->lock);
	if (!kick)
		return;

	vcpu = kvm_get_vcpu(runtime->kvm, 0);
	if (!vcpu)
		return;

	kvm_make_request(KVM_REQ_NYX_STRICT_PT_UPDATE, vcpu);
	kvm_make_request(KVM_REQ_NYX_STRICT_PT_REWALK, vcpu);
	kvm_vcpu_kick(vcpu);
}

int nyx_strict_pt_runtime_create(
	struct kvm *kvm, struct nyx_strict_pt_control_context *control)
{
	struct nyx_strict_pt_runtime_tracker *runtime;
	int ret;

	if (WARN_ON_ONCE(kvm->arch.nyx_strict_pt_runtime))
		return -EEXIST;

	runtime = kzalloc(sizeof(*runtime), GFP_KERNEL_ACCOUNT);
	if (!runtime)
		return -ENOMEM;

	runtime->kvm = kvm;
	runtime->control = control;
	mutex_init(&runtime->operation_mutex);
	spin_lock_init(&runtime->lock);
	init_waitqueue_head(&runtime->control_waitq);
	INIT_HLIST_NODE(&runtime->notifier.node);
	runtime->notifier.track_write = nyx_strict_pt_runtime_track_write;
	runtime->notifier.track_remove_region =
		nyx_strict_pt_runtime_track_remove_region;

	ret = kvm_page_track_register_internal_notifier(kvm, &runtime->notifier);
	if (ret) {
		kfree(runtime);
		return ret;
	}

	kvm->arch.nyx_strict_pt_runtime = runtime;
	return 0;
}

void nyx_strict_pt_runtime_wait_for_update(struct kvm *kvm)
{
	struct nyx_strict_pt_runtime_tracker *runtime = kvm->arch.nyx_strict_pt_runtime;
	__u64 epoch;

	if (!runtime)
		return;

	epoch = smp_load_acquire(&runtime->control_epoch);
	if (!epoch)
		return;

	wait_event(runtime->control_waitq,
		   smp_load_acquire(&runtime->completed_epoch) >= epoch);
}

void nyx_strict_pt_runtime_refresh_status(struct kvm *kvm)
{
	struct nyx_strict_pt_runtime_tracker *runtime = kvm->arch.nyx_strict_pt_runtime;

	if (!runtime)
		return;

	spin_lock(&runtime->lock);
	runtime->control->counters.pt_write_events = runtime->pt_write_events;
	spin_unlock(&runtime->lock);
}
