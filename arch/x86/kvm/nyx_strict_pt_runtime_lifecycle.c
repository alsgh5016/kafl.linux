// SPDX-License-Identifier: GPL-2.0

#include "nyx_strict_pt_runtime_internal.h"

static int nyx_strict_pt_runtime_cleanup_disabled(
	struct nyx_strict_pt_runtime_tracker *runtime, bool fail_closed)
{
	__u64 epoch;
	int ret;

	if (fail_closed)
		nyx_strict_pt_control_fail_closed(runtime->control);

	ret = nyx_strict_pt_runtime_begin_epoch(runtime, &epoch);
	if (ret)
		return nyx_strict_pt_runtime_fail_closed(runtime, ret);

	ret = nyx_strict_pt_runtime_clear_session(runtime, true);
	if (!ret) {
		spin_lock(&runtime->lock);
		runtime->invalidated = false;
		spin_unlock(&runtime->lock);
	}
	nyx_strict_pt_runtime_publish_disabled(runtime->control);
	nyx_strict_pt_runtime_end_epoch(runtime, epoch);
	if (ret)
		return nyx_strict_pt_runtime_fail_closed(runtime, ret);

	return 0;
}

int nyx_strict_pt_runtime_consume_invalidation(struct kvm *kvm)
{
	struct nyx_strict_pt_runtime_tracker *runtime = kvm->arch.nyx_strict_pt_runtime;

	if (!runtime)
		return 0;

	spin_lock(&runtime->lock);
	if (!runtime->invalidated) {
		spin_unlock(&runtime->lock);
		return 0;
	}
	spin_unlock(&runtime->lock);

	return nyx_strict_pt_runtime_cleanup_disabled(runtime, true);
}

int nyx_strict_pt_runtime_handle_enable(
	struct kvm *kvm, struct kvm_nyx_strict_pt_control *control)
{
	struct nyx_strict_pt_runtime_tracker *runtime = kvm->arch.nyx_strict_pt_runtime;
	int ret;

	ret = nyx_strict_pt_runtime_begin_session(runtime,
					  control->u.enable.session_id);
	if (ret)
		return nyx_strict_pt_runtime_cleanup_disabled(runtime, true);

	nyx_strict_pt_runtime_publish_enabled(runtime->control);
	kvm_make_all_cpus_request(kvm, KVM_REQ_NYX_STRICT_PT_UPDATE);
	return 0;
}

int nyx_strict_pt_runtime_handle_reset(
	struct kvm *kvm, struct kvm_nyx_strict_pt_control *control)
{
	struct nyx_strict_pt_runtime_tracker *runtime = kvm->arch.nyx_strict_pt_runtime;
	__u64 epoch;
	int ret;

	ret = nyx_strict_pt_runtime_begin_epoch(runtime, &epoch);
	if (ret)
		return nyx_strict_pt_runtime_fail_closed(runtime, ret);

	ret = nyx_strict_pt_runtime_clear_session(runtime, true);
	if (!ret) {
		spin_lock(&runtime->lock);
		runtime->invalidated = false;
		spin_unlock(&runtime->lock);
		ret = nyx_strict_pt_runtime_begin_session(runtime,
						  control->u.reset.new_session_id);
	}
	if (!ret)
		nyx_strict_pt_runtime_publish_enabled(runtime->control);
	else
		nyx_strict_pt_runtime_publish_disabled(runtime->control);

	nyx_strict_pt_runtime_end_epoch(runtime, epoch);
	if (ret)
		return nyx_strict_pt_runtime_cleanup_disabled(runtime, true);
	return 0;
}

int nyx_strict_pt_runtime_handle_disable(struct kvm *kvm)
{
	struct nyx_strict_pt_runtime_tracker *runtime = kvm->arch.nyx_strict_pt_runtime;

	return runtime ? nyx_strict_pt_runtime_cleanup_disabled(runtime, false) : 0;
}

void nyx_strict_pt_runtime_handle_copyout_fault(
	struct kvm *kvm, const struct kvm_nyx_strict_pt_control *control)
{
	struct nyx_strict_pt_runtime_tracker *runtime = kvm->arch.nyx_strict_pt_runtime;

	if (!runtime ||
	    !nyx_strict_pt_control_copyout_failed(runtime->control, control))
		return;

	(void)nyx_strict_pt_runtime_cleanup_disabled(runtime, false);
}
