// SPDX-License-Identifier: GPL-2.0

#include "nyx_strict_pt_runtime_rewalk_internal.h"

static __u64 nyx_strict_pt_runtime_begin_rewalk_batch(
	struct nyx_strict_pt_runtime_tracker *runtime, bool *invalidated)
{
	__u64 batch;

	spin_lock(&runtime->lock);
	*invalidated = runtime->invalidated;
	batch = runtime->pending_range_mask;
	runtime->pending_range_mask = 0;
	runtime->inflight_range_mask |= batch;
	spin_unlock(&runtime->lock);
	return batch;
}

int nyx_strict_pt_runtime_handle_rewalk(struct kvm_vcpu *vcpu)
{
	struct nyx_strict_pt_runtime_tracker *runtime;
	struct kvm_vcpu *vcpu0;
	__u64 batch;
	__u32 slot;
	__u8 va_bits;
	bool invalidated;
	int ret;

	if (!vcpu || !vcpu->kvm)
		return -EINVAL;
	runtime = vcpu->kvm->arch.nyx_strict_pt_runtime;
	if (!runtime)
		return 0;

	nyx_strict_pt_runtime_operation_lock(vcpu->kvm);
	ret = nyx_strict_pt_runtime_get_vcpu0(vcpu->kvm, &vcpu0, &va_bits);
	if (ret)
		goto out_unlock_fail_closed;
	if (vcpu != vcpu0) {
		ret = -EINVAL;
		goto out_unlock_fail_closed;
	}

	for (;;) {
		batch = nyx_strict_pt_runtime_begin_rewalk_batch(runtime,
								 &invalidated);
		if (invalidated) {
			ret = -EIO;
			goto out_unlock_fail_closed;
		}
		if (!batch) {
			ret = 0;
			break;
		}
		for (slot = 0; slot < NYX_STRICT_PT_MAX_RANGES; slot++) {
			if (!(batch & (1ULL << slot)))
				continue;
			ret = nyx_strict_pt_runtime_process_rewalk_slot(vcpu, runtime,
					slot, va_bits);
			if (ret)
				goto out_unlock_fail_closed;
		}
	}
	nyx_strict_pt_runtime_operation_unlock(vcpu->kvm);
	return 0;

out_unlock_fail_closed:
	ret = nyx_strict_pt_runtime_fail_closed_session(runtime, ret);
	nyx_strict_pt_runtime_operation_unlock(vcpu->kvm);
	return ret;

}
