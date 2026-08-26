// SPDX-License-Identifier: GPL-2.0

#include "mmu/tdp_mmu.h"
#include "nyx_strict_pt_runtime_internal.h"

static void nyx_strict_pt_runtime_copy_exit_to_run(struct kvm_vcpu *vcpu,
	const struct kvm_nyx_strict_pt_exit *payload)
{
	vcpu->run->exit_reason = KVM_EXIT_KAFL_STRICT_PT;
	vcpu->run->kafl_strict_pt = *payload;
}

bool nyx_strict_pt_runtime_data_gfn_needs_nx(struct kvm *kvm, gfn_t gfn)
{
	struct nyx_strict_pt_runtime_tracker *runtime = READ_ONCE(kvm->arch.nyx_strict_pt_runtime);
	bool needs_nx = false;

	if (!runtime || !smp_load_acquire(&runtime->control->runtime_root.enabled))
		return false;

	spin_lock(&runtime->lock);
	if (!runtime->invalidated && runtime->data_tracker.owner_count)
		needs_nx = !nyx_strict_pt_data_tracker_needs_nx(&runtime->data_tracker,
						       gfn, &needs_nx) &&
			   needs_nx;
	spin_unlock(&runtime->lock);

	return needs_nx;
}

static int nyx_strict_pt_runtime_replay_pending_locked(
	struct nyx_strict_pt_runtime_tracker *runtime, struct kvm_vcpu *vcpu)
{
	struct kvm_nyx_strict_pt_exit payload;

	lockdep_assert_held(&runtime->lock);
	if (runtime->invalidated)
		return -EIO;
	if (!nyx_strict_pt_exec_state_replay(&runtime->exec_state, &payload))
		return 0;

	spin_unlock(&runtime->lock);
	nyx_strict_pt_runtime_copy_exit_to_run(vcpu, &payload);
	return 1;
}

int nyx_strict_pt_runtime_replay_pending(struct kvm_vcpu *vcpu)
{
	struct nyx_strict_pt_runtime_tracker *runtime;
	int ret;

	if (!vcpu || !vcpu->kvm)
		return -EINVAL;

	runtime = READ_ONCE(vcpu->kvm->arch.nyx_strict_pt_runtime);
	if (!runtime || !smp_load_acquire(&runtime->control->runtime_root.enabled))
		return 0;

	spin_lock(&runtime->lock);
	ret = nyx_strict_pt_runtime_replay_pending_locked(runtime, vcpu);
	if (ret > 0)
		return ret;
	spin_unlock(&runtime->lock);
	if (!ret)
		return 0;
	return nyx_strict_pt_runtime_fail_closed_session(runtime, ret);
}

int nyx_strict_pt_runtime_handle_exec_violation(struct kvm_vcpu *vcpu,
	__u64 gva, gpa_t gpa, __u64 rip, __u64 cr3)
{
	struct nyx_strict_pt_runtime_tracker *runtime;
	struct nyx_strict_pt_exec_identity identity;
	struct kvm_nyx_strict_pt_exit payload = { 0 };
	bool needs_nx;
	int ret;

	if (!vcpu || !vcpu->kvm)
		return -EINVAL;

	runtime = READ_ONCE(vcpu->kvm->arch.nyx_strict_pt_runtime);
	if (!runtime || !smp_load_acquire(&runtime->control->runtime_root.enabled))
		return -EINVAL;

	spin_lock(&runtime->lock);
	ret = nyx_strict_pt_runtime_replay_pending_locked(runtime, vcpu);
	if (ret > 0)
		return 0;
	if (ret || !runtime->tracker.session_id ||
	    runtime->control->policy.state != KVM_NYX_STRICT_PT_ENABLED) {
		spin_unlock(&runtime->lock);
		return nyx_strict_pt_runtime_fail_closed_session(runtime, ret ?: -EIO);
	}

	ret = nyx_strict_pt_data_tracker_needs_nx(&runtime->data_tracker,
						 gpa >> PAGE_SHIFT,
						 &needs_nx);
	if (ret || !needs_nx)
		goto out_unlock_fail_closed;

	ret = nyx_strict_pt_tracker_resolve_exec(&runtime->tracker,
						 &runtime->data_tracker,
						 gva, gpa >> PAGE_SHIFT,
						 &identity);
	if (ret)
		goto out_unlock_fail_closed;
	if (!nyx_strict_pt_runtime_counter_inc(
		    &runtime->control->counters.strict_exits)) {
		ret = -EOVERFLOW;
		goto out_unlock_fail_closed;
	}

	payload.version = KVM_NYX_STRICT_PT_ABI_VERSION_1;
	payload.flags = KVM_NYX_STRICT_PT_EXIT_FIRST_EXEC;
	payload.session_id = runtime->tracker.session_id;
	payload.range_id = identity.range_id;
	payload.generation = identity.generation;
	payload.gva = gva;
	payload.gpa = gpa;
	payload.rip = rip;
	payload.cr3 = cr3;
	payload.page_index = identity.page_index;
	if (!nyx_strict_pt_exec_state_latch(&runtime->exec_state, &payload)) {
		ret = -EIO;
		goto out_unlock_fail_closed;
	}

	runtime->control->policy.pending_exit = 1;
	payload = runtime->exec_state.payload;
	spin_unlock(&runtime->lock);
	nyx_strict_pt_runtime_copy_exit_to_run(vcpu, &payload);
	return 0;

out_unlock_fail_closed:
	spin_unlock(&runtime->lock);
	return nyx_strict_pt_runtime_fail_closed_session(runtime,
						 ret ?: -EIO);
}

int nyx_strict_pt_runtime_handle_ack(struct kvm *kvm,
	struct kvm_nyx_strict_pt_control *control)
{
	struct nyx_strict_pt_runtime_tracker *runtime = kvm->arch.nyx_strict_pt_runtime;
	struct nyx_strict_pt_exec_identity identity;
	struct kvm_memory_slot *slot;
	__u64 gfn;
	int srcu_idx;
	int ret = 0;
	bool flush = false;

	if (!runtime || !control)
		return -EINVAL;

	srcu_idx = srcu_read_lock(&kvm->srcu);
	write_lock(&kvm->mmu_lock);
	spin_lock(&runtime->lock);
	if (!nyx_strict_pt_exec_state_compare_ack(&runtime->exec_state,
					control->u.ack.session_id,
					control->u.ack.range_id,
					control->u.ack.generation,
					control->u.ack.page_index))
		goto out_stale;

	gfn = runtime->exec_state.payload.gpa >> PAGE_SHIFT;
	slot = gfn_to_memslot(kvm, (gfn_t)gfn);
	ret = slot ? nyx_strict_pt_tracker_resolve_exec(&runtime->tracker,
							&runtime->data_tracker,
							runtime->exec_state.payload.gva,
							gfn, &identity) : -EIO;
	if (ret)
		goto out_unlock_fail_closed;
	if (identity.range_id != runtime->exec_state.payload.range_id ||
	    identity.generation != runtime->exec_state.payload.generation ||
	    identity.page_index != runtime->exec_state.payload.page_index)
		goto out_stale;

	ret = nyx_strict_pt_data_tracker_ack_exec(&runtime->data_tracker, gfn);
	if (ret)
		goto out_unlock_fail_closed;
	if (!nyx_strict_pt_runtime_counter_inc(&runtime->control->counters.acks)) {
		ret = -EOVERFLOW;
		goto out_unlock_fail_closed;
	}

	nyx_strict_pt_runtime_clear_pending_locked(runtime);
	spin_unlock(&runtime->lock);
	ret = kvm_tdp_mmu_nyx_strict_set_x_gfn(kvm, slot, (gfn_t)gfn, &flush);
	if (ret)
		goto out_fail_closed_after_unlock;
	if (flush)
		kvm_flush_remote_tlbs(kvm);
	write_unlock(&kvm->mmu_lock);
	srcu_read_unlock(&kvm->srcu, srcu_idx);
	return 0;

out_stale:
	if (nyx_strict_pt_runtime_counter_inc(&runtime->control->counters.stale_acks))
		ret = -ESTALE;
	else
		ret = -EOVERFLOW;
	spin_unlock(&runtime->lock);
	write_unlock(&kvm->mmu_lock);
	srcu_read_unlock(&kvm->srcu, srcu_idx);
	return ret;

out_unlock_fail_closed:
	spin_unlock(&runtime->lock);
out_fail_closed_after_unlock:
	write_unlock(&kvm->mmu_lock);
	srcu_read_unlock(&kvm->srcu, srcu_idx);
	return nyx_strict_pt_runtime_fail_closed_session(runtime, ret ?: -EIO);
}
