// SPDX-License-Identifier: GPL-2.0

#include "mmu.h"
#include "mmu/page_track.h"
#include "nyx_strict_pt_runtime_range_internal.h"

int nyx_strict_pt_runtime_get_vcpu0(struct kvm *kvm,
	struct kvm_vcpu **vcpu, __u8 *va_bits)
{
	struct kvm_vcpu *local_vcpu;

	if (kvm->created_vcpus != 1)
		return -EOPNOTSUPP;
	local_vcpu = kvm_get_vcpu(kvm, 0);
	if (!local_vcpu || !local_vcpu->arch.mmu)
		return -EOPNOTSUPP;
	switch (local_vcpu->arch.mmu->cpu_role.base.level) {
	case PT64_ROOT_4LEVEL:
		*va_bits = 48;
		break;
	case PT64_ROOT_5LEVEL:
		*va_bits = 57;
		break;
	default:
		return -EOPNOTSUPP;
	}
	*vcpu = local_vcpu;
	return 0;
}

int nyx_strict_pt_runtime_count_walk_gfns(
	const struct nyx_strict_pt_range_add_txn *add, __u32 *page_count,
	__u32 *max_walk_gfns)
{
	__u64 total_pages;

	if (!page_count || !max_walk_gfns ||
	    nyx_strict_pt_validate_range_add_txn(add))
		return -EINVAL;
	total_pages = (add->gva_end - add->gva_start) >> NYX_STRICT_PT_PAGE_SHIFT;
	if (total_pages > ~(__u32)0U ||
	    total_pages > ((__u64)~(__u32)0U / PT64_ROOT_MAX_LEVEL))
		return -EOVERFLOW;
	*page_count = (__u32)total_pages;
	*max_walk_gfns = (__u32)(total_pages * PT64_ROOT_MAX_LEVEL);
	return 0;
}

void nyx_strict_pt_runtime_rollback_added_tracks(
	struct kvm *kvm, const struct nyx_strict_pt_prepare *prepare,
	__u32 added_count)
{
	while (added_count-- > 0)
		(void)kvm_write_track_remove_gfn(kvm,
				      (gfn_t)prepare->track_gfns[added_count]);
}

void nyx_strict_pt_runtime_release_mmu_locks(struct kvm *kvm, int srcu_idx,
	bool flush)
{
	if (flush)
		kvm_flush_remote_tlbs(kvm);
	write_unlock(&kvm->mmu_lock);
	srcu_read_unlock(&kvm->srcu, srcu_idx);
}

int nyx_strict_pt_runtime_fail_closed_session(
	struct nyx_strict_pt_runtime_tracker *runtime, int ret)
{
	int clear_ret;

	ret = ret ?: -EIO;

	spin_lock(&runtime->lock);
	runtime->invalidated = true;
	runtime->pending_range_mask = 0;
	runtime->inflight_range_mask = 0;
	spin_unlock(&runtime->lock);
	(void)nyx_strict_pt_runtime_fail_closed(runtime, ret);
	clear_ret = nyx_strict_pt_runtime_clear_session(runtime, true);
	spin_lock(&runtime->lock);
	if (!clear_ret)
		runtime->invalidated = false;
	runtime->pending_range_mask = 0;
	runtime->inflight_range_mask = 0;
	spin_unlock(&runtime->lock);
	nyx_strict_pt_runtime_publish_disabled(runtime->control);
	return clear_ret ?: ret;
}
