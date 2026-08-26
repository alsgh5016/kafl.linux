/* SPDX-License-Identifier: GPL-2.0 */
#ifndef ARCH_X86_KVM_NYX_STRICT_PT_RUNTIME_RANGE_INTERNAL_H
#define ARCH_X86_KVM_NYX_STRICT_PT_RUNTIME_RANGE_INTERNAL_H

#include "nyx_strict_pt_runtime_internal.h"

int nyx_strict_pt_runtime_get_vcpu0(struct kvm *kvm,
	struct kvm_vcpu **vcpu, __u8 *va_bits);
int nyx_strict_pt_runtime_count_walk_gfns(
	const struct nyx_strict_pt_range_add_txn *add, __u32 *page_count,
	__u32 *max_walk_gfns);
void nyx_strict_pt_runtime_rollback_added_tracks(
	struct kvm *kvm, const struct nyx_strict_pt_prepare *prepare,
	__u32 added_count);
void nyx_strict_pt_runtime_release_mmu_locks(struct kvm *kvm, int srcu_idx,
	bool flush);
#endif
