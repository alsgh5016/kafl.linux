/* SPDX-License-Identifier: GPL-2.0 */
#ifndef ARCH_X86_KVM_NYX_STRICT_PT_RUNTIME_REWALK_INTERNAL_H
#define ARCH_X86_KVM_NYX_STRICT_PT_RUNTIME_REWALK_INTERNAL_H

#include "nyx_strict_pt_runtime_range_internal.h"

struct nyx_strict_pt_rewalk_snapshot {
	const struct nyx_strict_pt_owner *table_owners;
	const struct nyx_strict_pt_owner *data_owners;
	const __u64 *data_gfns;
	__u64 session_id;
	__u64 range_id;
	__u64 gva_start;
	__u64 gva_end;
	__u64 generation;
	__u64 assigned_generation;
	gpa_t target_cr3;
	__u32 slot;
	__u64 bit;
	bool data_active;
};

int nyx_strict_pt_runtime_process_rewalk_slot(
	struct kvm_vcpu *vcpu, struct nyx_strict_pt_runtime_tracker *runtime,
	__u32 slot, __u8 va_bits);

#endif
