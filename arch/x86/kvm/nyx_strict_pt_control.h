/* SPDX-License-Identifier: GPL-2.0 */
#ifndef ARCH_X86_KVM_NYX_STRICT_PT_CONTROL_H
#define ARCH_X86_KVM_NYX_STRICT_PT_CONTROL_H

#include "nyx_strict_pt_policy.h"

#define NYX_STRICT_PT_MAX_RANGES 64U
#define NYX_STRICT_PT_REQUIRED_FEATURES \
	(KVM_NYX_STRICT_PT_FEAT_CPU_PT_WRITE_TRACKING | \
	 KVM_NYX_STRICT_PT_FEAT_ROOT_LOCAL_EPT | \
	 KVM_NYX_STRICT_PT_FEAT_GENERATION_ACK | \
	 KVM_NYX_STRICT_PT_FEAT_HUGE_GUEST_LEAVES | \
	 KVM_NYX_STRICT_PT_FEAT_RESET)

struct nyx_strict_pt_control_counters {
	__u64 ranges_added;
	__u64 ranges_removed;
	__u64 resets;
	__u64 pt_write_events;
	__u64 mapping_changes;
	__u64 nx_arms;
	__u64 strict_exits;
	__u64 acks;
	__u64 stale_acks;
	__u64 fail_closed;
};

struct nyx_strict_pt_runtime_root_state {
	__u64 target_cr3;
	__u32 enabled;
	__u32 reserved0;
};

struct nyx_strict_pt_control_context {
	struct nyx_strict_pt_policy_state policy;
	struct nyx_strict_pt_runtime_root_state runtime_root;
	__u64 next_session_id;
	__u64 next_generation;
	struct nyx_strict_pt_control_counters counters;
};

int nyx_strict_pt_control_execute(
	struct nyx_strict_pt_control_context *context,
	struct kvm_nyx_strict_pt_control *control,
	__u32 vcpu_count,
	__u64 available_features);

void nyx_strict_pt_control_fail_closed(
	struct nyx_strict_pt_control_context *context);

bool nyx_strict_pt_control_copyout_failed(
	struct nyx_strict_pt_control_context *context,
	const struct kvm_nyx_strict_pt_control *control);

#endif
