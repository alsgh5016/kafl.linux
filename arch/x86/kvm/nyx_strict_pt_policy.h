/* SPDX-License-Identifier: GPL-2.0 */
#ifndef ARCH_X86_KVM_NYX_STRICT_PT_POLICY_H
#define ARCH_X86_KVM_NYX_STRICT_PT_POLICY_H

#ifndef __KERNEL__
#include <stdbool.h>
#endif

#include <linux/kvm.h>

enum nyx_strict_pt_policy_result {
	NYX_STRICT_PT_POLICY_OK = 0,
	NYX_STRICT_PT_POLICY_INVALID,
	NYX_STRICT_PT_POLICY_PROTOCOL,
	NYX_STRICT_PT_POLICY_UNSUPPORTED,
	NYX_STRICT_PT_POLICY_BUSY,
	NYX_STRICT_PT_POLICY_STALE,
	NYX_STRICT_PT_POLICY_BROKEN,
};

struct nyx_strict_pt_policy_state {
	__u32 state;
	__u32 active_ranges;
	__u32 pending_exit;
	__u32 reserved0;
	__u64 session_id;
	__u64 target_cr3;
};

struct nyx_strict_pt_policy_envelope {
	__u16 version;
	__u16 command;
	__u32 flags;
	__u32 size;
	__u32 reserved0;
};

enum nyx_strict_pt_policy_result
nyx_strict_pt_policy_validate_envelope(
	const struct nyx_strict_pt_policy_envelope *envelope,
	bool payload_reserved_zero);

__u64 nyx_strict_pt_policy_normalize_cr3(__u64 raw_cr3);

enum nyx_strict_pt_policy_result
nyx_strict_pt_policy_enable(struct nyx_strict_pt_policy_state *state,
	__u32 vcpu_count, bool enforcement_ready, __u64 target_cr3,
	__u64 new_session_id);

enum nyx_strict_pt_policy_result
nyx_strict_pt_policy_reset(struct nyx_strict_pt_policy_state *state,
	__u64 session_id, __u64 new_session_id);

enum nyx_strict_pt_policy_result
nyx_strict_pt_policy_disable(struct nyx_strict_pt_policy_state *state);

enum nyx_strict_pt_policy_result
nyx_strict_pt_policy_require_session(const struct nyx_strict_pt_policy_state *state,
	__u64 session_id);

enum nyx_strict_pt_policy_result
nyx_strict_pt_policy_fail_closed(struct nyx_strict_pt_policy_state *state);

bool nyx_strict_pt_policy_command_allowed(
	const struct nyx_strict_pt_policy_state *state,
	__u16 command);

bool nyx_strict_pt_policy_is_target_root(
	const struct nyx_strict_pt_policy_state *state, __u64 raw_cr3,
	bool is_guest_mode, bool is_smm, bool is_direct_tdp);

bool nyx_strict_pt_policy_vcpu_create_allowed(
	const struct nyx_strict_pt_policy_state *state);

#endif
