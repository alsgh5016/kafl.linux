// SPDX-License-Identifier: GPL-2.0

#include "nyx_strict_pt_policy.h"

static bool nyx_strict_pt_policy_valid_command(__u16 command)
{
	switch (command) {
	case KVM_NYX_STRICT_PT_QUERY:
	case KVM_NYX_STRICT_PT_ENABLE:
	case KVM_NYX_STRICT_PT_DISABLE:
	case KVM_NYX_STRICT_PT_RESET:
	case KVM_NYX_STRICT_PT_RANGE_ADD:
	case KVM_NYX_STRICT_PT_RANGE_REMOVE:
	case KVM_NYX_STRICT_PT_ACK:
	case KVM_NYX_STRICT_PT_GET_STATUS:
		return true;
	default:
		return false;
	}
}

static void nyx_strict_pt_policy_clear_transient(
	struct nyx_strict_pt_policy_state *state)
{
	state->active_ranges = 0;
	state->pending_exit = 0;
	state->reserved0 = 0;
}

enum nyx_strict_pt_policy_result
nyx_strict_pt_policy_validate_envelope(
	const struct nyx_strict_pt_policy_envelope *envelope,
	bool payload_reserved_zero)
{
	if (envelope->version != KVM_NYX_STRICT_PT_ABI_VERSION_1)
		return NYX_STRICT_PT_POLICY_PROTOCOL;

	if (!nyx_strict_pt_policy_valid_command(envelope->command) ||
	    envelope->flags != 0 ||
	    envelope->size != KVM_NYX_STRICT_PT_CONTROL_SIZE ||
	    envelope->reserved0 != 0 ||
	    !payload_reserved_zero)
		return NYX_STRICT_PT_POLICY_INVALID;

	return NYX_STRICT_PT_POLICY_OK;
}

__u64 nyx_strict_pt_policy_normalize_cr3(__u64 raw_cr3)
{
	return raw_cr3 & ~((1ULL << 63) | ((1ULL << 12) - 1));
}

enum nyx_strict_pt_policy_result
nyx_strict_pt_policy_enable(struct nyx_strict_pt_policy_state *state,
	__u32 vcpu_count, bool enforcement_ready, __u64 target_cr3,
	__u64 new_session_id)
{
	if (state->state == KVM_NYX_STRICT_PT_BROKEN)
		return NYX_STRICT_PT_POLICY_BROKEN;

	if (state->state == KVM_NYX_STRICT_PT_ENABLED)
		return NYX_STRICT_PT_POLICY_BUSY;

	if (vcpu_count != 1 || !enforcement_ready)
		return NYX_STRICT_PT_POLICY_UNSUPPORTED;

	if (new_session_id == 0)
		return NYX_STRICT_PT_POLICY_INVALID;

	state->state = KVM_NYX_STRICT_PT_ENABLED;
	nyx_strict_pt_policy_clear_transient(state);
	state->session_id = new_session_id;
	state->target_cr3 = nyx_strict_pt_policy_normalize_cr3(target_cr3);

	return NYX_STRICT_PT_POLICY_OK;
}

enum nyx_strict_pt_policy_result
nyx_strict_pt_policy_reset(struct nyx_strict_pt_policy_state *state,
	__u64 session_id, __u64 new_session_id)
{
	if (state->state == KVM_NYX_STRICT_PT_BROKEN)
		return NYX_STRICT_PT_POLICY_BROKEN;

	if (state->state != KVM_NYX_STRICT_PT_ENABLED)
		return NYX_STRICT_PT_POLICY_INVALID;

	if (state->session_id != session_id)
		return NYX_STRICT_PT_POLICY_STALE;

	if (new_session_id == 0 || new_session_id == state->session_id)
		return NYX_STRICT_PT_POLICY_INVALID;

	nyx_strict_pt_policy_clear_transient(state);
	state->session_id = new_session_id;

	return NYX_STRICT_PT_POLICY_OK;
}

enum nyx_strict_pt_policy_result
nyx_strict_pt_policy_disable(struct nyx_strict_pt_policy_state *state)
{
	state->state = KVM_NYX_STRICT_PT_DISABLED;
	nyx_strict_pt_policy_clear_transient(state);
	state->session_id = 0;
	state->target_cr3 = 0;

	return NYX_STRICT_PT_POLICY_OK;
}

enum nyx_strict_pt_policy_result
nyx_strict_pt_policy_require_session(const struct nyx_strict_pt_policy_state *state,
	__u64 session_id)
{
	if (state->state == KVM_NYX_STRICT_PT_BROKEN)
		return NYX_STRICT_PT_POLICY_BROKEN;

	if (state->state != KVM_NYX_STRICT_PT_ENABLED || session_id == 0)
		return NYX_STRICT_PT_POLICY_INVALID;

	if (state->session_id != session_id)
		return NYX_STRICT_PT_POLICY_STALE;

	return NYX_STRICT_PT_POLICY_OK;
}

enum nyx_strict_pt_policy_result
nyx_strict_pt_policy_fail_closed(struct nyx_strict_pt_policy_state *state)
{
	state->state = KVM_NYX_STRICT_PT_BROKEN;
	return NYX_STRICT_PT_POLICY_BROKEN;
}

bool nyx_strict_pt_policy_command_allowed(
	const struct nyx_strict_pt_policy_state *state,
	__u16 command)
{
	if (!nyx_strict_pt_policy_valid_command(command))
		return false;

	if (state->state != KVM_NYX_STRICT_PT_BROKEN)
		return true;

	return command == KVM_NYX_STRICT_PT_QUERY ||
	       command == KVM_NYX_STRICT_PT_GET_STATUS ||
	       command == KVM_NYX_STRICT_PT_DISABLE;
}

bool nyx_strict_pt_policy_is_target_root(
	const struct nyx_strict_pt_policy_state *state, __u64 raw_cr3,
	bool is_guest_mode, bool is_smm, bool is_direct_tdp)
{
	return state->state == KVM_NYX_STRICT_PT_ENABLED && !is_guest_mode &&
		!is_smm && is_direct_tdp &&
		nyx_strict_pt_policy_normalize_cr3(raw_cr3) == state->target_cr3;
}

bool nyx_strict_pt_policy_vcpu_create_allowed(
	const struct nyx_strict_pt_policy_state *state)
{
	return state->state == KVM_NYX_STRICT_PT_DISABLED;
}
