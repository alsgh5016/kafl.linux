// SPDX-License-Identifier: GPL-2.0

#include "nyx_strict_pt_control.h"

#ifdef __KERNEL__
#include <linux/errno.h>
#else
#include <errno.h>
#endif

static int nyx_strict_pt_control_errno(enum nyx_strict_pt_policy_result result)
{
	switch (result) {
	case NYX_STRICT_PT_POLICY_OK:
		return 0;
	case NYX_STRICT_PT_POLICY_INVALID:
		return -EINVAL;
	case NYX_STRICT_PT_POLICY_PROTOCOL:
		return -EPROTONOSUPPORT;
	case NYX_STRICT_PT_POLICY_UNSUPPORTED:
		return -EOPNOTSUPP;
	case NYX_STRICT_PT_POLICY_BUSY:
		return -EBUSY;
	case NYX_STRICT_PT_POLICY_STALE:
		return -ESTALE;
	case NYX_STRICT_PT_POLICY_BROKEN:
		return -EIO;
	default:
		return -EIO;
	}
}

static bool nyx_strict_pt_control_bytes_zero(const __u8 *bytes, __u32 len)
{
	__u32 i;

	for (i = 0; i < len; i++) {
		if (bytes[i] != 0)
			return false;
	}

	return true;
}

static void nyx_strict_pt_control_zero_bytes(__u8 *bytes, __u32 len)
{
	__u32 i;

	for (i = 0; i < len; i++)
		bytes[i] = 0;
}

static __u64 nyx_strict_pt_control_allocate_session_id(
	struct nyx_strict_pt_control_context *context)
{
	__u64 session_id = context->next_session_id;

	if (session_id == 0)
		session_id = 1;

	context->next_session_id = session_id + 1;
	return session_id;
}

static bool nyx_strict_pt_control_payload_reserved_zero(
	const struct kvm_nyx_strict_pt_control *control)
{
	switch (control->command) {
	case KVM_NYX_STRICT_PT_QUERY:
	case KVM_NYX_STRICT_PT_DISABLE:
	case KVM_NYX_STRICT_PT_GET_STATUS:
		return nyx_strict_pt_control_bytes_zero(control->u.reserved,
					sizeof(control->u.reserved));
	case KVM_NYX_STRICT_PT_ENABLE:
		return control->u.enable.session_id == 0 &&
			nyx_strict_pt_control_bytes_zero(
				(const __u8 *)control->u.enable.reserved,
				sizeof(control->u.enable.reserved));
	case KVM_NYX_STRICT_PT_RESET:
		return control->u.reset.new_session_id == 0 &&
			nyx_strict_pt_control_bytes_zero(
				(const __u8 *)control->u.reset.reserved,
				sizeof(control->u.reset.reserved));
	case KVM_NYX_STRICT_PT_RANGE_ADD:
		return control->u.range_add.range_id == 0 &&
			nyx_strict_pt_control_bytes_zero(
				(const __u8 *)control->u.range_add.reserved,
				sizeof(control->u.range_add.reserved));
	case KVM_NYX_STRICT_PT_RANGE_REMOVE:
		return nyx_strict_pt_control_bytes_zero(
			(const __u8 *)control->u.range_remove.reserved,
			sizeof(control->u.range_remove.reserved));
	case KVM_NYX_STRICT_PT_ACK:
		return control->u.ack.reserved0 == 0 &&
			nyx_strict_pt_control_bytes_zero(
				(const __u8 *)control->u.ack.reserved,
				sizeof(control->u.ack.reserved));
	default:
		return true;
	}
}

static void nyx_strict_pt_control_fill_query(
	struct kvm_nyx_strict_pt_control *control,
	__u64 available_features)
{
	nyx_strict_pt_control_zero_bytes(control->u.reserved,
			sizeof(control->u.reserved));
	control->u.query.features = available_features & NYX_STRICT_PT_REQUIRED_FEATURES;
	control->u.query.abi_min_version = KVM_NYX_STRICT_PT_ABI_VERSION_1;
	control->u.query.abi_max_version = KVM_NYX_STRICT_PT_ABI_VERSION_1;
	control->u.query.max_ranges = NYX_STRICT_PT_MAX_RANGES;
	control->u.query.max_pages_per_range = 0;
	control->u.query.max_vcpus = 1;
	control->u.query.exit_reason = KVM_EXIT_KAFL_STRICT_PT;
}

static void nyx_strict_pt_control_fill_status(
	struct nyx_strict_pt_control_context *context,
	struct kvm_nyx_strict_pt_control *control,
	__u32 vcpu_count)
{
	nyx_strict_pt_control_zero_bytes(control->u.reserved,
			sizeof(control->u.reserved));
	control->u.status.session_id = context->policy.session_id;
	control->u.status.next_generation = context->next_generation;
	control->u.status.state = context->policy.state;
	control->u.status.active_ranges = context->policy.active_ranges;
	control->u.status.vcpu_count = vcpu_count;
	control->u.status.reserved0 = 0;
	control->u.status.ranges_added = context->counters.ranges_added;
	control->u.status.ranges_removed = context->counters.ranges_removed;
	control->u.status.resets = context->counters.resets;
	control->u.status.pt_write_events = context->counters.pt_write_events;
	control->u.status.mapping_changes = context->counters.mapping_changes;
	control->u.status.nx_arms = context->counters.nx_arms;
	control->u.status.strict_exits = context->counters.strict_exits;
	control->u.status.acks = context->counters.acks;
	control->u.status.stale_acks = context->counters.stale_acks;
	control->u.status.fail_closed = context->counters.fail_closed;
}

int nyx_strict_pt_control_execute(
	struct nyx_strict_pt_control_context *context,
	struct kvm_nyx_strict_pt_control *control,
	__u32 vcpu_count,
	__u64 available_features)
{
	enum nyx_strict_pt_policy_result result;
	__u64 session_id;
	bool enforcement_ready;

	result = nyx_strict_pt_policy_validate_envelope(
		&(struct nyx_strict_pt_policy_envelope) {
			.version = control->version,
			.command = control->command,
			.flags = control->flags,
			.size = control->size,
			.reserved0 = control->reserved0,
		}, nyx_strict_pt_control_payload_reserved_zero(control));
	if (result != NYX_STRICT_PT_POLICY_OK)
		return nyx_strict_pt_control_errno(result);

	if (!nyx_strict_pt_policy_command_allowed(&context->policy, control->command))
		return nyx_strict_pt_control_errno(NYX_STRICT_PT_POLICY_BROKEN);

	switch (control->command) {
	case KVM_NYX_STRICT_PT_QUERY:
		nyx_strict_pt_control_fill_query(control, available_features);
		return 0;
	case KVM_NYX_STRICT_PT_GET_STATUS:
		nyx_strict_pt_control_fill_status(context, control, vcpu_count);
		return 0;
	case KVM_NYX_STRICT_PT_ENABLE:
		enforcement_ready =
			(available_features & NYX_STRICT_PT_REQUIRED_FEATURES) ==
			NYX_STRICT_PT_REQUIRED_FEATURES;
		session_id = context->next_session_id;
		if (session_id == 0)
			session_id = 1;
		result = nyx_strict_pt_policy_enable(&context->policy, vcpu_count,
						    enforcement_ready,
						    control->u.enable.target_cr3,
						    session_id);
		if (result != NYX_STRICT_PT_POLICY_OK)
			return nyx_strict_pt_control_errno(result);
		control->u.enable.session_id = nyx_strict_pt_control_allocate_session_id(context);
		context->next_generation = 1;
		return 0;
	case KVM_NYX_STRICT_PT_DISABLE:
		result = nyx_strict_pt_policy_disable(&context->policy);
		if (result != NYX_STRICT_PT_POLICY_OK)
			return nyx_strict_pt_control_errno(result);
		context->next_generation = 0;
		return 0;
	case KVM_NYX_STRICT_PT_RESET:
		session_id = context->next_session_id;
		if (session_id == 0)
			session_id = 1;
		result = nyx_strict_pt_policy_reset(&context->policy,
					   control->u.reset.session_id,
					   session_id);
		if (result != NYX_STRICT_PT_POLICY_OK)
			return nyx_strict_pt_control_errno(result);
		control->u.reset.new_session_id = nyx_strict_pt_control_allocate_session_id(context);
		context->next_generation = 1;
		context->counters.resets++;
		return 0;
	case KVM_NYX_STRICT_PT_RANGE_ADD:
	case KVM_NYX_STRICT_PT_RANGE_REMOVE:
	case KVM_NYX_STRICT_PT_ACK:
		if (control->command == KVM_NYX_STRICT_PT_RANGE_ADD)
			result = nyx_strict_pt_policy_require_session(&context->policy,
				control->u.range_add.session_id);
		else if (control->command == KVM_NYX_STRICT_PT_RANGE_REMOVE)
			result = nyx_strict_pt_policy_require_session(&context->policy,
				control->u.range_remove.session_id);
		else
			result = nyx_strict_pt_policy_require_session(&context->policy,
				control->u.ack.session_id);
		if (result != NYX_STRICT_PT_POLICY_OK)
			return nyx_strict_pt_control_errno(result);
		return -EOPNOTSUPP;
	default:
		return -EINVAL;
	}
}

void nyx_strict_pt_control_fail_closed(
	struct nyx_strict_pt_control_context *context)
{
	if (context->policy.state != KVM_NYX_STRICT_PT_BROKEN)
		context->counters.fail_closed++;

	nyx_strict_pt_policy_fail_closed(&context->policy);
}

bool nyx_strict_pt_control_copyout_failed(
	struct nyx_strict_pt_control_context *context,
	const struct kvm_nyx_strict_pt_control *control)
{
	__u64 session_id;

	switch (control->command) {
	case KVM_NYX_STRICT_PT_ENABLE:
		session_id = control->u.enable.session_id;
		break;
	case KVM_NYX_STRICT_PT_RESET:
		session_id = control->u.reset.new_session_id;
		break;
	case KVM_NYX_STRICT_PT_RANGE_ADD:
		session_id = control->u.range_add.session_id;
		break;
	case KVM_NYX_STRICT_PT_RANGE_REMOVE:
		session_id = control->u.range_remove.session_id;
		break;
	case KVM_NYX_STRICT_PT_ACK:
		session_id = control->u.ack.session_id;
		break;
	case KVM_NYX_STRICT_PT_QUERY:
	case KVM_NYX_STRICT_PT_DISABLE:
	case KVM_NYX_STRICT_PT_GET_STATUS:
	default:
		return false;
	}

	if (context->policy.state != KVM_NYX_STRICT_PT_ENABLED ||
	    context->policy.session_id != session_id)
		return false;

	nyx_strict_pt_control_fail_closed(context);
	return true;
}
