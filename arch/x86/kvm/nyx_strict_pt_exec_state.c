/* SPDX-License-Identifier: GPL-2.0 */
#include "nyx_strict_pt_exec_state.h"

#ifdef __KERNEL__
#include <linux/string.h>
#else
#include <string.h>
#endif

bool nyx_strict_pt_exec_state_latch(struct nyx_strict_pt_exec_state *state,
				    const struct kvm_nyx_strict_pt_exit *payload)
{
	if (state->pending)
		return false;

	state->payload = *payload;
	state->pending = true;
	return true;
}

bool nyx_strict_pt_exec_state_replay(const struct nyx_strict_pt_exec_state *state,
				     struct kvm_nyx_strict_pt_exit *out)
{
	if (!state->pending)
		return false;

	if (out)
		*out = state->payload;
	return true;
}

bool nyx_strict_pt_exec_state_compare_ack(const struct nyx_strict_pt_exec_state *state,
					  __u64 session_id, __u64 range_id,
					  __u64 generation, __u32 page_index)
{
	if (!state->pending)
		return false;

	return (state->payload.session_id == session_id) &&
	       (state->payload.range_id == range_id) &&
	       (state->payload.generation == generation) &&
	       (state->payload.page_index == page_index);
}

bool nyx_strict_pt_exec_state_commit_ack(struct nyx_strict_pt_exec_state *state,
					 __u64 session_id, __u64 range_id,
					 __u64 generation, __u32 page_index)
{
	if (nyx_strict_pt_exec_state_compare_ack(state, session_id, range_id,
						 generation, page_index)) {
		nyx_strict_pt_exec_state_clear(state);
		return true;
	}
	return false;
}

void nyx_strict_pt_exec_state_clear(struct nyx_strict_pt_exec_state *state)
{
	state->pending = false;
	memset(&state->payload, 0, sizeof(state->payload));
}
