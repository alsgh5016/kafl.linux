/* SPDX-License-Identifier: GPL-2.0 */
#ifndef ARCH_X86_KVM_NYX_STRICT_PT_EXEC_STATE_H
#define ARCH_X86_KVM_NYX_STRICT_PT_EXEC_STATE_H

#ifndef __KERNEL__
#include <stdbool.h>
#endif

#include <linux/kvm.h>
#include <linux/types.h>

struct nyx_strict_pt_exec_state {
	bool pending;
	struct kvm_nyx_strict_pt_exit payload;
};

bool nyx_strict_pt_exec_state_latch(struct nyx_strict_pt_exec_state *state,
				    const struct kvm_nyx_strict_pt_exit *payload);

bool nyx_strict_pt_exec_state_replay(const struct nyx_strict_pt_exec_state *state,
				     struct kvm_nyx_strict_pt_exit *out);

bool nyx_strict_pt_exec_state_compare_ack(const struct nyx_strict_pt_exec_state *state,
					  __u64 session_id, __u64 range_id,
					  __u64 generation, __u32 page_index);

bool nyx_strict_pt_exec_state_commit_ack(struct nyx_strict_pt_exec_state *state,
					 __u64 session_id, __u64 range_id,
					 __u64 generation, __u32 page_index);

void nyx_strict_pt_exec_state_clear(struct nyx_strict_pt_exec_state *state);

#endif
