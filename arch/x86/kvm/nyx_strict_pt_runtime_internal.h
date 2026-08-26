/* SPDX-License-Identifier: GPL-2.0 */
#ifndef ARCH_X86_KVM_NYX_STRICT_PT_RUNTIME_INTERNAL_H
#define ARCH_X86_KVM_NYX_STRICT_PT_RUNTIME_INTERNAL_H

#include <linux/kvm_host.h>
#include <linux/wait.h>

#include "mmu.h"
#include "mmu/page_track.h"
#include "nyx_strict_pt_control.h"
#include "nyx_strict_pt_exec_state.h"
#include "nyx_strict_pt_runtime.h"
#include "nyx_strict_pt_tracking.h"

struct nyx_strict_pt_runtime_tracker {
	struct kvm *kvm;
	struct nyx_strict_pt_control_context *control;
	struct kvm_page_track_notifier_node notifier;
	struct mutex operation_mutex;
	spinlock_t lock;
	wait_queue_head_t control_waitq;
	struct nyx_strict_pt_tracker tracker;
	struct nyx_strict_pt_data_tracker data_tracker;
	struct nyx_strict_pt_exec_state exec_state;
	__u64 control_epoch;
	__u64 completed_epoch;
	__u64 inflight_range_mask;
	__u64 pending_range_mask;
	__u64 pt_write_events;
	bool invalidated;
};

void nyx_strict_pt_runtime_publish_enabled(
	struct nyx_strict_pt_control_context *control);
void nyx_strict_pt_runtime_publish_disabled(
	struct nyx_strict_pt_control_context *control);
int nyx_strict_pt_runtime_fail_closed(
	struct nyx_strict_pt_runtime_tracker *runtime, int err);
int nyx_strict_pt_runtime_fail_closed_session(
	struct nyx_strict_pt_runtime_tracker *runtime, int ret);
int nyx_strict_pt_runtime_begin_epoch(
	struct nyx_strict_pt_runtime_tracker *runtime, __u64 *epoch);
void nyx_strict_pt_runtime_end_epoch(
	struct nyx_strict_pt_runtime_tracker *runtime, __u64 epoch);
int nyx_strict_pt_runtime_begin_session(
	struct nyx_strict_pt_runtime_tracker *runtime, __u64 session_id);
int nyx_strict_pt_runtime_clear_session(
	struct nyx_strict_pt_runtime_tracker *runtime, bool ignore_missing);
bool nyx_strict_pt_runtime_counter_inc(__u64 *counter);
void nyx_strict_pt_runtime_clear_pending_locked(
	struct nyx_strict_pt_runtime_tracker *runtime);
void nyx_strict_pt_runtime_invalidate_pending_data_locked(
	struct nyx_strict_pt_runtime_tracker *runtime,
	const struct nyx_strict_pt_data_prepare *prepare, __u64 range_id);
void nyx_strict_pt_runtime_invalidate_pending_range_locked(
	struct nyx_strict_pt_runtime_tracker *runtime, __u64 range_id);

#endif
