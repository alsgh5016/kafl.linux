/* SPDX-License-Identifier: GPL-2.0 */
#ifndef ARCH_X86_KVM_NYX_STRICT_PT_RUNTIME_H
#define ARCH_X86_KVM_NYX_STRICT_PT_RUNTIME_H

#include <linux/types.h>
#include <linux/kvm_types.h>

struct kvm;
struct kvm_vcpu;
struct kvm_nyx_strict_pt_control;
struct nyx_strict_pt_control_context;

struct nyx_strict_pt_runtime_tracker;

int nyx_strict_pt_runtime_create(
	struct kvm *kvm, struct nyx_strict_pt_control_context *control);
void nyx_strict_pt_runtime_destroy(struct kvm *kvm);
void nyx_strict_pt_runtime_operation_lock(struct kvm *kvm);
void nyx_strict_pt_runtime_operation_unlock(struct kvm *kvm);
void nyx_strict_pt_runtime_wait_for_update(struct kvm *kvm);
void nyx_strict_pt_runtime_refresh_status(struct kvm *kvm);
int nyx_strict_pt_runtime_consume_invalidation(struct kvm *kvm);
bool nyx_strict_pt_runtime_data_gfn_needs_nx(struct kvm *kvm, gfn_t gfn);
int nyx_strict_pt_runtime_handle_enable(
	struct kvm *kvm, struct kvm_nyx_strict_pt_control *control);
int nyx_strict_pt_runtime_handle_reset(
	struct kvm *kvm, struct kvm_nyx_strict_pt_control *control);
int nyx_strict_pt_runtime_handle_disable(struct kvm *kvm);
int nyx_strict_pt_runtime_handle_range_add(
	struct kvm *kvm, struct kvm_nyx_strict_pt_control *control);
int nyx_strict_pt_runtime_handle_range_remove(
	struct kvm *kvm, struct kvm_nyx_strict_pt_control *control);
int nyx_strict_pt_runtime_handle_rewalk(struct kvm_vcpu *vcpu);
int nyx_strict_pt_runtime_replay_pending(struct kvm_vcpu *vcpu);
int nyx_strict_pt_runtime_handle_exec_violation(struct kvm_vcpu *vcpu,
	__u64 gva, gpa_t gpa, __u64 rip, __u64 cr3);
int nyx_strict_pt_runtime_handle_ack(
	struct kvm *kvm, struct kvm_nyx_strict_pt_control *control);
void nyx_strict_pt_runtime_handle_copyout_fault(
	struct kvm *kvm, const struct kvm_nyx_strict_pt_control *control);

#endif
