/* SPDX-License-Identifier: GPL-2.0 */
/*
 * KVM Nyx in-kernel API hook table.
 *
 * Filters EPT exec violations on user-registered hook pages: only
 * matching RIPs exit to userspace (QEMU); non-matching instructions
 * on the same page are stepped over in-kernel via MTF without
 * userspace round-trip.
 */
#ifndef __KVM_X86_NYX_HOOK_H
#define __KVM_X86_NYX_HOOK_H

#include <linux/kvm_host.h>

#ifdef CONFIG_KVM_NYX

/* Match a guest RIP against the registered hook list.
 * Returns true if matched; *hook_id_out is set to the hook id. */
bool nyx_hook_match(struct kvm *kvm, u64 rip, u64 *hook_id_out);

/* Returns true if any registered hook RIP falls within the given GFN. */
bool nyx_hook_page_has_any(struct kvm *kvm, gfn_t gfn);

/* Hook table management (called from x86.c ioctl dispatch). */
int  nyx_hook_add(struct kvm *kvm, u64 rip, u64 gfn, u64 hook_id);
int  nyx_hook_remove(struct kvm *kvm, u64 rip);
void nyx_hook_clear(struct kvm *kvm);

/* In-kernel single-step over a non-matching instruction on a hook page.
 * Clears NX on the SPTE for one instruction and arms MTF.
 * The MTF handler calls nyx_step_over_complete() to re-NX the page. */
int  nyx_step_over_begin(struct kvm_vcpu *vcpu, gfn_t gfn);

/* Called from handle_monitor_trap when nyx_step_active is set.
 * Re-NX the saved GFN, disarm MTF, return 1 to resume guest. */
int  nyx_step_over_complete(struct kvm_vcpu *vcpu);

#endif /* CONFIG_KVM_NYX */
#endif /* __KVM_X86_NYX_HOOK_H */
