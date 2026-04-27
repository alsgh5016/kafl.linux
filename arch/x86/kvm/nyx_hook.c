// SPDX-License-Identifier: GPL-2.0
/*
 * KVM Nyx in-kernel API hook table.
 *
 * Used to filter EPT exec violations on user-registered hook pages so that
 * only matching RIPs cause a userspace exit; non-matching instructions on
 * the same page are stepped over in-kernel via MTF.
 */

#include <linux/kvm_host.h>
#include <linux/spinlock.h>
#include <linux/printk.h>
#include <linux/errno.h>
#include <linux/module.h>

#include "nyx_hook.h"
#include "mmu/mmu_internal.h"

#ifdef CONFIG_KVM_NYX

bool nyx_hook_match(struct kvm *kvm, u64 rip, u64 *hook_id_out)
{
	unsigned long flags;
	int i;
	bool matched = false;

	spin_lock_irqsave(&kvm->arch.nyx_hook_lock, flags);
	for (i = 0; i < kvm->arch.nyx_hook_count; i++) {
		if (kvm->arch.nyx_hooks[i].rip == rip) {
			if (hook_id_out)
				*hook_id_out = kvm->arch.nyx_hooks[i].hook_id;
			matched = true;
			break;
		}
	}
	spin_unlock_irqrestore(&kvm->arch.nyx_hook_lock, flags);
	return matched;
}
EXPORT_SYMBOL_GPL(nyx_hook_match);

bool nyx_hook_page_has_any(struct kvm *kvm, gfn_t gfn)
{
	unsigned long flags;
	int i;
	bool has = false;

	spin_lock_irqsave(&kvm->arch.nyx_hook_lock, flags);
	for (i = 0; i < kvm->arch.nyx_hook_count; i++) {
		if ((kvm->arch.nyx_hooks[i].rip >> PAGE_SHIFT) == gfn) {
			has = true;
			break;
		}
	}
	spin_unlock_irqrestore(&kvm->arch.nyx_hook_lock, flags);
	return has;
}
EXPORT_SYMBOL_GPL(nyx_hook_page_has_any);

int nyx_hook_add(struct kvm *kvm, u64 rip, u64 hook_id)
{
	unsigned long flags;
	int i, ret = 0;

	spin_lock_irqsave(&kvm->arch.nyx_hook_lock, flags);
	/* Replace existing entry if same RIP already registered. */
	for (i = 0; i < kvm->arch.nyx_hook_count; i++) {
		if (kvm->arch.nyx_hooks[i].rip == rip) {
			kvm->arch.nyx_hooks[i].hook_id = hook_id;
			goto out;
		}
	}
	if (kvm->arch.nyx_hook_count >=
	    (int)ARRAY_SIZE(kvm->arch.nyx_hooks)) {
		ret = -ENOSPC;
		goto out;
	}
	kvm->arch.nyx_hooks[kvm->arch.nyx_hook_count].rip = rip;
	kvm->arch.nyx_hooks[kvm->arch.nyx_hook_count].hook_id = hook_id;
	kvm->arch.nyx_hook_count++;
out:
	spin_unlock_irqrestore(&kvm->arch.nyx_hook_lock, flags);
	return ret;
}

int nyx_hook_remove(struct kvm *kvm, u64 rip)
{
	unsigned long flags;
	int i, ret = -ENOENT;

	spin_lock_irqsave(&kvm->arch.nyx_hook_lock, flags);
	for (i = 0; i < kvm->arch.nyx_hook_count; i++) {
		if (kvm->arch.nyx_hooks[i].rip == rip) {
			/* Compact by moving the tail entry into this slot. */
			kvm->arch.nyx_hook_count--;
			if (i != kvm->arch.nyx_hook_count) {
				kvm->arch.nyx_hooks[i] =
					kvm->arch.nyx_hooks[kvm->arch.nyx_hook_count];
			}
			ret = 0;
			break;
		}
	}
	spin_unlock_irqrestore(&kvm->arch.nyx_hook_lock, flags);
	return ret;
}

void nyx_hook_clear(struct kvm *kvm)
{
	unsigned long flags;

	spin_lock_irqsave(&kvm->arch.nyx_hook_lock, flags);
	kvm->arch.nyx_hook_count = 0;
	spin_unlock_irqrestore(&kvm->arch.nyx_hook_lock, flags);
}

/*
 * In-kernel step-over: clear NX on the SPTE for one instruction, then
 * arm MTF.  The pre-VMENTER hook in vmx.c sets CPU_BASED_MONITOR_TRAP_FLAG
 * when vcpu->arch.mtf is true.  After the next instruction executes, the
 * MTF VM-exit invokes handle_monitor_trap → nyx_step_over_complete().
 */
int nyx_step_over_begin(struct kvm_vcpu *vcpu, gfn_t gfn)
{
	struct kvm *kvm = vcpu->kvm;
	struct kvm_memory_slot *slot;
	bool flushed = false;

	if (vcpu->arch.nyx_step_active) {
		printk_ratelimited(KERN_WARNING
			"kvm-nyx: step_over_begin called while active "
			"(prev_gfn=0x%llx new_gfn=0x%llx)\n",
			(unsigned long long)vcpu->arch.nyx_step_restore_gfn,
			(unsigned long long)gfn);
		return 1;
	}

	write_lock(&kvm->mmu_lock);
	slot = gfn_to_memslot(kvm, gfn);
	if (slot)
		flushed = kvm_mmu_slot_gfn_clear_nx(kvm, slot, gfn);
	if (flushed)
		kvm_flush_remote_tlbs(kvm);
	write_unlock(&kvm->mmu_lock);

	vcpu->arch.nyx_step_restore_gfn = gfn;
	vcpu->arch.nyx_step_active = true;
	vcpu->arch.mtf = true;

	return 1; /* resume guest, no userspace exit */
}
EXPORT_SYMBOL_GPL(nyx_step_over_begin);

int nyx_step_over_complete(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;
	struct kvm_memory_slot *slot;
	gfn_t gfn = vcpu->arch.nyx_step_restore_gfn;
	bool flushed = false;

	write_lock(&kvm->mmu_lock);
	slot = gfn_to_memslot(kvm, gfn);
	if (slot)
		flushed = kvm_mmu_slot_gfn_set_nx(kvm, slot, gfn);
	if (flushed)
		kvm_flush_remote_tlbs(kvm);
	write_unlock(&kvm->mmu_lock);

	vcpu->arch.mtf = false;
	vcpu->arch.nyx_step_active = false;

	return 1; /* resume guest, no userspace exit */
}
EXPORT_SYMBOL_GPL(nyx_step_over_complete);

#endif /* CONFIG_KVM_NYX */
