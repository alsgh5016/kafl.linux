// SPDX-License-Identifier: GPL-2.0

#include <stddef.h>
#include <linux/ioctl.h>
#include <linux/kvm.h>

#define ABI_ASSERT(_cond, _msg) _Static_assert((_cond), _msg)

ABI_ASSERT(KVM_CAP_NYX_STRICT_PT == 514,
	   "KVM_CAP_NYX_STRICT_PT must stay fixed at 514");

ABI_ASSERT(_IOC_NR(KVM_NYX_STRICT_PT_CONTROL) == 0xfe,
	   "KVM_NYX_STRICT_PT_CONTROL ioctl number must stay fixed at 0xfe");
ABI_ASSERT(_IOC_SIZE(KVM_NYX_STRICT_PT_CONTROL) == 128,
	   "KVM_NYX_STRICT_PT_CONTROL ioctl payload size must stay fixed at 128");
ABI_ASSERT(_IOC_DIR(KVM_NYX_STRICT_PT_CONTROL) == (_IOC_READ | _IOC_WRITE),
	   "KVM_NYX_STRICT_PT_CONTROL ioctl direction must be read|write");

ABI_ASSERT(KVM_EXIT_KAFL_STRICT_PT == 145,
	   "KVM_EXIT_KAFL_STRICT_PT must stay fixed at 145");
ABI_ASSERT(KVM_EXIT_KAFL_WTE == 142,
	   "KVM_EXIT_KAFL_WTE must remain 142");
ABI_ASSERT(KVM_EXIT_KAFL_WTE_SETUP == 143,
	   "KVM_EXIT_KAFL_WTE_SETUP must remain 143");
ABI_ASSERT(KVM_EXIT_KAFL_NYX_HOOK == 144,
	   "KVM_EXIT_KAFL_NYX_HOOK must remain 144");

ABI_ASSERT(_IOC_NR(KVM_NYX_WTE_ENABLE) == 0xf2,
	   "KVM_NYX_WTE_ENABLE must remain in ioctl slot 0xf2");
ABI_ASSERT(_IOC_NR(KVM_NYX_WTE_DISABLE) == 0xf3,
	   "KVM_NYX_WTE_DISABLE must remain in ioctl slot 0xf3");
ABI_ASSERT(_IOC_NR(KVM_NYX_WTE_SET_NX) == 0xf4,
	   "KVM_NYX_WTE_SET_NX must remain in ioctl slot 0xf4");
ABI_ASSERT(_IOC_NR(KVM_NYX_WTE_CLEAR_NX) == 0xf5,
	   "KVM_NYX_WTE_CLEAR_NX must remain in ioctl slot 0xf5");
ABI_ASSERT(_IOC_NR(KVM_NYX_WTE_SET_CR3) == 0xf6,
	   "KVM_NYX_WTE_SET_CR3 must remain in ioctl slot 0xf6");
ABI_ASSERT(_IOC_NR(KVM_NYX_WTE_SET_WP) == 0xf7,
	   "KVM_NYX_WTE_SET_WP must remain in ioctl slot 0xf7");
ABI_ASSERT(_IOC_NR(KVM_NYX_WTE_CLEAR_WP) == 0xf8,
	   "KVM_NYX_WTE_CLEAR_WP must remain in ioctl slot 0xf8");
ABI_ASSERT(_IOC_NR(KVM_NYX_HOOK_ADD) == 0xf9,
	   "KVM_NYX_HOOK_ADD must remain in ioctl slot 0xf9");
ABI_ASSERT(_IOC_NR(KVM_NYX_HOOK_REMOVE) == 0xfa,
	   "KVM_NYX_HOOK_REMOVE must remain in ioctl slot 0xfa");
ABI_ASSERT(_IOC_NR(KVM_NYX_HOOK_CLEAR) == 0xfb,
	   "KVM_NYX_HOOK_CLEAR must remain in ioctl slot 0xfb");
ABI_ASSERT(_IOC_NR(KVM_NYX_DYN_RANGE_ADD) == 0xfc,
	   "KVM_NYX_DYN_RANGE_ADD must remain in ioctl slot 0xfc");
ABI_ASSERT(_IOC_NR(KVM_NYX_DYN_RANGE_CLEAR) == 0xfd,
	   "KVM_NYX_DYN_RANGE_CLEAR must remain in ioctl slot 0xfd");

ABI_ASSERT(KVM_NYX_STRICT_PT_ABI_VERSION_1 == 1,
	   "KVM_NYX_STRICT_PT_ABI_VERSION_1 must stay fixed at 1");
ABI_ASSERT(KVM_NYX_STRICT_PT_CONTROL_SIZE == 128,
	   "KVM_NYX_STRICT_PT_CONTROL_SIZE must stay fixed at 128");

ABI_ASSERT(KVM_NYX_STRICT_PT_QUERY == 0,
	   "KVM_NYX_STRICT_PT_QUERY command value must stay fixed at 0");
ABI_ASSERT(KVM_NYX_STRICT_PT_ENABLE == 1,
	   "KVM_NYX_STRICT_PT_ENABLE command value must stay fixed at 1");
ABI_ASSERT(KVM_NYX_STRICT_PT_DISABLE == 2,
	   "KVM_NYX_STRICT_PT_DISABLE command value must stay fixed at 2");
ABI_ASSERT(KVM_NYX_STRICT_PT_RESET == 3,
	   "KVM_NYX_STRICT_PT_RESET command value must stay fixed at 3");
ABI_ASSERT(KVM_NYX_STRICT_PT_RANGE_ADD == 4,
	   "KVM_NYX_STRICT_PT_RANGE_ADD command value must stay fixed at 4");
ABI_ASSERT(KVM_NYX_STRICT_PT_RANGE_REMOVE == 5,
	   "KVM_NYX_STRICT_PT_RANGE_REMOVE command value must stay fixed at 5");
ABI_ASSERT(KVM_NYX_STRICT_PT_ACK == 6,
	   "KVM_NYX_STRICT_PT_ACK command value must stay fixed at 6");
ABI_ASSERT(KVM_NYX_STRICT_PT_GET_STATUS == 7,
	   "KVM_NYX_STRICT_PT_GET_STATUS command value must stay fixed at 7");

ABI_ASSERT(KVM_NYX_STRICT_PT_DISABLED == 0,
	   "KVM_NYX_STRICT_PT_DISABLED state value must stay fixed at 0");
ABI_ASSERT(KVM_NYX_STRICT_PT_ENABLED == 1,
	   "KVM_NYX_STRICT_PT_ENABLED state value must stay fixed at 1");
ABI_ASSERT(KVM_NYX_STRICT_PT_BROKEN == 2,
	   "KVM_NYX_STRICT_PT_BROKEN state value must stay fixed at 2");

ABI_ASSERT(KVM_NYX_STRICT_PT_FEAT_CPU_PT_WRITE_TRACKING == (1ULL << 0),
	   "KVM_NYX_STRICT_PT_FEAT_CPU_PT_WRITE_TRACKING must stay bit 0");
ABI_ASSERT(KVM_NYX_STRICT_PT_FEAT_ROOT_LOCAL_EPT == (1ULL << 1),
	   "KVM_NYX_STRICT_PT_FEAT_ROOT_LOCAL_EPT must stay bit 1");
ABI_ASSERT(KVM_NYX_STRICT_PT_FEAT_GENERATION_ACK == (1ULL << 2),
	   "KVM_NYX_STRICT_PT_FEAT_GENERATION_ACK must stay bit 2");
ABI_ASSERT(KVM_NYX_STRICT_PT_FEAT_HUGE_GUEST_LEAVES == (1ULL << 3),
	   "KVM_NYX_STRICT_PT_FEAT_HUGE_GUEST_LEAVES must stay bit 3");
ABI_ASSERT(KVM_NYX_STRICT_PT_FEAT_RESET == (1ULL << 4),
	   "KVM_NYX_STRICT_PT_FEAT_RESET must stay bit 4");

ABI_ASSERT(KVM_NYX_STRICT_PT_EXIT_FIRST_EXEC == (1U << 0),
	   "KVM_NYX_STRICT_PT_EXIT_FIRST_EXEC must stay bit 0");

ABI_ASSERT(sizeof(struct kvm_nyx_strict_pt_query) == 112,
	   "struct kvm_nyx_strict_pt_query must stay 112 bytes");
ABI_ASSERT(sizeof(struct kvm_nyx_strict_pt_enable) == 112,
	   "struct kvm_nyx_strict_pt_enable must stay 112 bytes");
ABI_ASSERT(sizeof(struct kvm_nyx_strict_pt_reset) == 112,
	   "struct kvm_nyx_strict_pt_reset must stay 112 bytes");
ABI_ASSERT(sizeof(struct kvm_nyx_strict_pt_range_add) == 112,
	   "struct kvm_nyx_strict_pt_range_add must stay 112 bytes");
ABI_ASSERT(sizeof(struct kvm_nyx_strict_pt_range_remove) == 112,
	   "struct kvm_nyx_strict_pt_range_remove must stay 112 bytes");
ABI_ASSERT(sizeof(struct kvm_nyx_strict_pt_ack) == 112,
	   "struct kvm_nyx_strict_pt_ack must stay 112 bytes");
ABI_ASSERT(sizeof(struct kvm_nyx_strict_pt_status) == 112,
	   "struct kvm_nyx_strict_pt_status must stay 112 bytes");

ABI_ASSERT(sizeof(struct kvm_nyx_strict_pt_control) == 128,
	   "struct kvm_nyx_strict_pt_control must stay 128 bytes");
ABI_ASSERT(_Alignof(struct kvm_nyx_strict_pt_control) == 8,
	   "struct kvm_nyx_strict_pt_control must stay 8-byte aligned");
ABI_ASSERT(offsetof(struct kvm_nyx_strict_pt_control, version) == 0,
	   "struct kvm_nyx_strict_pt_control version must stay at offset 0");
ABI_ASSERT(offsetof(struct kvm_nyx_strict_pt_control, command) == 2,
	   "struct kvm_nyx_strict_pt_control command must stay at offset 2");
ABI_ASSERT(offsetof(struct kvm_nyx_strict_pt_control, flags) == 4,
	   "struct kvm_nyx_strict_pt_control flags must stay at offset 4");
ABI_ASSERT(offsetof(struct kvm_nyx_strict_pt_control, size) == 8,
	   "struct kvm_nyx_strict_pt_control size must stay at offset 8");
ABI_ASSERT(offsetof(struct kvm_nyx_strict_pt_control, reserved0) == 12,
	   "struct kvm_nyx_strict_pt_control reserved0 must stay at offset 12");
ABI_ASSERT(offsetof(struct kvm_nyx_strict_pt_control, u) == 16,
	   "struct kvm_nyx_strict_pt_control union payload must stay at offset 16");
ABI_ASSERT(sizeof(((struct kvm_nyx_strict_pt_control *)0)->u.reserved) == 112,
	   "struct kvm_nyx_strict_pt_control raw payload reserve must stay 112 bytes");

ABI_ASSERT(offsetof(struct kvm_nyx_strict_pt_query, features) == 0,
	   "struct kvm_nyx_strict_pt_query features must stay at offset 0");
ABI_ASSERT(offsetof(struct kvm_nyx_strict_pt_query, abi_min_version) == 8,
	   "struct kvm_nyx_strict_pt_query abi_min_version must stay at offset 8");
ABI_ASSERT(offsetof(struct kvm_nyx_strict_pt_query, abi_max_version) == 12,
	   "struct kvm_nyx_strict_pt_query abi_max_version must stay at offset 12");
ABI_ASSERT(offsetof(struct kvm_nyx_strict_pt_query, max_ranges) == 16,
	   "struct kvm_nyx_strict_pt_query max_ranges must stay at offset 16");
ABI_ASSERT(offsetof(struct kvm_nyx_strict_pt_query, max_pages_per_range) == 20,
	   "struct kvm_nyx_strict_pt_query max_pages_per_range must stay at offset 20");
ABI_ASSERT(offsetof(struct kvm_nyx_strict_pt_query, max_vcpus) == 24,
	   "struct kvm_nyx_strict_pt_query max_vcpus must stay at offset 24");
ABI_ASSERT(offsetof(struct kvm_nyx_strict_pt_query, exit_reason) == 28,
	   "struct kvm_nyx_strict_pt_query exit_reason must stay at offset 28");
ABI_ASSERT(offsetof(struct kvm_nyx_strict_pt_query, reserved) == 32,
	   "struct kvm_nyx_strict_pt_query reserved must stay at offset 32");

ABI_ASSERT(offsetof(struct kvm_nyx_strict_pt_enable, target_cr3) == 0,
	   "struct kvm_nyx_strict_pt_enable target_cr3 must stay at offset 0");
ABI_ASSERT(offsetof(struct kvm_nyx_strict_pt_enable, session_id) == 8,
	   "struct kvm_nyx_strict_pt_enable session_id must stay at offset 8");
ABI_ASSERT(offsetof(struct kvm_nyx_strict_pt_enable, reserved) == 16,
	   "struct kvm_nyx_strict_pt_enable reserved must stay at offset 16");

ABI_ASSERT(offsetof(struct kvm_nyx_strict_pt_reset, session_id) == 0,
	   "struct kvm_nyx_strict_pt_reset session_id must stay at offset 0");
ABI_ASSERT(offsetof(struct kvm_nyx_strict_pt_reset, new_session_id) == 8,
	   "struct kvm_nyx_strict_pt_reset new_session_id must stay at offset 8");
ABI_ASSERT(offsetof(struct kvm_nyx_strict_pt_reset, reserved) == 16,
	   "struct kvm_nyx_strict_pt_reset reserved must stay at offset 16");

ABI_ASSERT(offsetof(struct kvm_nyx_strict_pt_range_add, session_id) == 0,
	   "struct kvm_nyx_strict_pt_range_add session_id must stay at offset 0");
ABI_ASSERT(offsetof(struct kvm_nyx_strict_pt_range_add, gva_start) == 8,
	   "struct kvm_nyx_strict_pt_range_add gva_start must stay at offset 8");
ABI_ASSERT(offsetof(struct kvm_nyx_strict_pt_range_add, gva_end) == 16,
	   "struct kvm_nyx_strict_pt_range_add gva_end must stay at offset 16");
ABI_ASSERT(offsetof(struct kvm_nyx_strict_pt_range_add, range_id) == 24,
	   "struct kvm_nyx_strict_pt_range_add range_id must stay at offset 24");
ABI_ASSERT(offsetof(struct kvm_nyx_strict_pt_range_add, reserved) == 32,
	   "struct kvm_nyx_strict_pt_range_add reserved must stay at offset 32");

ABI_ASSERT(offsetof(struct kvm_nyx_strict_pt_range_remove, session_id) == 0,
	   "struct kvm_nyx_strict_pt_range_remove session_id must stay at offset 0");
ABI_ASSERT(offsetof(struct kvm_nyx_strict_pt_range_remove, range_id) == 8,
	   "struct kvm_nyx_strict_pt_range_remove range_id must stay at offset 8");
ABI_ASSERT(offsetof(struct kvm_nyx_strict_pt_range_remove, reserved) == 16,
	   "struct kvm_nyx_strict_pt_range_remove reserved must stay at offset 16");

ABI_ASSERT(offsetof(struct kvm_nyx_strict_pt_ack, session_id) == 0,
	   "struct kvm_nyx_strict_pt_ack session_id must stay at offset 0");
ABI_ASSERT(offsetof(struct kvm_nyx_strict_pt_ack, range_id) == 8,
	   "struct kvm_nyx_strict_pt_ack range_id must stay at offset 8");
ABI_ASSERT(offsetof(struct kvm_nyx_strict_pt_ack, generation) == 16,
	   "struct kvm_nyx_strict_pt_ack generation must stay at offset 16");
ABI_ASSERT(offsetof(struct kvm_nyx_strict_pt_ack, page_index) == 24,
	   "struct kvm_nyx_strict_pt_ack page_index must stay at offset 24");
ABI_ASSERT(offsetof(struct kvm_nyx_strict_pt_ack, reserved0) == 28,
	   "struct kvm_nyx_strict_pt_ack reserved0 must stay at offset 28");
ABI_ASSERT(offsetof(struct kvm_nyx_strict_pt_ack, reserved) == 32,
	   "struct kvm_nyx_strict_pt_ack reserved must stay at offset 32");

ABI_ASSERT(offsetof(struct kvm_nyx_strict_pt_status, session_id) == 0,
	   "struct kvm_nyx_strict_pt_status session_id must stay at offset 0");
ABI_ASSERT(offsetof(struct kvm_nyx_strict_pt_status, next_generation) == 8,
	   "struct kvm_nyx_strict_pt_status next_generation must stay at offset 8");
ABI_ASSERT(offsetof(struct kvm_nyx_strict_pt_status, state) == 16,
	   "struct kvm_nyx_strict_pt_status state must stay at offset 16");
ABI_ASSERT(offsetof(struct kvm_nyx_strict_pt_status, active_ranges) == 20,
	   "struct kvm_nyx_strict_pt_status active_ranges must stay at offset 20");
ABI_ASSERT(offsetof(struct kvm_nyx_strict_pt_status, vcpu_count) == 24,
	   "struct kvm_nyx_strict_pt_status vcpu_count must stay at offset 24");
ABI_ASSERT(offsetof(struct kvm_nyx_strict_pt_status, reserved0) == 28,
	   "struct kvm_nyx_strict_pt_status reserved0 must stay at offset 28");
ABI_ASSERT(offsetof(struct kvm_nyx_strict_pt_status, ranges_added) == 32,
	   "struct kvm_nyx_strict_pt_status ranges_added must stay at offset 32");
ABI_ASSERT(offsetof(struct kvm_nyx_strict_pt_status, fail_closed) == 104,
	   "struct kvm_nyx_strict_pt_status fail_closed must stay at offset 104");

ABI_ASSERT(sizeof(struct kvm_nyx_strict_pt_exit) == 96,
	   "struct kvm_nyx_strict_pt_exit must stay 96 bytes");
ABI_ASSERT(offsetof(struct kvm_nyx_strict_pt_exit, version) == 0,
	   "struct kvm_nyx_strict_pt_exit version must stay at offset 0");
ABI_ASSERT(offsetof(struct kvm_nyx_strict_pt_exit, reserved0) == 2,
	   "struct kvm_nyx_strict_pt_exit reserved0 must stay at offset 2");
ABI_ASSERT(offsetof(struct kvm_nyx_strict_pt_exit, flags) == 4,
	   "struct kvm_nyx_strict_pt_exit flags must stay at offset 4");
ABI_ASSERT(offsetof(struct kvm_nyx_strict_pt_exit, session_id) == 8,
	   "struct kvm_nyx_strict_pt_exit session_id must stay at offset 8");
ABI_ASSERT(offsetof(struct kvm_nyx_strict_pt_exit, range_id) == 16,
	   "struct kvm_nyx_strict_pt_exit range_id must stay at offset 16");
ABI_ASSERT(offsetof(struct kvm_nyx_strict_pt_exit, generation) == 24,
	   "struct kvm_nyx_strict_pt_exit generation must stay at offset 24");
ABI_ASSERT(offsetof(struct kvm_nyx_strict_pt_exit, gva) == 32,
	   "struct kvm_nyx_strict_pt_exit gva must stay at offset 32");
ABI_ASSERT(offsetof(struct kvm_nyx_strict_pt_exit, gpa) == 40,
	   "struct kvm_nyx_strict_pt_exit gpa must stay at offset 40");
ABI_ASSERT(offsetof(struct kvm_nyx_strict_pt_exit, rip) == 48,
	   "struct kvm_nyx_strict_pt_exit rip must stay at offset 48");
ABI_ASSERT(offsetof(struct kvm_nyx_strict_pt_exit, cr3) == 56,
	   "struct kvm_nyx_strict_pt_exit cr3 must stay at offset 56");
ABI_ASSERT(offsetof(struct kvm_nyx_strict_pt_exit, page_index) == 64,
	   "struct kvm_nyx_strict_pt_exit page_index must stay at offset 64");
ABI_ASSERT(offsetof(struct kvm_nyx_strict_pt_exit, reserved1) == 68,
	   "struct kvm_nyx_strict_pt_exit reserved1 must stay at offset 68");
ABI_ASSERT(offsetof(struct kvm_nyx_strict_pt_exit, reserved) == 72,
	   "struct kvm_nyx_strict_pt_exit reserved must stay at offset 72");

ABI_ASSERT(sizeof(((struct kvm_run *)0)->kafl_strict_pt) == 96,
	   "struct kvm_run must expose 96-byte kafl_strict_pt exit payload");

int main(void)
{
	return 0;
}
