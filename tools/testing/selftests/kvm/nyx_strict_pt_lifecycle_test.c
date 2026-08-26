// SPDX-License-Identifier: GPL-2.0

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <linux/kvm.h>

#include "nyx_strict_pt_policy.h"

#define EXPECT_TRUE(cond)                                                        \
	do {                                                                      \
		if (!(cond)) {                                                      \
			fprintf(stderr, "FAIL:%d: %s\n", __LINE__, #cond);          \
			exit(1);                                                     \
		}                                                                 \
	} while (0)

#define EXPECT_U64(actual, expected)                                             \
	do {                                                                      \
		uint64_t _actual = (actual);                                        \
		uint64_t _expected = (expected);                                    \
		if (_actual != _expected) {                                         \
			fprintf(stderr,                                               \
				"FAIL:%d: %s=0x%llx expected 0x%llx\n",              \
				__LINE__, #actual,                                       \
				(unsigned long long)_actual,                            \
				(unsigned long long)_expected);                         \
			exit(1);                                                     \
		}                                                                 \
	} while (0)

#define EXPECT_U32(actual, expected) EXPECT_U64((actual), (expected))

#define EXPECT_RESULT(actual, expected) EXPECT_U32((actual), (expected))

static void expect_envelope_result(uint16_t version, uint16_t command,
				   uint32_t flags, uint32_t size,
				   uint32_t reserved0,
				   bool payload_reserved_zero,
				   enum nyx_strict_pt_policy_result expected)
{
	struct nyx_strict_pt_policy_envelope envelope = {
		.version = version,
		.command = command,
		.flags = flags,
		.size = size,
		.reserved0 = reserved0,
	};

	EXPECT_RESULT(nyx_strict_pt_policy_validate_envelope(&envelope,
			payload_reserved_zero), expected);
}

int main(void)
{
	struct nyx_strict_pt_policy_state state = { 0 };
	uint64_t raw_cr3 = 0x8000001234567abcULL;
	uint64_t normalized_cr3 = 0x0000001234567000ULL;
	uint64_t different_normalized_cr3 = 0x0000002234567000ULL;

	EXPECT_TRUE(nyx_strict_pt_policy_vcpu_create_allowed(&state));
	EXPECT_TRUE(!nyx_strict_pt_policy_is_target_root(&state, normalized_cr3,
		false, false, true));

	expect_envelope_result(KVM_NYX_STRICT_PT_ABI_VERSION_1,
		KVM_NYX_STRICT_PT_QUERY, 0, KVM_NYX_STRICT_PT_CONTROL_SIZE, 0,
		true, NYX_STRICT_PT_POLICY_OK);
	expect_envelope_result(KVM_NYX_STRICT_PT_ABI_VERSION_1 + 1,
		KVM_NYX_STRICT_PT_QUERY, 0, KVM_NYX_STRICT_PT_CONTROL_SIZE, 0,
		true, NYX_STRICT_PT_POLICY_PROTOCOL);
	expect_envelope_result(KVM_NYX_STRICT_PT_ABI_VERSION_1,
		KVM_NYX_STRICT_PT_QUERY, 0, KVM_NYX_STRICT_PT_CONTROL_SIZE - 8, 0,
		true, NYX_STRICT_PT_POLICY_INVALID);
	expect_envelope_result(KVM_NYX_STRICT_PT_ABI_VERSION_1,
		KVM_NYX_STRICT_PT_QUERY, 1, KVM_NYX_STRICT_PT_CONTROL_SIZE, 0,
		true, NYX_STRICT_PT_POLICY_INVALID);
	expect_envelope_result(KVM_NYX_STRICT_PT_ABI_VERSION_1,
		KVM_NYX_STRICT_PT_QUERY, 0, KVM_NYX_STRICT_PT_CONTROL_SIZE, 1,
		true, NYX_STRICT_PT_POLICY_INVALID);
	expect_envelope_result(KVM_NYX_STRICT_PT_ABI_VERSION_1,
		KVM_NYX_STRICT_PT_QUERY, 0, KVM_NYX_STRICT_PT_CONTROL_SIZE, 0,
		false, NYX_STRICT_PT_POLICY_INVALID);
	expect_envelope_result(KVM_NYX_STRICT_PT_ABI_VERSION_1, 0xffff, 0,
		KVM_NYX_STRICT_PT_CONTROL_SIZE, 0, true,
		NYX_STRICT_PT_POLICY_INVALID);

	EXPECT_U64(nyx_strict_pt_policy_normalize_cr3(raw_cr3), normalized_cr3);

	EXPECT_RESULT(nyx_strict_pt_policy_enable(&state, 0, true, raw_cr3, 1),
		NYX_STRICT_PT_POLICY_UNSUPPORTED);
	EXPECT_U32(state.state, KVM_NYX_STRICT_PT_DISABLED);
	EXPECT_RESULT(nyx_strict_pt_policy_enable(&state, 2, true, raw_cr3, 1),
		NYX_STRICT_PT_POLICY_UNSUPPORTED);
	EXPECT_RESULT(nyx_strict_pt_policy_enable(&state, 1, false, raw_cr3, 1),
		NYX_STRICT_PT_POLICY_UNSUPPORTED);
	EXPECT_RESULT(nyx_strict_pt_policy_enable(&state, 1, true, raw_cr3, 0),
		NYX_STRICT_PT_POLICY_INVALID);

	EXPECT_RESULT(nyx_strict_pt_policy_enable(&state, 1, true, raw_cr3, 0x11),
		NYX_STRICT_PT_POLICY_OK);
	EXPECT_U32(state.state, KVM_NYX_STRICT_PT_ENABLED);
	EXPECT_U64(state.target_cr3, normalized_cr3);
	EXPECT_U64(state.session_id, 0x11);
	EXPECT_TRUE(!nyx_strict_pt_policy_vcpu_create_allowed(&state));
	EXPECT_TRUE(nyx_strict_pt_policy_is_target_root(&state, normalized_cr3,
		false, false, true));
	EXPECT_TRUE(nyx_strict_pt_policy_is_target_root(&state, raw_cr3, false,
		false, true));
	EXPECT_TRUE(!nyx_strict_pt_policy_is_target_root(&state,
		different_normalized_cr3, false, false, true));
	EXPECT_TRUE(!nyx_strict_pt_policy_is_target_root(&state, normalized_cr3,
		true, false, true));
	EXPECT_TRUE(!nyx_strict_pt_policy_is_target_root(&state, normalized_cr3,
		false, true, true));
	EXPECT_TRUE(!nyx_strict_pt_policy_is_target_root(&state, normalized_cr3,
		false, false, false));

	EXPECT_RESULT(nyx_strict_pt_policy_enable(&state, 1, true, raw_cr3, 0x22),
		NYX_STRICT_PT_POLICY_BUSY);
	EXPECT_U64(state.session_id, 0x11);

	state.active_ranges = 3;
	state.pending_exit = 1;
	EXPECT_RESULT(nyx_strict_pt_policy_reset(&state, 0x99, 0x22),
		NYX_STRICT_PT_POLICY_STALE);
	EXPECT_U32(state.state, KVM_NYX_STRICT_PT_ENABLED);
	EXPECT_U64(state.session_id, 0x11);
	EXPECT_U32(state.active_ranges, 3);
	EXPECT_U32(state.pending_exit, 1);
	EXPECT_U64(state.target_cr3, normalized_cr3);

	EXPECT_RESULT(nyx_strict_pt_policy_reset(&state, 0x11, 0x22),
		NYX_STRICT_PT_POLICY_OK);
	EXPECT_U32(state.state, KVM_NYX_STRICT_PT_ENABLED);
	EXPECT_U64(state.session_id, 0x22);
	EXPECT_U32(state.active_ranges, 0);
	EXPECT_U32(state.pending_exit, 0);
	EXPECT_TRUE(nyx_strict_pt_policy_is_target_root(&state, normalized_cr3,
		false, false, true));
	EXPECT_RESULT(nyx_strict_pt_policy_require_session(&state, 0x11),
		NYX_STRICT_PT_POLICY_STALE);
	EXPECT_RESULT(nyx_strict_pt_policy_require_session(&state, 0x22),
		NYX_STRICT_PT_POLICY_OK);

	state.active_ranges = 1;
	state.pending_exit = 1;
	EXPECT_RESULT(nyx_strict_pt_policy_fail_closed(&state),
		NYX_STRICT_PT_POLICY_BROKEN);
	EXPECT_U32(state.state, KVM_NYX_STRICT_PT_BROKEN);
	EXPECT_TRUE(!nyx_strict_pt_policy_is_target_root(&state, normalized_cr3,
		false, false, true));
	EXPECT_TRUE(nyx_strict_pt_policy_command_allowed(&state,
		KVM_NYX_STRICT_PT_QUERY));
	EXPECT_TRUE(nyx_strict_pt_policy_command_allowed(&state,
		KVM_NYX_STRICT_PT_GET_STATUS));
	EXPECT_TRUE(nyx_strict_pt_policy_command_allowed(&state,
		KVM_NYX_STRICT_PT_DISABLE));
	EXPECT_TRUE(!nyx_strict_pt_policy_command_allowed(&state,
		KVM_NYX_STRICT_PT_ENABLE));
	EXPECT_TRUE(!nyx_strict_pt_policy_command_allowed(&state,
		KVM_NYX_STRICT_PT_RESET));
	EXPECT_TRUE(!nyx_strict_pt_policy_command_allowed(&state,
		KVM_NYX_STRICT_PT_RANGE_ADD));
	EXPECT_RESULT(nyx_strict_pt_policy_require_session(&state, 0x22),
		NYX_STRICT_PT_POLICY_BROKEN);
	EXPECT_RESULT(nyx_strict_pt_policy_enable(&state, 1, true, raw_cr3, 0x33),
		NYX_STRICT_PT_POLICY_BROKEN);
	EXPECT_TRUE(!nyx_strict_pt_policy_vcpu_create_allowed(&state));

	EXPECT_RESULT(nyx_strict_pt_policy_disable(&state),
		NYX_STRICT_PT_POLICY_OK);
	EXPECT_U32(state.state, KVM_NYX_STRICT_PT_DISABLED);
	EXPECT_U64(state.session_id, 0);
	EXPECT_U32(state.active_ranges, 0);
	EXPECT_U32(state.pending_exit, 0);
	EXPECT_U64(state.target_cr3, 0);
	EXPECT_TRUE(!nyx_strict_pt_policy_is_target_root(&state, normalized_cr3,
		false, false, true));
	EXPECT_TRUE(nyx_strict_pt_policy_vcpu_create_allowed(&state));

	printf("nyx_strict_pt_lifecycle_test: ok\n");
	return 0;
}
