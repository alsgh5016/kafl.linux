// SPDX-License-Identifier: GPL-2.0

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <linux/kvm.h>

#include "nyx_strict_pt_control.h"

#define EXPECT_TRUE(cond)                                                        \
	do {                                                                      \
		if (!(cond)) {                                                      \
			fprintf(stderr, "FAIL:%d: %s\n", __LINE__, #cond);          \
			exit(1);                                                     \
		}                                                                 \
	} while (0)

#define EXPECT_U64(actual, expected)                                             \
	do {                                                                      \
		uint64_t _actual = (uint64_t)(actual);                               \
		uint64_t _expected = (uint64_t)(expected);                           \
		if (_actual != _expected) {                                         \
			fprintf(stderr,                                               \
				"FAIL:%d: %s=0x%llx expected 0x%llx\n",              \
				__LINE__, #actual,                                       \
				(unsigned long long)_actual,                            \
				(unsigned long long)_expected);                         \
			exit(1);                                                     \
		}                                                                 \
	} while (0)

#define EXPECT_S32(actual, expected)                                             \
	do {                                                                      \
		int _actual = (actual);                                              \
		int _expected = (expected);                                          \
		if (_actual != _expected) {                                         \
			fprintf(stderr,                                               \
				"FAIL:%d: %s=%d expected %d\n",                        \
				__LINE__, #actual, _actual, _expected);                  \
			exit(1);                                                     \
		}                                                                 \
	} while (0)

#define EXPECT_COUNTERS_ZERO(counters)                                           \
	do {                                                                      \
		EXPECT_U64((counters).ranges_added, 0);                            \
		EXPECT_U64((counters).ranges_removed, 0);                          \
		EXPECT_U64((counters).resets, 0);                                  \
		EXPECT_U64((counters).pt_write_events, 0);                         \
		EXPECT_U64((counters).mapping_changes, 0);                         \
		EXPECT_U64((counters).nx_arms, 0);                                 \
		EXPECT_U64((counters).strict_exits, 0);                            \
		EXPECT_U64((counters).acks, 0);                                    \
		EXPECT_U64((counters).stale_acks, 0);                              \
		EXPECT_U64((counters).fail_closed, 0);                             \
	} while (0)

#define EXPECT_COUNTERS_MATCH(status, counters)                                   \
	do {                                                                      \
		EXPECT_U64((status).ranges_added, (counters).ranges_added);         \
		EXPECT_U64((status).ranges_removed, (counters).ranges_removed);     \
		EXPECT_U64((status).resets, (counters).resets);                     \
		EXPECT_U64((status).pt_write_events, (counters).pt_write_events);   \
		EXPECT_U64((status).mapping_changes, (counters).mapping_changes);   \
		EXPECT_U64((status).nx_arms, (counters).nx_arms);                   \
		EXPECT_U64((status).strict_exits, (counters).strict_exits);         \
		EXPECT_U64((status).acks, (counters).acks);                         \
		EXPECT_U64((status).stale_acks, (counters).stale_acks);             \
		EXPECT_U64((status).fail_closed, (counters).fail_closed);           \
	} while (0)

#define CONTROL_ASSERT(_cond, _msg) _Static_assert((_cond), _msg)

CONTROL_ASSERT(NYX_STRICT_PT_MAX_RANGES == 64,
	       "NYX_STRICT_PT_MAX_RANGES must stay fixed at 64");
CONTROL_ASSERT(NYX_STRICT_PT_REQUIRED_FEATURES ==
	       (KVM_NYX_STRICT_PT_FEAT_CPU_PT_WRITE_TRACKING |
		KVM_NYX_STRICT_PT_FEAT_ROOT_LOCAL_EPT |
		KVM_NYX_STRICT_PT_FEAT_GENERATION_ACK |
		KVM_NYX_STRICT_PT_FEAT_HUGE_GUEST_LEAVES |
		KVM_NYX_STRICT_PT_FEAT_RESET),
	       "NYX_STRICT_PT_REQUIRED_FEATURES must contain all v1 feature bits");

static struct kvm_nyx_strict_pt_control make_control(__u16 command)
{
	struct kvm_nyx_strict_pt_control control;

	memset(&control, 0, sizeof(control));
	control.version = KVM_NYX_STRICT_PT_ABI_VERSION_1;
	control.command = command;
	control.size = KVM_NYX_STRICT_PT_CONTROL_SIZE;

	return control;
}

static int execute(struct nyx_strict_pt_control_context *context,
		   struct kvm_nyx_strict_pt_control *control,
		   __u32 vcpu_count, __u64 available_features)
{
	return nyx_strict_pt_control_execute(context, control, vcpu_count,
					     available_features);
}

static void expect_query_shape(const struct kvm_nyx_strict_pt_control *control)
{
	EXPECT_U64(control->u.query.features, NYX_STRICT_PT_REQUIRED_FEATURES);
	EXPECT_U64(control->u.query.abi_min_version,
		   KVM_NYX_STRICT_PT_ABI_VERSION_1);
	EXPECT_U64(control->u.query.abi_max_version,
		   KVM_NYX_STRICT_PT_ABI_VERSION_1);
	EXPECT_U64(control->u.query.max_ranges, NYX_STRICT_PT_MAX_RANGES);
	EXPECT_U64(control->u.query.max_pages_per_range, 0);
	EXPECT_U64(control->u.query.max_vcpus, 1);
	EXPECT_U64(control->u.query.exit_reason, KVM_EXIT_KAFL_STRICT_PT);
	for (size_t i = 0; i < sizeof(control->u.query.reserved) /
				 sizeof(control->u.query.reserved[0]); ++i)
		EXPECT_U64(control->u.query.reserved[i], 0);
}

static void expect_status_matches(const struct nyx_strict_pt_control_context *ctx,
				 const struct kvm_nyx_strict_pt_control *control,
				 __u32 vcpu_count)
{
	EXPECT_U64(control->u.status.session_id, ctx->policy.session_id);
	EXPECT_U64(control->u.status.next_generation, ctx->next_generation);
	EXPECT_U64(control->u.status.state, ctx->policy.state);
	EXPECT_U64(control->u.status.active_ranges, ctx->policy.active_ranges);
	EXPECT_U64(control->u.status.vcpu_count, vcpu_count);
	EXPECT_U64(control->u.status.reserved0, 0);
	EXPECT_COUNTERS_MATCH(control->u.status, ctx->counters);
}

int main(void)
{
	struct nyx_strict_pt_control_context ctx = { 0 };
	struct kvm_nyx_strict_pt_control control;
	const __u64 required = NYX_STRICT_PT_REQUIRED_FEATURES;
	const __u64 partial = KVM_NYX_STRICT_PT_FEAT_CPU_PT_WRITE_TRACKING |
		KVM_NYX_STRICT_PT_FEAT_ROOT_LOCAL_EPT;
	const __u64 raw_cr3 = 0x8000001234567abcULL;
	const __u64 normalized_cr3 = 0x0000001234567000ULL;

	EXPECT_U64(ctx.policy.state, KVM_NYX_STRICT_PT_DISABLED);
	EXPECT_U64(ctx.next_session_id, 0);
	EXPECT_U64(ctx.next_generation, 0);
	EXPECT_COUNTERS_ZERO(ctx.counters);

	control = make_control(KVM_NYX_STRICT_PT_QUERY);
	EXPECT_S32(execute(&ctx, &control, 1, required), 0);
	expect_query_shape(&control);
	EXPECT_U64(ctx.policy.state, KVM_NYX_STRICT_PT_DISABLED);
	EXPECT_U64(ctx.policy.session_id, 0);
	EXPECT_U64(ctx.next_session_id, 0);
	EXPECT_COUNTERS_ZERO(ctx.counters);

	control = make_control(KVM_NYX_STRICT_PT_QUERY);
	control.version = KVM_NYX_STRICT_PT_ABI_VERSION_1 + 1;
	EXPECT_S32(execute(&ctx, &control, 1, required), -EPROTONOSUPPORT);

	control = make_control(KVM_NYX_STRICT_PT_QUERY);
	control.flags = 1;
	EXPECT_S32(execute(&ctx, &control, 1, required), -EINVAL);

	control = make_control(KVM_NYX_STRICT_PT_QUERY);
	control.size -= 8;
	EXPECT_S32(execute(&ctx, &control, 1, required), -EINVAL);

	control = make_control(KVM_NYX_STRICT_PT_QUERY);
	control.reserved0 = 1;
	EXPECT_S32(execute(&ctx, &control, 1, required), -EINVAL);

	control = make_control(KVM_NYX_STRICT_PT_QUERY);
	control.u.query.reserved[0] = 1;
	EXPECT_S32(execute(&ctx, &control, 1, required), -EINVAL);

	control = make_control(KVM_NYX_STRICT_PT_QUERY);
	control.u.query.features = 1;
	EXPECT_S32(execute(&ctx, &control, 1, required), -EINVAL);

	control = make_control(KVM_NYX_STRICT_PT_ENABLE);
	control.u.enable.target_cr3 = raw_cr3;
	EXPECT_S32(execute(&ctx, &control, 1, 0), -EOPNOTSUPP);
	EXPECT_U64(ctx.policy.state, KVM_NYX_STRICT_PT_DISABLED);
	EXPECT_U64(ctx.policy.session_id, 0);
	EXPECT_U64(control.u.enable.session_id, 0);

	control = make_control(KVM_NYX_STRICT_PT_ENABLE);
	control.u.enable.target_cr3 = raw_cr3;
	EXPECT_S32(execute(&ctx, &control, 1, partial), -EOPNOTSUPP);
	EXPECT_U64(ctx.policy.session_id, 0);

	control = make_control(KVM_NYX_STRICT_PT_ENABLE);
	control.u.enable.target_cr3 = raw_cr3;
	EXPECT_S32(execute(&ctx, &control, 2, required), -EOPNOTSUPP);
	EXPECT_U64(ctx.policy.session_id, 0);

	control = make_control(KVM_NYX_STRICT_PT_ENABLE);
	control.u.enable.target_cr3 = raw_cr3;
	control.u.enable.session_id = 1;
	EXPECT_S32(execute(&ctx, &control, 1, required), -EINVAL);

	control = make_control(KVM_NYX_STRICT_PT_ENABLE);
	control.u.enable.target_cr3 = raw_cr3;
	control.u.enable.reserved[0] = 1;
	EXPECT_S32(execute(&ctx, &control, 1, required), -EINVAL);

	control = make_control(KVM_NYX_STRICT_PT_DISABLE);
	control.u.reserved[0] = 1;
	EXPECT_S32(execute(&ctx, &control, 1, required), -EINVAL);

	control = make_control(KVM_NYX_STRICT_PT_ENABLE);
	control.u.enable.target_cr3 = raw_cr3;
	EXPECT_S32(execute(&ctx, &control, 1, required), 0);
	EXPECT_U64(control.u.enable.session_id, 1);
	EXPECT_U64(ctx.policy.state, KVM_NYX_STRICT_PT_ENABLED);
	EXPECT_U64(ctx.policy.session_id, 1);
	EXPECT_U64(ctx.policy.target_cr3, normalized_cr3);
	EXPECT_U64(ctx.next_session_id, 2);
	EXPECT_COUNTERS_ZERO(ctx.counters);

	control = make_control(KVM_NYX_STRICT_PT_ENABLE);
	control.u.enable.target_cr3 = raw_cr3;
	EXPECT_S32(execute(&ctx, &control, 1, required), -EBUSY);
	EXPECT_U64(ctx.policy.session_id, 1);
	EXPECT_U64(ctx.next_session_id, 2);

	control = make_control(KVM_NYX_STRICT_PT_GET_STATUS);
	EXPECT_S32(execute(&ctx, &control, 1, required), 0);
	expect_status_matches(&ctx, &control, 1);

	control = make_control(KVM_NYX_STRICT_PT_GET_STATUS);
	control.u.status.session_id = 1;
	EXPECT_S32(execute(&ctx, &control, 1, required), -EINVAL);

	control = make_control(KVM_NYX_STRICT_PT_RESET);
	control.u.reset.session_id = 0x99;
	EXPECT_S32(execute(&ctx, &control, 1, required), -ESTALE);
	EXPECT_U64(ctx.policy.session_id, 1);
	EXPECT_U64(ctx.next_session_id, 2);
	EXPECT_COUNTERS_ZERO(ctx.counters);

	control = make_control(KVM_NYX_STRICT_PT_RESET);
	control.u.reset.session_id = 1;
	control.u.reset.new_session_id = 1;
	EXPECT_S32(execute(&ctx, &control, 1, required), -EINVAL);

	control = make_control(KVM_NYX_STRICT_PT_RANGE_REMOVE);
	control.u.range_remove.session_id = 1;
	control.u.range_remove.range_id = 7;
	control.u.range_remove.reserved[0] = 1;
	EXPECT_S32(execute(&ctx, &control, 1, required), -EINVAL);

	control = make_control(KVM_NYX_STRICT_PT_ACK);
	control.u.ack.session_id = 1;
	control.u.ack.reserved0 = 1;
	EXPECT_S32(execute(&ctx, &control, 1, required), -EINVAL);

	ctx.policy.active_ranges = 4;
	ctx.policy.pending_exit = 1;
	control = make_control(KVM_NYX_STRICT_PT_RESET);
	control.u.reset.session_id = 1;
	EXPECT_S32(execute(&ctx, &control, 1, required), 0);
	EXPECT_U64(control.u.reset.new_session_id, 2);
	EXPECT_U64(ctx.policy.state, KVM_NYX_STRICT_PT_ENABLED);
	EXPECT_U64(ctx.policy.session_id, 2);
	EXPECT_U64(ctx.policy.active_ranges, 0);
	EXPECT_U64(ctx.policy.pending_exit, 0);
	EXPECT_U64(ctx.counters.resets, 1);
	EXPECT_U64(ctx.next_session_id, 3);

	control = make_control(KVM_NYX_STRICT_PT_RANGE_ADD);
	control.u.range_add.session_id = 2;
	control.u.range_add.gva_start = 0x4000;
	control.u.range_add.gva_end = 0x8000;
	control.u.range_add.range_id = 1;
	EXPECT_S32(execute(&ctx, &control, 1, required), -EINVAL);

	control = make_control(KVM_NYX_STRICT_PT_RANGE_ADD);
	control.u.range_add.session_id = 2;
	control.u.range_add.gva_start = 0x4000;
	control.u.range_add.gva_end = 0x8000;
	EXPECT_S32(execute(&ctx, &control, 1, required), -EOPNOTSUPP);
	EXPECT_U64(ctx.policy.session_id, 2);
	EXPECT_U64(ctx.policy.active_ranges, 0);
	EXPECT_U64(ctx.counters.ranges_added, 0);
	EXPECT_U64(ctx.counters.resets, 1);

	nyx_strict_pt_control_fail_closed(&ctx);
	EXPECT_U64(ctx.policy.state, KVM_NYX_STRICT_PT_BROKEN);
	EXPECT_U64(ctx.counters.fail_closed, 1);
	nyx_strict_pt_control_fail_closed(&ctx);
	EXPECT_U64(ctx.counters.fail_closed, 1);

	control = make_control(KVM_NYX_STRICT_PT_QUERY);
	EXPECT_S32(execute(&ctx, &control, 1, required), 0);
	expect_query_shape(&control);

	control = make_control(KVM_NYX_STRICT_PT_GET_STATUS);
	EXPECT_S32(execute(&ctx, &control, 1, required), 0);
	expect_status_matches(&ctx, &control, 1);
	EXPECT_U64(control.u.status.state, KVM_NYX_STRICT_PT_BROKEN);

	control = make_control(KVM_NYX_STRICT_PT_ENABLE);
	control.u.enable.target_cr3 = raw_cr3;
	EXPECT_S32(execute(&ctx, &control, 1, required), -EIO);
	EXPECT_U64(ctx.policy.session_id, 2);
	EXPECT_U64(ctx.next_session_id, 3);

	control = make_control(KVM_NYX_STRICT_PT_DISABLE);
	EXPECT_S32(execute(&ctx, &control, 1, required), 0);
	EXPECT_U64(ctx.policy.state, KVM_NYX_STRICT_PT_DISABLED);
	EXPECT_U64(ctx.policy.session_id, 0);
	EXPECT_U64(ctx.policy.target_cr3, 0);
	EXPECT_U64(ctx.policy.active_ranges, 0);
	EXPECT_U64(ctx.policy.pending_exit, 0);
	EXPECT_U64(ctx.counters.resets, 1);
	EXPECT_U64(ctx.counters.fail_closed, 1);
	EXPECT_U64(ctx.next_session_id, 3);

	control = make_control(KVM_NYX_STRICT_PT_ENABLE);
	control.u.enable.target_cr3 = raw_cr3;
	EXPECT_S32(execute(&ctx, &control, 1, required), 0);
	EXPECT_U64(control.u.enable.session_id, 3);
	EXPECT_U64(ctx.policy.state, KVM_NYX_STRICT_PT_ENABLED);
	EXPECT_U64(ctx.policy.session_id, 3);
	EXPECT_U64(ctx.policy.target_cr3, normalized_cr3);
	EXPECT_U64(ctx.counters.resets, 1);
	EXPECT_U64(ctx.counters.fail_closed, 1);
	EXPECT_U64(ctx.next_session_id, 4);

	{
		struct nyx_strict_pt_control_context copyout_ctx = { 0 };
		struct kvm_nyx_strict_pt_control enable_control;

		enable_control = make_control(KVM_NYX_STRICT_PT_ENABLE);
		enable_control.u.enable.target_cr3 = raw_cr3;
		EXPECT_S32(execute(&copyout_ctx, &enable_control, 1, required), 0);
		control = make_control(KVM_NYX_STRICT_PT_QUERY);
		EXPECT_S32(execute(&copyout_ctx, &control, 1, required), 0);
		EXPECT_TRUE(!nyx_strict_pt_control_copyout_failed(
			&copyout_ctx, &control));
		EXPECT_U64(copyout_ctx.policy.state, KVM_NYX_STRICT_PT_ENABLED);
		EXPECT_TRUE(nyx_strict_pt_control_copyout_failed(
			&copyout_ctx, &enable_control));
		EXPECT_U64(copyout_ctx.policy.state, KVM_NYX_STRICT_PT_BROKEN);
		EXPECT_U64(copyout_ctx.counters.fail_closed, 1);

		control = make_control(KVM_NYX_STRICT_PT_DISABLE);
		EXPECT_S32(execute(&copyout_ctx, &control, 1, required), 0);
		EXPECT_TRUE(!nyx_strict_pt_control_copyout_failed(
			&copyout_ctx, &control));
		EXPECT_U64(copyout_ctx.policy.state, KVM_NYX_STRICT_PT_DISABLED);

		control = make_control(KVM_NYX_STRICT_PT_ENABLE);
		control.u.enable.target_cr3 = raw_cr3;
		EXPECT_S32(execute(&copyout_ctx, &control, 1, required), 0);
		control = make_control(KVM_NYX_STRICT_PT_RESET);
		control.u.reset.session_id = copyout_ctx.policy.session_id;
		EXPECT_S32(execute(&copyout_ctx, &control, 1, required), 0);
		EXPECT_TRUE(nyx_strict_pt_control_copyout_failed(
			&copyout_ctx, &control));
		EXPECT_U64(copyout_ctx.policy.state, KVM_NYX_STRICT_PT_BROKEN);
		EXPECT_U64(copyout_ctx.counters.fail_closed, 2);
	}

	{
		struct nyx_strict_pt_control_context race_ctx = { 0 };
		struct kvm_nyx_strict_pt_control stale_enable;

		stale_enable = make_control(KVM_NYX_STRICT_PT_ENABLE);
		stale_enable.u.enable.target_cr3 = raw_cr3;
		EXPECT_S32(execute(&race_ctx, &stale_enable, 1, required), 0);
		control = make_control(KVM_NYX_STRICT_PT_DISABLE);
		EXPECT_S32(execute(&race_ctx, &control, 1, required), 0);
		control = make_control(KVM_NYX_STRICT_PT_ENABLE);
		control.u.enable.target_cr3 = raw_cr3;
		EXPECT_S32(execute(&race_ctx, &control, 1, required), 0);
		EXPECT_TRUE(!nyx_strict_pt_control_copyout_failed(
			&race_ctx, &stale_enable));
		EXPECT_U64(race_ctx.policy.state, KVM_NYX_STRICT_PT_ENABLED);
		EXPECT_U64(race_ctx.policy.session_id, control.u.enable.session_id);
		EXPECT_U64(race_ctx.counters.fail_closed, 0);
	}

	printf("nyx_strict_pt_control_test: ok\n");
	return 0;
}
