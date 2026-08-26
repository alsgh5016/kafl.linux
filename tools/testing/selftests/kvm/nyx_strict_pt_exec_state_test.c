/* SPDX-License-Identifier: GPL-2.0 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "nyx_strict_pt_exec_state.h"

static void test_latch_and_replay(void)
{
	struct nyx_strict_pt_exec_state state;
	struct kvm_nyx_strict_pt_exit payload;
	struct kvm_nyx_strict_pt_exit replay;
	bool ret;

	nyx_strict_pt_exec_state_clear(&state);
	memset(&payload, 0xaa, sizeof(payload));

	payload.session_id = 1;
	payload.range_id = 2;
	payload.generation = 3;
	payload.page_index = 4;

	ret = nyx_strict_pt_exec_state_latch(&state, &payload);
	assert(ret == true);
	assert(state.pending == true);

	memset(&replay, 0, sizeof(replay));
	ret = nyx_strict_pt_exec_state_replay(&state, &replay);
	assert(ret == true);
	assert(memcmp(&payload, &replay, sizeof(payload)) == 0);
}

static void test_second_latch_immutability(void)
{
	struct nyx_strict_pt_exec_state state;
	struct kvm_nyx_strict_pt_exit payload1, payload2, replay;
	bool ret;

	nyx_strict_pt_exec_state_clear(&state);
	memset(&payload1, 0x11, sizeof(payload1));
	memset(&payload2, 0x22, sizeof(payload2));

	ret = nyx_strict_pt_exec_state_latch(&state, &payload1);
	assert(ret == true);

	ret = nyx_strict_pt_exec_state_latch(&state, &payload2);
	assert(ret == false);

	ret = nyx_strict_pt_exec_state_replay(&state, &replay);
	assert(ret == true);
	assert(memcmp(&payload1, &replay, sizeof(payload1)) == 0);
}

static void test_ack_mismatches(void)
{
	struct nyx_strict_pt_exec_state state;
	struct kvm_nyx_strict_pt_exit payload;
	bool ret;

	nyx_strict_pt_exec_state_clear(&state);
	memset(&payload, 0, sizeof(payload));

	payload.session_id = 10;
	payload.range_id = 20;
	payload.generation = 30;
	payload.page_index = 40;

	ret = nyx_strict_pt_exec_state_latch(&state, &payload);
	assert(ret == true);

	/* independent ACK mismatches */
	ret = nyx_strict_pt_exec_state_compare_ack(&state, 99, 20, 30, 40);
	assert(ret == false);
	ret = nyx_strict_pt_exec_state_compare_ack(&state, 10, 99, 30, 40);
	assert(ret == false);
	ret = nyx_strict_pt_exec_state_compare_ack(&state, 10, 20, 99, 40);
	assert(ret == false);
	ret = nyx_strict_pt_exec_state_compare_ack(&state, 10, 20, 30, 99);
	assert(ret == false);

	/* exact ACK */
	ret = nyx_strict_pt_exec_state_compare_ack(&state, 10, 20, 30, 40);
	assert(ret == true);

	/* commit should succeed with exact */
	ret = nyx_strict_pt_exec_state_commit_ack(&state, 10, 20, 30, 40);
	assert(ret == true);
	assert(state.pending == false);
}

static void test_ack_no_pending(void)
{
	struct nyx_strict_pt_exec_state state;
	bool ret;

	nyx_strict_pt_exec_state_clear(&state);

	ret = nyx_strict_pt_exec_state_compare_ack(&state, 1, 2, 3, 4);
	assert(ret == false);

	ret = nyx_strict_pt_exec_state_commit_ack(&state, 1, 2, 3, 4);
	assert(ret == false);
}

static void test_clear_zeroing(void)
{
	struct nyx_strict_pt_exec_state state;
	struct kvm_nyx_strict_pt_exit payload;
	struct kvm_nyx_strict_pt_exit zero_payload;
	bool ret;

	nyx_strict_pt_exec_state_clear(&state);
	memset(&payload, 0xaa, sizeof(payload));

	ret = nyx_strict_pt_exec_state_latch(&state, &payload);
	assert(ret == true);

	nyx_strict_pt_exec_state_clear(&state);
	assert(state.pending == false);

	memset(&zero_payload, 0, sizeof(zero_payload));
	assert(memcmp(&state.payload, &zero_payload, sizeof(zero_payload)) == 0);
}

static void test_replay_without_output_buffer(void)
{
	struct nyx_strict_pt_exec_state state;
	struct kvm_nyx_strict_pt_exit payload;
	bool ret;

	nyx_strict_pt_exec_state_clear(&state);
	memset(&payload, 0x5a, sizeof(payload));
	payload.session_id = 7;

	ret = nyx_strict_pt_exec_state_latch(&state, &payload);
	assert(ret == true);

	ret = nyx_strict_pt_exec_state_replay(&state, NULL);
	assert(ret == true);
	assert(state.pending == true);
	assert(state.payload.session_id == 7);
}

int main(void)
{
	test_latch_and_replay();
	test_second_latch_immutability();
	test_ack_mismatches();
	test_ack_no_pending();
	test_clear_zeroing();
	test_replay_without_output_buffer();

	printf("exec_state test passed\n");
	return 0;
}
