#!/bin/sh
# SPDX-License-Identifier: GPL-2.0

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
tree_root=$(CDPATH= cd -- "$script_dir/../../../.." && pwd)

cc=${CC:-cc}

tmp_root=$(mktemp -d "${TMPDIR:-/tmp}/nyx_strict_pt_abi.XXXXXX")
hdr_root="$tmp_root/headers"
install_log="$tmp_root/headers_install.log"
unifdef_bin="$tmp_root/unifdef"
abi_src_path="$script_dir/nyx_strict_pt_abi_test.c"
abi_bin_path="$tmp_root/nyx_strict_pt_abi_test"
lifecycle_src_path="$script_dir/nyx_strict_pt_lifecycle_test.c"
lifecycle_bin_path="$tmp_root/nyx_strict_pt_lifecycle_test"
control_src_path="$script_dir/nyx_strict_pt_control_test.c"
control_bin_path="$tmp_root/nyx_strict_pt_control_test"
tracking_src_path="$script_dir/nyx_strict_pt_tracking_test.c"
tracking_bin_path="$tmp_root/nyx_strict_pt_tracking_test"
tracking_limits_src_path="$script_dir/nyx_strict_pt_tracking_limits_test.c"
tracking_limits_bin_path="$tmp_root/nyx_strict_pt_tracking_limits_test"
tracking_rewalk_src_path="$script_dir/nyx_strict_pt_tracking_rewalk_test.c"
tracking_rewalk_bin_path="$tmp_root/nyx_strict_pt_tracking_rewalk_test"
tracking_data_src_path="$script_dir/nyx_strict_pt_tracking_data_test.c"
tracking_data_bin_path="$tmp_root/nyx_strict_pt_tracking_data_test"
tracking_exec_src_path="$script_dir/nyx_strict_pt_tracking_exec_test.c"
tracking_exec_bin_path="$tmp_root/nyx_strict_pt_tracking_exec_test"
lifecycle_policy_src="$tree_root/arch/x86/kvm/nyx_strict_pt_policy.c"
control_impl_src="$tree_root/arch/x86/kvm/nyx_strict_pt_control.c"
tracking_common_src="$tree_root/arch/x86/kvm/nyx_strict_pt_tracking_common.c"
tracking_prepare_src="$tree_root/arch/x86/kvm/nyx_strict_pt_tracking_prepare.c"
tracking_owners_src="$tree_root/arch/x86/kvm/nyx_strict_pt_tracking_owners.c"
tracking_runtime_src="$tree_root/arch/x86/kvm/nyx_strict_pt_tracking_runtime.c"
tracking_rewalk_impl_src="$tree_root/arch/x86/kvm/nyx_strict_pt_tracking_rewalk.c"
tracking_data_impl_src="$tree_root/arch/x86/kvm/nyx_strict_pt_tracking_data.c"
tracking_exec_impl_src="$tree_root/arch/x86/kvm/nyx_strict_pt_tracking_exec.c"
exec_state_src_path="$script_dir/nyx_strict_pt_exec_state_test.c"
exec_state_bin_path="$tmp_root/nyx_strict_pt_exec_state_test"
exec_state_impl_src="$tree_root/arch/x86/kvm/nyx_strict_pt_exec_state.c"

cleanup() {
	rm -rf -- "$tmp_root"
}

trap cleanup EXIT HUP INT TERM

mkdir -p -- \
	"$hdr_root/include/linux" \
	"$hdr_root/include/asm" \
	"$hdr_root/include/asm-generic"

if ! "$cc" -O2 "$tree_root/scripts/unifdef.c" -o "$unifdef_bin" >"$install_log" 2>&1; then
	cat "$install_log" >&2
	exit 1
fi

install_header() {
	infile=$1
	outfile=$2
	tmpfile=$outfile.tmp
	mkdir -p -- "$(dirname -- "$outfile")"
	sed -E -e '
		s/([[:space:](])(__user|__force|__iomem)[[:space:]]/\1/g
		s/__attribute_const__([[:space:]]|$)/\1/g
		s@^#include <linux/compiler.h>@@
		s@^#include <linux/compiler_types.h>@@
		s/(^|[^a-zA-Z0-9])__packed([^a-zA-Z0-9_]|$)/\1__attribute__((packed))\2/g
		s/(^|[[:space:](])(inline|asm|volatile)([[:space:](]|$)/\1__\2__\3/g
		s@#(ifndef|define|endif[[:space:]]*/[*])[[:space:]]*_UAPI@#\1 @
	' "$infile" > "$tmpfile"
	if "$unifdef_bin" -U__KERNEL__ -D__EXPORTED_HEADERS__ "$tmpfile" > "$outfile"; then
		:
	else
		status=$?
		if [ "$status" -gt 1 ]; then
			return "$status"
		fi
	fi
	rm -f -- "$tmpfile"
}

install_header "$tree_root/include/uapi/linux/kvm.h" "$hdr_root/include/linux/kvm.h"
install_header "$tree_root/include/uapi/linux/const.h" "$hdr_root/include/linux/const.h"
install_header "$tree_root/include/uapi/linux/types.h" "$hdr_root/include/linux/types.h"
install_header "$tree_root/include/uapi/linux/ioctl.h" "$hdr_root/include/linux/ioctl.h"
install_header "$tree_root/include/uapi/linux/posix_types.h" "$hdr_root/include/linux/posix_types.h"
install_header "$tree_root/include/uapi/linux/stddef.h" "$hdr_root/include/linux/stddef.h"
install_header "$tree_root/arch/x86/include/uapi/asm/kvm.h" "$hdr_root/include/asm/kvm.h"
install_header "$tree_root/arch/x86/include/uapi/asm/posix_types.h" "$hdr_root/include/asm/posix_types.h"
install_header "$tree_root/arch/x86/include/uapi/asm/posix_types_64.h" "$hdr_root/include/asm/posix_types_64.h"
install_header "$tree_root/arch/x86/include/uapi/asm/bitsperlong.h" "$hdr_root/include/asm/bitsperlong.h"
install_header "$tree_root/include/uapi/asm-generic/types.h" "$hdr_root/include/asm/types.h"
install_header "$tree_root/include/uapi/asm-generic/ioctl.h" "$hdr_root/include/asm/ioctl.h"
install_header "$tree_root/include/uapi/asm-generic/int-ll64.h" "$hdr_root/include/asm-generic/int-ll64.h"
install_header "$tree_root/include/uapi/asm-generic/posix_types.h" "$hdr_root/include/asm-generic/posix_types.h"
install_header "$tree_root/include/uapi/asm-generic/bitsperlong.h" "$hdr_root/include/asm-generic/bitsperlong.h"

compile_and_run() {
	label=$1
	src_path=$2
	bin_path=$3
	shift 3
	compile_log="$tmp_root/$label.compile.log"
	compile_cmd="$cc -std=c11 -Wall -Wextra -Werror -I$hdr_root/include -I$tree_root/arch/x86/kvm $src_path $* -o $bin_path"

	printf 'Compile command: %s\n' "$compile_cmd"

	if "$cc" -std=c11 -Wall -Wextra -Werror \
		-I"$hdr_root/include" \
		-I"$tree_root/arch/x86/kvm" \
		"$src_path" "$@" -o "$bin_path" >"$compile_log" 2>&1; then
		cat "$compile_log"
		if "$bin_path" >"$tmp_root/test.log" 2>&1; then
			cat "$tmp_root/test.log"
			printf 'Binary completed successfully\n'
			return 0
		else
			status=$?
			cat "$tmp_root/test.log" >&2
			return "$status"
		fi
	fi

	cat "$compile_log" >&2
	return 1
}

compile_and_run abi "$abi_src_path" "$abi_bin_path"
compile_and_run lifecycle "$lifecycle_src_path" "$lifecycle_bin_path" "$lifecycle_policy_src"
compile_and_run control "$control_src_path" "$control_bin_path" "$lifecycle_policy_src" "$control_impl_src"
compile_and_run tracking "$tracking_src_path" "$tracking_bin_path" \
	"$tracking_common_src" "$tracking_prepare_src" "$tracking_runtime_src"
compile_and_run tracking_limits "$tracking_limits_src_path" \
	"$tracking_limits_bin_path" "$tracking_common_src" \
	"$tracking_prepare_src" "$tracking_runtime_src"
compile_and_run tracking_rewalk "$tracking_rewalk_src_path" \
	"$tracking_rewalk_bin_path" "$tracking_common_src" \
	"$tracking_prepare_src" "$tracking_owners_src" "$tracking_runtime_src" \
	"$tracking_rewalk_impl_src"
compile_and_run tracking_data "$tracking_data_src_path" \
	"$tracking_data_bin_path" "$tracking_common_src" \
	"$tracking_prepare_src" "$tracking_owners_src" "$tracking_runtime_src" \
	"$tracking_data_impl_src"
compile_and_run tracking_exec "$tracking_exec_src_path" \
	"$tracking_exec_bin_path" "$tracking_common_src" \
	"$tracking_prepare_src" "$tracking_owners_src" "$tracking_runtime_src" \
	"$tracking_data_impl_src" "$tracking_exec_impl_src"
compile_and_run exec_state "$exec_state_src_path" \
	"$exec_state_bin_path" "$exec_state_impl_src"
