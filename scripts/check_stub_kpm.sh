#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Real AArch64 code generation with compile-only fake host headers. This is
# NOT a deployable build, and does not verify any actual loader ABI.
# -mgeneral-regs-only keeps Clang -O2 from emitting NEON/FPSIMD in KPM code.
set -eu
: "${CLANG:=clang}"
: "${LLD:=ld.lld}"
: "${OBJDUMP:=llvm-objdump}"
if ! command -v "$CLANG" >/dev/null 2>&1 ||
   ! command -v "$LLD" >/dev/null 2>&1 ||
   ! command -v "$OBJDUMP" >/dev/null 2>&1; then
  echo "clang, ld.lld and llvm-objdump are required for stub code generation" >&2
  exit 1
fi
: "${KPM_TUNE:=generic}"
case "$KPM_TUNE" in
  ''|*[!a-zA-Z0-9_-]*)
    echo "KPM_TUNE must be a simple CPU tune name" >&2
    exit 1
    ;;
esac
# Exercise the same optional scheduling tune while retaining generic ARM64 ISA.
if [ "$KPM_TUNE" = generic ]; then
  set --
else
  set -- "-mtune=$KPM_TUNE"
fi
OUT=$(mktemp -d)
trap 'rm -rf "$OUT"' EXIT HUP INT TERM
objects=""
for file in src/secdebug_core.c src/secdebug_mem.c src/secdebug_session.c src/secdebug_hwbp.c; do
  object="$OUT/$(basename "$file" .c).o"
  "$CLANG" --target=aarch64-none-elf -mcpu=generic "$@" -std=gnu11 -O2 -Wall -Wextra -Werror \
    -fno-builtin -ffreestanding -fno-stack-protector -mgeneral-regs-only \
    -mno-outline-atomics -fstack-usage \
    -Itests/stub_host -Iinclude -c "$file" -o "$object"
  objects="$objects $object"
  if "$OBJDUMP" -d "$object" | grep -E -q \
      '([[:space:]]q[0-9]+|[[:space:]]v[0-9]+\.[0-9]+|(^|[[:space:]])(fmov|fcmp|fadd|fsub|fmul|fdiv|fmadd|cmeq|cmgt|ldp[[:space:]]+q|stp[[:space:]]+q|ldr[[:space:]]+q|str[[:space:]]+q|stur[[:space:]]+q|ldur[[:space:]]+q)\b)'; then
    echo "NEON/FPSIMD instruction in $object" >&2
    "$OBJDUMP" -d "$object" | grep -E -n \
      '([[:space:]]q[0-9]+|[[:space:]]v[0-9]+\.[0-9]+|(^|[[:space:]])(fmov|fcmp|fadd|fsub|fmul|fdiv|fmadd|cmeq|cmgt|ldp[[:space:]]+q|stp[[:space:]]+q|ldr[[:space:]]+q|str[[:space:]]+q|stur[[:space:]]+q|ldur[[:space:]]+q)\b)' >&2 || true
    exit 1
  fi
done

# Stack frames that used to hold the full request/response or perf attr.
check_frame() {
  func=$1
  limit=$2
  found=0
  for su in "$OUT"/*.su; do
    if grep -q "${func}" "$su"; then
      found=1
      bytes=$(grep "${func}" "$su" | awk '{print $(NF-1)}')
      if [ "$bytes" -gt "$limit" ]; then
        echo "stack frame $func is $bytes bytes (limit $limit)" >&2
        exit 1
      fi
      printf '%s\n' "stack $func: $bytes bytes"
    fi
  done
  if [ "$found" -ne 1 ]; then
    echo "missing stack usage for $func" >&2
    exit 1
  fi
}
check_frame secdebug_control0 1024
check_frame secdebug_hwbp_register 512

# Intentional word splitting of this internal space-delimited object list.
# shellcheck disable=SC2086
"$LLD" -r -o "$OUT/secdebug.stub.kpm" $objects
if command -v readelf >/dev/null 2>&1; then
  readelf -h "$OUT/secdebug.stub.kpm" | grep -q 'AArch64' || exit 1
fi
printf '%s\n' 'AArch64 stub objects/link: PASS (no NEON; not a real host KPM build)'
