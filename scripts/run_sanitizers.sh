#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu
: "${CLANG:=clang}"
: "${SANITIZERS:=address,undefined}"
OUT=$(mktemp -d)
trap 'rm -rf "$OUT"' EXIT HUP INT TERM
for test in client_protocol client_session proto_layout perf_attr_layout session_state; do
  "$CLANG" -std=c11 -O1 -g -Wall -Wextra -Werror \
    -fsanitize="$SANITIZERS" -fno-sanitize-recover=all -fno-omit-frame-pointer \
    -Iinclude -Iclient -Itests/stub_host "tests/$test.c" -o "$OUT/$test"
  "$OUT/$test"
done
printf '%s sanitizer regression suite: PASS\n' "$SANITIZERS"
