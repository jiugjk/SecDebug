#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
verify_symbols.py - Strict ELF undefined symbol checker for the secdebug KPM.

Every SHN_UNDEF symbol must be one of:
1. A symbol this module intentionally imports from KernelPatch / KPatch-Next
2. A compiler runtime built-in (__stack_chk_guard, __stack_chk_fail)
"""

import sys
import subprocess
import shutil

ALLOWED_BUILTINS = {
    "__stack_chk_guard",
    "__stack_chk_fail",
}

# Least-privilege imports. Adding a symbol here is a review decision.
COMMON_EXPORTS = {
    "secdebug_host_contract_v1",
    "kallsyms_lookup_name",
    "printk",
    "kver",
    "kpver",
    "current_uid",
    "is_su_allow_uid",
    "compat_copy_to_user",
    # asm/current.h get_current() may inline references to these host exports.
    "sp_el0_is_current",
    "sp_el0_is_thread_info",
    "thread_info_in_task",
    "thread_size",
    "task_in_thread_info_offset",
    "strlen",
    "memset",
    "memcpy",
    "kf_strlen",
    "kf_memset",
    "kf_memcpy",
}


def verify_kpm(kpm_file):
    readelf = shutil.which("llvm-readelf") or shutil.which("readelf")
    if not readelf:
        print("Neither llvm-readelf nor readelf is installed.")
        return False
    # GNU readelf otherwise abbreviates long names (including valid imports).
    res = subprocess.run([readelf, "-Ws", kpm_file], capture_output=True, text=True)
    if res.returncode != 0:
        print(f"Error running {readelf} on {kpm_file}:\n{res.stderr}")
        return False

    errors = []
    for line in res.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 8 and parts[6] == "UND":
            sym_name = parts[7]
            if sym_name not in COMMON_EXPORTS and sym_name not in ALLOWED_BUILTINS:
                errors.append(sym_name)

    if errors:
        print(f"[FAIL] {kpm_file} has prohibited undefined symbols that will fail loading:")
        for err in errors:
            print(f"  - {err}")
        return False

    print(f"[PASS] {kpm_file} passed strict KPM symbol verification.")
    return True


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: verify_symbols.py <path/to/module.kpm>")
        sys.exit(1)
    if not verify_kpm(sys.argv[1]):
        sys.exit(1)
