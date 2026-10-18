#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Source-level regression tripwires (not a substitute for real kernel tests)."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]

def read(path):
    return (ROOT / path).read_text(encoding="utf-8")

def require(blob, s, where):
    if s not in blob:
        raise AssertionError(f"{where}: missing {s!r}")

def forbid(blob, s, where):
    if s in blob:
        raise AssertionError(f"{where}: unsafe pattern {s!r}")

def ordered(blob, a, b, where):
    if a not in blob or b not in blob or blob.index(a) >= blob.index(b):
        raise AssertionError(f"{where}: expected {a!r} before {b!r}")

def main():
    core = read("src/secdebug_core.c")
    ctl = core[core.index("static long secdebug_control0"):]
    hwbp = read("src/secdebug_hwbp.c")
    session = read("src/secdebug_session.c")
    mem = read("src/secdebug_mem.c")
    client = read("client/libsecdebug.c")
    proto = read("include/secdebug_proto.h")
    build = read("Makefile")

    require(core, "secdebug_preflight_request", "preflight")
    ordered(ctl, "int preflight = secdebug_preflight_request", "switch (req_hdr->cmd)", "preflight")
    require(core, "secdebug_rcu_drop(&response_rcu_dropped)", "faulting copy")
    ordered(ctl, "secdebug_rcu_drop(&response_rcu_dropped)", "compat_copy_to_user", "RCU")
    ordered(ctl, "compat_copy_to_user", "secdebug_rcu_restore(&response_rcu_dropped)", "RCU")
    require(ctl, "secdebug_hwbp_finish_hit", "BP hit completion")
    require(ctl, "secdebug_session_finish_open(opened_session_id", "session open completion/rollback")
    require(ctl, "secdebug_hwbp_finish_register(registered_slot_id", "BP register completion/rollback")
    forbid(ctl, "secdebug_session_close(opened_session_id)", "re-contended session rollback")
    forbid(ctl, "secdebug_hwbp_unregister(&rollback)", "re-contended BP rollback")
    forbid(ctl, "bounded_len(ctl_args, 2048)", "unbounded host arg")
    require(core, "g_page_size = 0", "unknown page size")
    forbid(core, 'lookup_sym("page_shift")', "invalid page shift symbol")

    get_hit = hwbp[hwbp.index("int secdebug_hwbp_get_hit("):hwbp.index("void secdebug_hwbp_finish_hit(")]
    finish = hwbp[hwbp.index("void secdebug_hwbp_finish_hit("):]
    forbid(get_hit, "slot_restore_active(slot, req->slot_id);\n    return 0;", "BP lease")
    require(finish, "slot_restore_active(slot, req->slot_id)", "BP lease release")
    forbid(finish, "g_syms.perf_event_enable(event)", "one-shot ACK must not rearm")
    require(hwbp, "pin_leader(caller_tgid)", "leader ref")
    forbid(hwbp, "leader = owner;", "nonleader fallback")
    require(read("include/secdebug_perf_abi.h"), "_Static_assert(__builtin_offsetof", "perf attr ABI assertion")
    require(hwbp, "slot_lifecycle(public_id, BP_SLOT_BUSY)", "enable publication order")
    require(hwbp, "void secdebug_hwbp_finish_register(", "BP register lease completion")
    require(session, "void secdebug_session_finish_open(", "session open lease completion")
    require(hwbp, "req->bp_len != 4", "ARM64 breakpoint length")
    handler = hwbp[hwbp.index("static void slot_record_hit("):hwbp.index("static void bp_perf_handler(")]
    ordered(handler, "if (retries >= 16)", "g_syms.perf_event_disable_inatomic(event)", "overflow fail-safe")

    require(session, "struct mm_struct *mm;", "pinned mm")
    require(session, "secdebug_pin_mm(req->target_pid, &mm", "pinned mm")
    require(session, "slot->owner != secdebug_current_task()", "session ownership")
    require(session, "session_state(id, SESSION_BUSY)", "session exclusive claim")
    require(session, "secdebug_session_cleanup", "session cleanup")
    require(session, "g_syms.access_remote_vm(slot->mm", "mm not pid")
    require(mem, "secdebug_pin_mm", "mm get helper")
    require(mem, "return get_current();", "kernel current")
    forbid(mem, "usage_offset", "guess task_struct refcount")
    forbid(mem, "mrs %0, sp_el0", "guess thread current")

    require(client, "#define SECDEBUG_ALLOW_LEGACY_TRUNCATE_SYSCALL 0", "safe SuperCall")
    require(client, "secdebug_open_mem_session(client", "SDK stable chunks")
    require(client, "secdebug_client_destroy", "SDK secret cleanup")
    require(client, "receipt_ambiguous && err == -EFAULT", "lost receipt only")
    forbid(client, "command_is_mutating(cmd) ? -EINPROGRESS", "every transport error unknown")
    require(client, "secure_zero(raw_req", "SDK stack scrub")
    require(client, "resp_hdr->seq != seq", "protocol sequence")
    require(client, "return -ENAMETOOLONG", "strict key length")
    require(proto, 'SECDEBUG_MOD_VER     "1.0.0"', "version")
    require(proto, "SECDEBUG_CAP_MEM_SESSION", "capability")
    require(proto, "GPL-2.0-only OR Apache-2.0", "license")
    require(proto, "clear acknowledges without re-arming", "one-shot proto comment")
    forbid(proto, "clear re-arms the one-shot event", "misleading proto comment")
    require(build, "HOST_CONTRACT_ACK", "fail-closed KPM build")
    require(build, "HOST_COMMIT", "pinned KPM host")
    require(build, "TARGET_PAGE_SHIFT", "explicit page size")
    require(build, "-mgeneral-regs-only", "no kernel NEON")
    require(build, "SECDEBUG_FOLL_FORCE", "explicit FOLL_FORCE")
    forbid(mem, "VERSION(6, 3, 0)", "version-guessed FOLL_FORCE")
    require(mem, "SECDEBUG_FOLL_FORCE", "compile-time FOLL_FORCE")
    require(core, "auth_token_matches", "constant-time token compare")
    require(core, "wipe_load_token", "wipe load token")
    require(core, "secdebug_alloc(SECDEBUG_ARGS_MAX)", "heap control buffers")
    forbid(core, "secdebug_hwbp_self_test", "fake probe self-test")
    require(hwbp, "secdebug_hwbp_prerequisites_ready", "breakpoint dependency gate")
    require(read("client/test_secdebug.c"), "secdebug_get_hit", "opt-in real HW hit smoke test")
    require(session, "secdebug_init_pid", "init namespace liveness")
    forbid(session, "task_pid_nr_ns(slot->owner, 0, NULL)", "caller-ns reap")
    require(hwbp, "slot_leader_alive", "init namespace breakpoint reap")
    require(read("include/secdebug_internal.h"), '#error "SECDEBUG_PERF_PENDING_OFFSET is unsupported', "no raw offset ABI")
    forbid(hwbp, "g_syms.irq_work_sync", "no internal perf_event offset access")
    require(core, "SECDEBUG_CALLS_CLOSED", "atomic close gate")
    require(core, "__atomic_compare_exchange_n(&g_call_state", "atomic close gate")
    forbid(core, "g_schedule", "no scheduler busy loop")
    require(core, "secdebug_host_contract_v1() != SECDEBUG_HOST_CONTRACT_V1", "runtime host guard")
    require(hwbp, "public_id_in_use", "breakpoint id collision")
    require(session, "session_id_in_use", "session id collision")
    require(read("scripts/check_stub_kpm.sh"), "-mgeneral-regs-only", "stub NEON flag")
    require(read("scripts/check_stub_kpm.sh"), "llvm-objdump", "disassembly gate")
    def forbid_added(blob, needle, where):
        for line in blob.splitlines():
            if line.startswith("+") and not line.startswith("+++") and needle in line:
                raise AssertionError(f"{where}: added line still has {needle!r}")

    kp = read("host_patches/bmax121-KernelPatch-f36f3d1.patch")
    kpn = read("host_patches/KernelSU-Next-KPatch-Next-456744b.patch")
    for blob, name in ((kp, "KernelPatch patch"), (kpn, "KPatch-Next patch")):
        require(blob, "request_args", name)
        require(blob, "spin_lock_irqsave(&module_lock)", name)
        require(blob, "list_add_tail_rcu", name)
        require(blob, "list_del_rcu", name)
        require(blob, "\"<redacted>\"", name)
        require(blob, "mod->ctl_active != 0", name)
        require(blob, "secdebug_host_contract_v1", name)
        forbid(blob, "+    module_wait_callbacks", name)
        require(blob, "+    kfunc_call(synchronize_rcu);", name)
        require(blob, "copied == copy_len ?", name)
        require(blob, "ctl_active", name)
        require(blob, "payload redacted", name)
        forbid_added(blob, "size - 1 - off", name)
        require(blob, "written >= remaining", name)
        require(blob, "if (remaining <= 1)", name)
        forbid_added(blob, "args: %s", name)
    require(kpn, "+        rcu_read_unlock();\n+        return -ENOENT;", "missing module unlocks RCU")
    for path in ("src/secdebug_core.c", "src/secdebug_mem.c", "src/secdebug_hwbp.c",
                 "src/secdebug_session.c", "include/secdebug_internal.h"):
        require(read(path), "SPDX-License-Identifier: GPL-2.0-only", path)

    print("source invariants: PASS")

if __name__ == "__main__":
    try:
        main()
    except AssertionError as exc:
        print(f"source invariants: FAIL: {exc}", file=sys.stderr)
        sys.exit(1)
