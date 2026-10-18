#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run the real module and SDK against isolated host services, never a KPM."""
from pathlib import Path
import os
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def write_sources(out: Path, *, legacy_sd02: bool = False) -> None:
    core = (ROOT / 'src/secdebug_core.c').read_text()
    session = (ROOT / 'src/secdebug_session.c').read_text()
    hwbp = (ROOT / 'src/secdebug_hwbp.c').read_text()
    bti = '__attribute__((noinline, target("branch-protection=bti")))'
    assert hwbp.count(bti) == 1
    hwbp = hwbp.replace(bti, '__attribute__((noinline))')

    if legacy_sd02:
        old_session = (
            '    /* Hold SESSION_BUSY until the response copy completes in finish_open(). */\n'
            '    __atomic_store_n(&slot->lifecycle, session_state(id, SESSION_BUSY),\n'
            '                     __ATOMIC_RELEASE);'
        )
        new_session = (
            '    __atomic_store_n(&slot->lifecycle, session_state(id, SESSION_ACTIVE),\n'
            '                     __ATOMIC_RELEASE);'
        )
        assert session.count(old_session) == 1
        session = session.replace(old_session, new_session)

        old_hwbp = (
            '    /* A hardware hit during enable is already supported in the BUSY state.\n'
            '     * Keep BP_SLOT_BUSY until finish_register() commits or rolls back. */\n'
            '    g_syms.perf_event_enable(event);'
        )
        new_hwbp = (
            '    g_syms.perf_event_enable(event);\n'
            '    __atomic_store_n(&slot->lifecycle, slot_lifecycle(public_id, BP_SLOT_ACTIVE),\n'
            '                     __ATOMIC_RELEASE);'
        )
        assert hwbp.count(old_hwbp) == 1
        hwbp = hwbp.replace(old_hwbp, new_hwbp)

        old_core = (
            '        if (registered_slot_pending) {\n'
            '            secdebug_hwbp_finish_register(registered_slot_id,\n'
            '                                          copied == resp_total_len);\n'
            '        }\n'
            '        if (opened_session_pending) {\n'
            '            secdebug_session_finish_open(opened_session_id,\n'
            '                                         copied == resp_total_len);\n'
            '        }\n'
            '        if (copied != resp_total_len) {\n'
            '            ret = -EFAULT; /* Side effects of writes/closes may already exist. */\n'
            '            goto out;\n'
            '        }'
        )
        new_core = (
            '        if (copied != resp_total_len) {\n'
            '            if (registered_slot_pending) {\n'
            '                struct secdebug_bp_unreg_req rollback = { registered_slot_id, 0 };\n'
            '                (void)secdebug_hwbp_unregister(&rollback);\n'
            '            }\n'
            '            if (opened_session_pending)\n'
            '                (void)secdebug_session_close(opened_session_id);\n'
            '            ret = -EFAULT;\n'
            '            goto out;\n'
            '        }'
        )
        assert core.count(old_core) == 1
        core = core.replace(old_core, new_core)

    (out / 'core_host_adapted.c').write_text(core)
    (out / 'session_host_adapted.c').write_text(session)
    (out / 'hwbp_host_adapted.c').write_text(hwbp)


def main():
    compiler = shlex.split(os.environ.get('CC', 'cc'))
    flags = ['-pthread', '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror']
    sanitizers = os.environ.get('SECDEBUG_TEST_SANITIZERS', '')
    if sanitizers:
        flags += [f'-fsanitize={sanitizers}', '-fno-sanitize-recover=all',
                  '-fno-omit-frame-pointer']

    with tempfile.TemporaryDirectory(prefix='secdebug-runtime-') as tmp:
        out = Path(tmp)
        write_sources(out, legacy_sd02=False)
        includes = [f'-I{out}', f'-I{ROOT / "tests/stub_host"}',
                    f'-I{ROOT / "include"}', f'-I{ROOT / "client"}']
        binary = out / 'runtime_regressions'
        subprocess.run([*compiler, *flags, *includes,
                        str(ROOT / 'tests/runtime_regressions.c'), '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True)

    # Negative validation: verify the concurrent rollback-vs-reaper harness
    # deterministically catches the pre-SD-02 early-ACTIVE implementation.
    with tempfile.TemporaryDirectory(prefix='secdebug-runtime-neg-') as tmp:
        out = Path(tmp)
        write_sources(out, legacy_sd02=True)
        includes = [f'-I{out}', f'-I{ROOT / "tests/stub_host"}',
                    f'-I{ROOT / "include"}', f'-I{ROOT / "client"}']
        neg_bin = out / 'runtime_regressions_legacy'
        subprocess.run([*compiler, *flags, '-DSECDEBUG_LEGACY_PRE_SD02_RACE=1', *includes,
                        str(ROOT / 'tests/runtime_regressions.c'), '-o', str(neg_bin)], check=True)
        neg_run = subprocess.run([str(neg_bin)], capture_output=True, text=True)
        assert neg_run.returncode == 77, (neg_run.returncode, neg_run.stdout, neg_run.stderr)
        assert 'SD-02 session and breakpoint races reproduced in legacy mode' in neg_run.stderr
        print('Negative test confirms harness catches pre-SD-02 BUSY lease rollback race: PASS')


if __name__ == '__main__':
    main()
