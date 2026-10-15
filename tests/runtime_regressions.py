#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run the real module and SDK against isolated host services, never a KPM."""
from pathlib import Path
import os
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    with tempfile.TemporaryDirectory(prefix='secdebug-runtime-') as tmp:
        out = Path(tmp)
        (out / 'core_host_adapted.c').write_text((ROOT / 'src/secdebug_core.c').read_text())
        adaptations = (
            ('hwbp', '__attribute__((noinline, target("branch-protection=bti")))',
             '__attribute__((noinline))'),)
        for name, old, new in adaptations:
            source = (ROOT / f'src/secdebug_{name}.c').read_text()
            assert source.count(old) == 1
            (out / f'{name}_host_adapted.c').write_text(source.replace(old, new))
        compiler = shlex.split(os.environ.get('CC', 'cc'))
        flags = ['-pthread', '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror']
        sanitizers = os.environ.get('SECDEBUG_TEST_SANITIZERS', '')
        if sanitizers:
            flags += [f'-fsanitize={sanitizers}', '-fno-sanitize-recover=all',
                      '-fno-omit-frame-pointer']
        includes = [f'-I{out}', f'-I{ROOT / "tests/stub_host"}',
                    f'-I{ROOT / "include"}', f'-I{ROOT / "client"}']
        binary = out / 'runtime_regressions'
        subprocess.run([*compiler, *flags, *includes,
                        str(ROOT / 'tests/runtime_regressions.c'), '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True)


if __name__ == '__main__':
    main()
