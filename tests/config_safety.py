#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check C-level safeguards independently of Make's environment gate."""
from pathlib import Path
import os
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]

def main():
    cc = shlex.split(os.environ.get('CC', 'cc'))
    with tempfile.TemporaryDirectory(prefix='secdebug-config-safety-') as tmp:
        src = Path(tmp) / 'case.c'
        obj = src.with_suffix('.o')
        base = [*cc, '-std=gnu11', '-Werror', '-I'+str(ROOT/'tests/stub_host'),
                '-I'+str(ROOT/'include'), '-c', str(src), '-o', str(obj)]
        src.write_text('#include "secdebug_internal.h"\n')
        subprocess.run(base, check=True)
        for offset in ('0', '1', '128', '0x100000'):
            result = subprocess.run([*base, '-DSECDEBUG_PERF_PENDING_OFFSET='+offset],
                                    capture_output=True, text=True)
            assert result.returncode and 'SECDEBUG_PERF_PENDING_OFFSET is unsupported' in result.stderr
        print('raw perf offsets are rejected even when bypassing Make: PASS')
        for string, ok in (('1.0.0', True), ('12345678901', True), ('123456789012', False)):
            src.write_text('#include "kpmodule.h"\nKPM_VERSION("'+string+'");\n')
            result = subprocess.run(base, capture_output=True, text=True)
            assert (result.returncode == 0) == ok, result.stderr
        print('stub enforces strictest host version length: PASS')

if __name__ == '__main__':
    main()
