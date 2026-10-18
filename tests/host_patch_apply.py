#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Rebuild the preimage hunk contexts and require both patches to apply cleanly.

This is a structural consistency check, NOT a substitute for the exact pinned
host checkout (the original module.c/module.h Git objects are not bundled).
"""
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from host_contract import apply_patch_isolated, isolated_git_env
PATCHES = sorted((ROOT/'host_patches').glob('*.patch'))
HUNK = re.compile(r'^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@')


def preimages(patch: Path):
    contents = {}
    current = None
    old_at = None
    last_old_index = None
    last_old_type = None
    for line in patch.read_text().splitlines(keepends=True):
        if line.startswith('diff --git '):
            current = None
            old_at = None
        elif line.startswith('--- a/'):
            current = line[6:].rstrip('\n')
            contents[current] = {}
        elif (m := HUNK.match(line)):
            assert current
            old_at = int(m.group(1)) - 1
            last_old_index = None
        elif old_at is not None and current and line[:1] in (' ', '-', '+'):
            if line[0] != '+':
                data = line[1:]
                old_entry = contents[current].get(old_at)
                assert old_entry is None or old_entry == data, (patch.name, current, old_at)
                contents[current][old_at] = data
                last_old_index = old_at
                last_old_type = line[0]
                old_at += 1
            else:
                last_old_type = '+'
        elif line.startswith('\\ No newline at end of file'):
            if last_old_index is not None and last_old_type in (' ', '-'):
                contents[current][last_old_index] = contents[current][last_old_index].removesuffix('\n')
    result = {}
    for name, lines in contents.items():
        if not lines:
            raise AssertionError(f'{patch.name} empty preimage {name}')
        maximum = max(lines)
        data = ['\n'] * (maximum + 1)
        for idx, row in lines.items():
            data[idx] = row
        result[name] = ''.join(data)
    return result


def main():
    for patch in PATCHES:
        with tempfile.TemporaryDirectory(prefix='secdebug-patch-fixture-') as td:
            tmp = Path(td)
            raw_preimages = {name: text.encode('utf-8') for name, text in preimages(patch).items()}
            env = isolated_git_env()
            subprocess.run(['git', 'init', '-q', '--template='], cwd=tmp, env=env, check=True)
            for name, raw in raw_preimages.items():
                file = tmp / name
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_bytes(raw)
            subprocess.run(['git', '-c', 'core.autocrlf=false', 'apply', '--check', str(patch)],
                           cwd=tmp, env=env, check=True)
        with tempfile.TemporaryDirectory(prefix='secdebug-patch-fixture-') as td:
            tmp = Path(td)
            raw_preimages = {name: text.encode('utf-8') for name, text in preimages(patch).items()}
            patched_files = apply_patch_isolated(tmp, patch, raw_preimages)
            patched = patched_files['kernel/patch/module/module.c'].decode('utf-8')
            assert 'if (remaining <= 1)' in patched
            assert 'written >= remaining' in patched
            assert 'size - 1 - off' not in patched
        print(f'{patch.name}: synthetic preimage git apply: PASS')

if __name__ == '__main__':
    main()
