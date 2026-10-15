#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Shared helpers: patched synthetic contexts, explicitly NOT real host trees."""
from pathlib import Path
import subprocess
from host_patch_apply import preimages


def patched_sources(patch: Path, destination: Path) -> dict[str, str]:
    for name, text in preimages(patch).items():
        file = destination / name
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(text)
    subprocess.run(['git', 'apply', str(patch.resolve())], cwd=destination, check=True)
    return {name: (destination / name).read_text() for name in preimages(patch)}


def function(source: str, name: str) -> str:
    pos = source.index(name + '(')
    start = source.rfind('\n', 0, pos) + 1
    brace = source.index('{', pos)
    depth = 1
    end = brace + 1
    while depth and end < len(source):
        if source[end] == '{':
            depth += 1
        elif source[end] == '}':
            depth -= 1
        end += 1
    if depth:
        raise AssertionError(f'incomplete source context for {name}')
    return source[start:end] + '\n'
