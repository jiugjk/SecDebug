#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Shared helpers: patched synthetic contexts, explicitly NOT real host trees."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from host_contract import apply_patch_isolated
from host_patch_apply import preimages


def patched_sources(patch: Path, destination: Path) -> dict[str, str]:
    raw_preimages = {name: text.encode('utf-8') for name, text in preimages(patch).items()}
    patched = apply_patch_isolated(destination, patch, raw_preimages)
    return {name: data.decode('utf-8') for name, data in patched.items()}


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
