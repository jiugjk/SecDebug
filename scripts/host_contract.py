#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify the pinned source tree PLUS the complete approved safety patch.

The working tree/index are never reset. Expected patched bytes are constructed
in a temporary directory from Git HEAD, not inferred from marker strings.
This is source verification, not attestation of the kernel running on a device.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / 'host_patches/hosts.json'
CONTRACT = '0x53440101'


def git(host: Path, *args: str) -> bytes:
    env = dict(os.environ, GIT_NO_REPLACE_OBJECTS='1')
    for key in ('GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE'):
        env.pop(key, None)
    proc = subprocess.run(['git', '-C', str(host), *args], env=env,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.returncode:
        raise ValueError(proc.stderr.decode(errors='replace').strip() or 'git command failed')
    return proc.stdout


def blob_sha(data: bytes) -> str:
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()


def host_spec(commit: str) -> dict:
    if not re.fullmatch('[0-9a-f]{40}', commit):
        raise ValueError('HOST_COMMIT must be a full lowercase 40-character SHA')
    hosts = json.loads(MANIFEST.read_text())['hosts']
    for item in hosts:
        if item['commit'] == commit:
            patch = ROOT / 'host_patches' / item['patch']
            if hashlib.sha256(patch.read_bytes()).hexdigest() != item['patch_sha256']:
                raise ValueError('safety patch checksum mismatch; review the patch and manifest together')
            return item
    raise ValueError('unsupported HOST_COMMIT; arbitrary checkouts and KernelPatch LKM are not supported')


def verify_host(directory: str | Path, commit: str, *, patched: bool = True) -> dict:
    host = Path(directory).resolve()
    item = host_spec(commit)
    top = git(host, 'rev-parse', '--show-toplevel').decode().strip()
    if Path(top).resolve() != host:
        raise ValueError('KP_DIR must be the host Git worktree root')
    if git(host, 'rev-parse', 'HEAD').decode().strip() != commit:
        raise ValueError('HOST_COMMIT does not match host HEAD')
    tree: dict[str, tuple[str, str]] = {}
    for entry in git(host, 'ls-tree', '-rz', 'HEAD', '--', 'kernel').split(b'\0'):
        if not entry:
            continue
        meta, raw_name = entry.split(b'\t', 1)
        mode, kind, sha = meta.decode().split()
        name = os.fsdecode(raw_name)
        if kind != 'blob' or mode not in ('100644', '100755', '120000'):
            raise ValueError(f'unsupported source-tree entry: {name}')
        tree[name] = (mode, sha)
    module = 'kernel/patch/module/module.c'
    if module not in tree or tree[module][1] != item['module_blob']:
        raise ValueError('host loader preimage does not match the pinned module.c blob')
    patch = ROOT / 'host_patches' / item['patch']
    paths = re.findall(r'^--- a/(.+)$', patch.read_text(), re.M)
    if not paths or any(name not in tree for name in paths):
        raise ValueError('patch targets are missing from the host tree')
    if patched:
        with tempfile.TemporaryDirectory(prefix='secdebug-expected-host-') as tmp:
            target = Path(tmp)
            for name in paths:
                file = target / name
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_bytes(git(host, 'show', f'HEAD:{name}'))
            proc = subprocess.run(['git', 'apply', str(patch)], cwd=target,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if proc.returncode:
                raise ValueError('approved patch does not apply to pinned source: ' +
                                 proc.stderr.decode(errors='replace'))
            for name in paths:
                tree[name] = (tree[name][0], blob_sha((target / name).read_bytes()))
    digest = hashlib.sha256()
    for name, (mode, expected) in sorted(tree.items()):
        file = host / name
        if mode == '120000':
            if not file.is_symlink():
                raise ValueError(f'missing tracked symlink: {name}')
            data = os.fsencode(os.readlink(file))
            if not file.resolve().is_relative_to(host):
                raise ValueError(f'symlink escapes host source tree: {name}')
        else:
            if file.is_symlink() or not file.is_file():
                raise ValueError(f'missing/redirected host source: {name}')
            data = file.read_bytes()
        if blob_sha(data) != expected:
            raise ValueError(f'host source mismatch: {name}; apply the complete approved patch, with no extra kernel edits')
        digest.update(name.encode() + b'\0' + expected.encode() + b'\n')
    # Ignored source files can also shadow an include. Build products such as
    # .o are harmless here, but added source/linker inputs are not permitted.
    for file in (host / 'kernel').rglob('*'):
        if file.is_symlink() and file.relative_to(host).as_posix() not in tree:
            raise ValueError(f'untracked host symlink: {file.relative_to(host)}')
        if file.is_file() and file.suffix.lower() in {'.h', '.c', '.s', '.inc', '.ld'}:
            if file.relative_to(host).as_posix() not in tree:
                raise ValueError(f'untracked host source: {file.relative_to(host)}')
    return {'fork': item['fork'], 'commit': commit, 'contract': CONTRACT,
            'patch_sha256': item['patch_sha256'], 'source_tree_sha256': digest.hexdigest()}


def validate_build_inputs() -> None:
    env = os.environ
    if env.get('HOST_CONTRACT_ACK') != 'I_ACKNOWLEDGE_VERIFIED_HOST':
        raise ValueError('set HOST_CONTRACT_ACK=I_ACKNOWLEDGE_VERIFIED_HOST only after target review')
    if not re.fullmatch('[A-Za-z][A-Za-z0-9_-]*', env.get('KPM_TUNE', '')):
        raise ValueError('KPM_TUNE must be one compiler-supported CPU tune name')
    if env.get('TARGET_PAGE_SHIFT') not in ('12', '14', '16'):
        raise ValueError('specify verified TARGET_PAGE_SHIFT=12,14,16')
    force = env.get('SECDEBUG_FOLL_FORCE', '')
    if not re.fullmatch(r'(0|[1-9][0-9]*|0[xX][0-9a-fA-F]+)', force):
        raise ValueError('specify SECDEBUG_FOLL_FORCE from the target header, or 0')
    value = int(force, 16 if force.lower().startswith('0x') else 10)
    if value > 0xffffffff or (value and value & (value - 1)) or value == 1:
        raise ValueError('SECDEBUG_FOLL_FORCE must be 0 or a single uint32 flag other than FOLL_WRITE')
    if env.get('SECDEBUG_PERF_PENDING_OFFSET', '').strip():
        raise ValueError('SECDEBUG_PERF_PENDING_OFFSET is unsupported; hardware breakpoints are one-shot')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', type=Path)
    parser.add_argument('--commit')
    parser.add_argument('--fork', choices=('KernelPatch', 'KPatch-Next'))
    parser.add_argument('--action', choices=('check', 'apply', 'verify'), default='verify')
    parser.add_argument('--build', action='store_true')
    args = parser.parse_args()
    try:
        if args.build:
            validate_build_inputs()
        directory = args.host or os.environ.get('KP_DIR', '')
        commit = args.commit or os.environ.get('HOST_COMMIT', '')
        if args.fork:
            spec = next(x for x in json.loads(MANIFEST.read_text())['hosts'] if x['fork'] == args.fork)
            if commit and commit != spec['commit']:
                raise ValueError('fork and commit disagree')
            commit = spec['commit']
        if not directory:
            raise ValueError('host directory is required')
        if args.action in ('check', 'apply'):
            item = host_spec(commit)
            if git(Path(directory), 'status', '--porcelain').strip():
                raise ValueError('installer requires a clean worktree and index')
            verify_host(directory, commit, patched=False)
            patch = str(ROOT / 'host_patches' / item['patch'])
            git(Path(directory), 'apply', '--check', patch)
            if args.action == 'apply':
                git(Path(directory), 'apply', patch)
                verify_host(directory, commit)
        else:
            verify_host(directory, commit)
        print(f'Host source {args.action}: PASS ({commit}). Not a device runtime safety proof.')
        return 0
    except (ValueError, OSError, KeyError, StopIteration) as exc:
        print(f'Host contract: REFUSED: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
