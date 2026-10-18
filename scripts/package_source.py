#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Create a clean UNIX-mode ZIP from the deterministic release file list."""
from __future__ import annotations
import argparse
import os
from pathlib import Path
import stat
import zipfile

from host_contract import git

ROOT = Path(__file__).resolve().parents[1]
EXCLUDE_DIRS = {'.git', 'build', 'dist', '__pycache__', '.pytest_cache'}

# Explicit deterministic release manifest, also used when repacking an extracted
# source archive that does not carry a .git directory.
RELEASE_FILES: tuple[str, ...] = (
    '.github/workflows/ci.yml',
    '.gitignore',
    'DISCLAIMER.md',
    'LICENSE',
    'LICENSES/Apache-2.0.txt',
    'LICENSES/GPL-2.0.txt',
    'Makefile',
    'README.md',
    'README.zh-CN.md',
    'SECURITY.md',
    'THIRD_PARTY_NOTICES.md',
    'client/libsecdebug.c',
    'client/libsecdebug.h',
    'client/secdebug_host_abi.h',
    'client/test_secdebug.c',
    'host_patches/KernelSU-Next-KPatch-Next-456744b.patch',
    'host_patches/README.md',
    'host_patches/apply_checked.sh',
    'host_patches/bmax121-KernelPatch-f36f3d1.patch',
    'host_patches/hosts.json',
    'include/secdebug_internal.h',
    'include/secdebug_perf_abi.h',
    'include/secdebug_proto.h',
    'scripts/build_config.py',
    'scripts/check_stub_kpm.sh',
    'scripts/host_contract.py',
    'scripts/link_kpm.py',
    'scripts/package_source.py',
    'scripts/run_sanitizers.sh',
    'scripts/verify_symbols.py',
    'src/secdebug_core.c',
    'src/secdebug_hwbp.c',
    'src/secdebug_mem.c',
    'src/secdebug_session.c',
    'tests/build_regressions.py',
    'tests/client_protocol.c',
    'tests/client_session.c',
    'tests/config_safety.py',
    'tests/host_lifecycle.py',
    'tests/host_patch_apply.py',
    'tests/host_patch_bounds.py',
    'tests/patch_support.py',
    'tests/perf_attr_layout.c',
    'tests/proto_layout.c',
    'tests/runtime_regressions.c',
    'tests/runtime_regressions.py',
    'tests/session_state.c',
    'tests/source_invariants.py',
    'tests/stub_host/README.md',
    'tests/stub_host/asm/current.h',
    'tests/stub_host/compiler.h',
    'tests/stub_host/kpmodule.h',
    'tests/stub_host/kputils.h',
    'tests/stub_host/ktypes.h',
    'tests/stub_host/linux/err.h',
    'tests/stub_host/linux/printk.h',
    'tests/stub_host/linux/string.h',
    'tests/stub_host/uapi/asm-generic/errno.h',
)


def release_paths(root: Path = ROOT) -> list[Path]:
    root = root.resolve()
    expected = list(RELEASE_FILES)
    if (root / '.git').exists():
        try:
            raw_out = git(root, 'ls-files', '-z')
        except ValueError as exc:
            raise RuntimeError(f'git ls-files failed: {exc}') from exc
        tracked = sorted(os.fsdecode(raw) for raw in raw_out.split(b'\0') if raw)
        if tracked != expected:
            raise RuntimeError('tracked Git file list does not match RELEASE_FILES manifest')
    paths: list[Path] = []
    for rel_str in expected:
        rel = Path(rel_str)
        if any(part in EXCLUDE_DIRS or part.startswith('build-') for part in rel.parts):
            raise RuntimeError(f'excluded directory in release manifest: {rel}')
        path = root / rel
        if path.is_symlink():
            raise RuntimeError(f'refusing symlink in release archive: {rel}')
        if not path.is_file():
            raise RuntimeError(f'missing release source file: {rel}')
        if not path.resolve().is_relative_to(root):
            raise RuntimeError(f'release file escapes source root: {rel}')
        paths.append(path)
    return paths


def package(destination: Path, root: Path = ROOT) -> None:
    root = root.resolve()
    destination = destination.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    files = release_paths(root)
    if any(path.resolve() == destination for path in files):
        raise RuntimeError('refusing to overwrite a release source file with the output archive')
    with zipfile.ZipFile(destination, 'w', compression=zipfile.ZIP_DEFLATED,
                         compresslevel=9, strict_timestamps=False) as archive:
        for path in files:
            rel = path.relative_to(root)
            info = zipfile.ZipInfo(f'secdebug/{rel.as_posix()}', (2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3  # UNIX: chmod survives unzip on POSIX hosts
            # Restores script execution bits even if the input ZIP or an
            # extraction tool discarded all POSIX permission metadata.
            executable = rel.suffix in {'.sh', '.py'} and path.read_bytes().startswith(b'#!')
            mode = stat.S_IFREG | (0o755 if executable else 0o644)
            info.external_attr = (mode << 16)
            archive.writestr(info, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED,
                             compresslevel=9)
    with zipfile.ZipFile(destination) as archive:
        if archive.testzip() is not None:
            raise RuntimeError('archive CRC failure')
        names = archive.namelist()
        assert not any('/.git/' in name for name in names)
        assert names == [f'secdebug/{rel}' for rel in RELEASE_FILES]
    print(f'Created {destination} ({len(files)} source files, no .git/build/dist)')


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'dist' / 'SecDebug-source.zip')
    args = parser.parse_args()
    package(args.output)


if __name__ == '__main__':
    main()
