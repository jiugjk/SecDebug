#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Create a clean UNIX-mode ZIP while excluding Git history and build outputs."""
import argparse
from pathlib import Path
import stat
import zipfile

ROOT = Path(__file__).resolve().parents[1]
EXCLUDE_DIRS = {'.git', 'build', 'dist', '__pycache__', '.pytest_cache'}
EXCLUDE_FILES = {'.DS_Store'}


def package(destination: Path):
    destination = destination.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    files = []
    for path in ROOT.rglob('*'):
        rel = path.relative_to(ROOT)
        if any(part in EXCLUDE_DIRS or part.startswith('build-') for part in rel.parts):
            continue
        if rel.name in EXCLUDE_FILES or rel.name.endswith(('.pyc', '.swp', '~', '.o', '.kpm', '.a', '.so')):
            continue
        if path.is_symlink():
            raise RuntimeError(f'refusing symlink in release archive: {rel}')
        if path.is_file() and path.resolve() != destination:
            files.append(path)
    with zipfile.ZipFile(destination, 'w', compression=zipfile.ZIP_DEFLATED,
                         compresslevel=9, strict_timestamps=False) as archive:
        for path in sorted(files):
            rel = path.relative_to(ROOT)
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
        assert not any('/.git/' in name for name in archive.namelist())
    print(f'Created {destination} ({len(files)} source files, no .git/build/dist)')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT/'dist'/'SecDebug-source.zip')
    args = parser.parse_args()
    package(args.output)

if __name__ == '__main__':
    main()
