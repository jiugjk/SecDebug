#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Write a stable, content-based KPM configuration prerequisite."""
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile

from host_contract import git, verify_host, validate_build_inputs

ROOT = Path(__file__).resolve().parents[1]
FIELDS = ('KP_DIR', 'HOST_COMMIT', 'TARGET_ARCH', 'KPM_TUNE', 'TARGET_PAGE_SHIFT',
          'SECDEBUG_FOLL_FORCE', 'SECDEBUG_PERF_PENDING_OFFSET',
          'KPM_CFLAGS', 'INCLUDE_FLAGS', 'CLANG', 'LLD')


def tool_identity(command):
    args = shlex.split(command)
    if not args:
        raise ValueError('empty compiler/linker command')
    binary = shutil.which(args[0])
    if binary is None:
        raise ValueError(f'tool not found: {args[0]}')
    version = subprocess.check_output([*args, '--version'], stderr=subprocess.STDOUT)
    command_files = {}
    for arg in args[1:]:
        candidate = Path(arg) if Path(arg).is_file() else Path(shutil.which(arg) or '')
        if candidate.is_file():
            command_files[str(candidate.resolve())] = hashlib.sha256(candidate.read_bytes()).hexdigest()
    return {'path': str(Path(binary).resolve()),
            'sha256': hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
            'command_files': command_files,
            'version': version.decode('utf-8', errors='replace').strip()}


def configuration():
    validate_build_inputs()
    fields = {key: os.environ.get(key, '') for key in FIELDS}
    host = Path(fields['KP_DIR']).resolve()
    fields['KP_DIR'] = str(host)
    contract = verify_host(host, fields['HOST_COMMIT'])
    actual = git(host, 'rev-parse', 'HEAD').decode().strip()
    if actual != fields['HOST_COMMIT']:
        raise ValueError('host commit changed during build')
    # Includes staged and unstaged changes to loader sources and headers.
    digest = hashlib.sha256(git(host, 'diff', '--no-ext-diff',
                                '--binary', 'HEAD', '--', 'kernel'))
    untracked = git(host, 'ls-files', '--others',
                    '--exclude-standard', '-z', '--', 'kernel')
    for raw in sorted(filter(None, untracked.split(b'\0'))):
        digest.update(raw + b'\0')
        digest.update(hashlib.sha256((host / os.fsdecode(raw)).read_bytes()).digest())
    version = re.search(r'^#define SECDEBUG_MOD_VER\s+"([^"]+)"',
                        (ROOT / 'include/secdebug_proto.h').read_text(), re.M)
    if not version:
        raise ValueError('missing module version')
    return {'schema': 2, 'host_contract': contract, 'module_version': version.group(1), 'inputs': fields,
            'host_changes_sha256': digest.hexdigest(),
            'compiler': tool_identity(fields['CLANG']),
            'linker': tool_identity(fields['LLD'])}


def main():
    destination = Path(sys.argv[1])
    data = (json.dumps(configuration(), sort_keys=True, indent=2) + '\n').encode()
    if destination.exists() and destination.read_bytes() == data:
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=destination.parent, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(data)
        os.replace(temporary, destination)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


if __name__ == '__main__':
    main()
