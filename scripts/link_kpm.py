#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Validate a temporary ELF before publishing the KPM and its metadata."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

from verify_symbols import verify_kpm


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--metadata', type=Path, required=True)
    parser.add_argument('objects', nargs='+')
    args = parser.parse_args()
    try:
        config_bytes = args.config.read_bytes()
        config = json.loads(config_bytes)
        values = config['inputs']
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='.kpm-link-', dir=args.output.parent) as tmp:
            candidate = Path(tmp) / 'secdebug.kpm'
            metadata = Path(tmp) / 'BUILD-METADATA.txt'
            subprocess.run([*shlex.split(values['LLD']), '-r', '-o', str(candidate),
                            *args.objects], check=True)
            if not verify_kpm(str(candidate)):
                raise ValueError('KPM symbol validation failed')
            metadata.write_text(
                f"secdebug module {config['module_version']}\n"
                f"loader commit {values['HOST_COMMIT']}\n"
                f"page shift {values['TARGET_PAGE_SHIFT']}\n"
                f"foll force {values['SECDEBUG_FOLL_FORCE']}\n"
                f"hardware breakpoint mode one-shot-no-offset\n"
                f"host contract {config['host_contract']['contract']}\n"
                f"host patch sha256 {config['host_contract']['patch_sha256']}\n"
                f"target arch {values['TARGET_ARCH']}\n"
                f"kpm tune {values['KPM_TUNE']}\n"
                f"host changes sha256 {config['host_changes_sha256']}\n"
                f"config sha256 {hashlib.sha256(config_bytes).hexdigest()}\n"
                f"kpm sha256 {hashlib.sha256(candidate.read_bytes()).hexdigest()}\n")
            os.replace(metadata, args.metadata)
            os.replace(candidate, args.output)
    except BaseException:
        # A failed or interrupted link must not leave an apparent release.
        args.output.unlink(missing_ok=True)
        args.metadata.unlink(missing_ok=True)
        raise


if __name__ == '__main__':
    main()
