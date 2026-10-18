#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise the real gate and Makefile; all mock-host builds stay in temp dirs.

Only the temp PROJECT COPY has a synthetic SHA in its manifest. Production
code has no environment variable, flag or fallback that permits fake hosts.
"""
from pathlib import Path
import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from host_patch_apply import preimages

ROOT = Path(__file__).resolve().parents[1]


def run(args, cwd=ROOT, env=None, success=True):
    if os.environ.get('SECDEBUG_TEST_TRACE'):
        print('RUN', ' '.join(map(str, args)), flush=True)
    result = subprocess.run(args, cwd=cwd, env=env, capture_output=True, text=True, timeout=120)
    if success:
        assert result.returncode == 0, result.stdout + result.stderr
    return result


def copy_release_tree(destination: Path) -> None:
    sys.path.insert(0, str(ROOT / 'scripts'))
    from package_source import RELEASE_FILES
    for rel in RELEASE_FILES:
        src = ROOT / rel
        dst = destination / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)


COMPILER = r'''#!/usr/bin/env python3
import os, pathlib, subprocess, sys
if sys.argv[1:] == ['--version']:
    print('SecDebug native ELF dependency fixture, not an ARM64 compiler')
    sys.exit(0)
args = sys.argv[1:]
output = pathlib.Path(args[args.index('-o') + 1])
source = pathlib.Path(args[-1]).stem
offset = '-1'
for arg in args:
    if arg.startswith('-DSECDEBUG_TARGET_PAGE_SHIFT='):
        offset = str(int(arg.split('=', 1)[1], 0))
code = f'long fixture_{source} = {offset};\n'
if os.environ.get('SECDEBUG_FIXTURE_BAD') == '1' and source.endswith('core'):
    code += 'extern int forbidden_import_for_test; int probe(void) { return forbidden_import_for_test; }\n'
with open(os.environ['SECDEBUG_FIXTURE_LOG'], 'a') as log:
    log.write(source + ':' + offset + '\n')
subprocess.run(['cc', '-x', 'c', '-c', '-o', str(output), '-'], input=code, text=True, check=True)
'''


def main():
    with tempfile.TemporaryDirectory(prefix='secdebug-build-') as tmp:
        base = Path(tmp)
        host = base / 'host'
        host.mkdir()
        patch_name = 'bmax121-KernelPatch-f36f3d1.patch'
        patch = ROOT / 'host_patches' / patch_name
        for name, text in preimages(patch).items():
            file = host / name
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text(text)
        header = host / 'kernel/fixture.h'
        header.write_text('/* pinned synthetic host header */\n')
        run(['git', 'init', '-q', str(host)])
        run(['git', 'add', '.'], cwd=host)
        run(['git', '-c', 'user.name=Test Fixture', '-c', 'user.email=test@example.invalid',
             '-c', 'commit.gpgsign=false', 'commit', '-qm', 'SYNTHETIC test fixture'], cwd=host)
        sha = run(['git', 'rev-parse', 'HEAD'], cwd=host).stdout.strip()
        env = dict(os.environ, SECDEBUG_FIXTURE_LOG=str(base / 'compiler.log'))
        for key in ('MAKEFLAGS', 'MFLAGS', 'SECDEBUG_PERF_PENDING_OFFSET', 'HOST_COMMIT'):
            env.pop(key, None)
        compiler = base / 'compiler.py'
        compiler.write_text(COMPILER)
        args = [f'KP_DIR={host}', f'HOST_COMMIT={sha}', 'TARGET_PAGE_SHIFT=12',
                'SECDEBUG_FOLL_FORCE=0', 'HOST_CONTRACT_ACK=I_ACKNOWLEDGE_VERIFIED_HOST',
                f'CLANG={shlex.quote(sys.executable)} {shlex.quote(str(compiler))}', 'LLD=ld']
        # The original production gate must reject even this plausible host.
        refusal = run(['make', '--no-print-directory', *args, 'check-host-contract'],
                      env=env, success=False)
        assert refusal.returncode and 'unsupported HOST_COMMIT' in refusal.stderr
        print('production allow-list rejects synthetic/arbitrary Git HEAD: PASS')

        project = base / 'project'
        copy_release_tree(project)
        manifest = project / 'host_patches/hosts.json'
        spec = next(x for x in json.loads(manifest.read_text())['hosts'] if x['patch'] == patch_name)
        spec['commit'] = sha
        spec['module_blob'] = run(['git', 'hash-object', 'kernel/patch/module/module.c'], cwd=host).stdout.strip()
        manifest.write_text(json.dumps({'schema': 1, 'hosts': [spec]}, indent=2) + '\n')
        build = base / 'output'

        def make(*extra, success=True, folder=build, environment=env):
            return run(['make', '--no-print-directory', f'BUILD_DIR={folder}', *args, *extra],
                       cwd=project, env=environment, success=success)

        def compiles():
            log = base / 'compiler.log'
            return len(log.read_text().splitlines()) if log.exists() else 0

        denied = make('check-host-contract', success=False)
        assert denied.returncode and 'host source mismatch' in denied.stderr and compiles() == 0
        nested_tmp = project / 'build-tmp-inside-git'
        nested_tmp.mkdir()
        run(['git', 'init', '-q', str(project)])
        nested_env = dict(env, TMPDIR=str(nested_tmp), GIT_DIR=str(project / '.git'),
                          GIT_WORK_TREE=str(project))
        denied_nested = make('check-host-contract', success=False, environment=nested_env)
        assert denied_nested.returncode and 'host source mismatch' in denied_nested.stderr and compiles() == 0
        shutil.rmtree(nested_tmp)
        shutil.rmtree(project / '.git')
        print('known baseline without safety patch is rejected before compilation (including nested-Git TMPDIR): PASS')
        run(['sh', str(project / 'host_patches/apply_checked.sh'), str(host), 'KernelPatch', '--check'], env=env)
        run(['sh', str(project / 'host_patches/apply_checked.sh'), str(host), 'KernelPatch', '--apply'], env=env)
        make('check-host-contract')
        assert not run(['git', 'diff', '--cached', '--name-only'], cwd=host).stdout
        print('checked installer and exact patched-source verification: PASS')

        rcu = host / 'kernel/linux/include/linux/rcupdate.h'
        fixed_rcu = rcu.read_bytes()
        rcu.write_bytes(run(['git', 'show', 'HEAD:kernel/linux/include/linux/rcupdate.h'], cwd=host).stdout.encode())
        assert make('check-host-contract', success=False).returncode
        rcu.write_bytes(fixed_rcu)
        original_header = header.read_bytes()
        header.write_text('/* unreviewed changed header */\n')
        assert make('check-host-contract', success=False).returncode
        header.write_bytes(original_header)
        extra = host / 'kernel/shadow.h'
        extra.write_text('/* untracked source */\n')
        assert make('check-host-contract', success=False).returncode
        (host / '.git/info/exclude').write_text('kernel/shadow.h\n')
        assert make('check-host-contract', success=False).returncode
        extra.unlink()
        print('partial patch, modified tracked header and ignored/untracked headers rejected: PASS')
        for offset in ('0', '1', '128', '0x100000'):
            denied = make(f'SECDEBUG_PERF_PENDING_OFFSET={offset}', success=False)
            assert denied.returncode and 'SECDEBUG_PERF_PENDING_OFFSET is unsupported' in denied.stderr
        assert compiles() == 0
        print('all raw perf offsets, including zero and plausible values, rejected: PASS')

        make()
        kpm = build / 'secdebug.kpm'
        metadata = build / 'BUILD-METADATA.txt'
        assert kpm.exists() and metadata.exists() and compiles() == 4
        make()
        assert compiles() == 4
        make('KPM_TUNE=cortex-a78')
        assert compiles() == 8
        config = json.loads((build / 'build-config.json').read_text())
        assert config['inputs']['KPM_TUNE'] == 'cortex-a78'
        assert '-mtune=cortex-a78' in config['inputs']['KPM_CFLAGS']
        assert 'kpm tune cortex-a78\n' in metadata.read_text()
        make('KPM_TUNE=cortex-a78')
        assert compiles() == 8
        make('KPM_TUNE=generic')
        assert compiles() == 12
        config = json.loads((build / 'build-config.json').read_text())
        assert '-mtune=' not in config['inputs']['KPM_CFLAGS']
        invalid = make('KPM_TUNE=invalid!cpu', success=False)
        assert invalid.returncode and 'KPM_TUNE must' in invalid.stderr
        print('default build, unchanged cache, CPU tuning fingerprint and validation: PASS')
        before = kpm.read_bytes()
        for shift in ('14', '16', '12'):
            count = compiles()
            make('-j4', f'TARGET_PAGE_SHIFT={shift}')
            assert compiles() == count + 4 and kpm.read_bytes() != before
            assert f'page shift {shift}\n' in metadata.read_text()
            before = kpm.read_bytes()
        print('verified build-parameter changes recompile all objects: PASS')
        count = compiles()
        metadata.unlink()
        make()
        assert metadata.exists() and compiles() == count
        assert f'kpm sha256 {hashlib.sha256(kpm.read_bytes()).hexdigest()}' in metadata.read_text()
        assert 'hardware breakpoint mode one-shot-no-offset' in metadata.read_text()
        print('missing metadata regenerated with exact ELF hash and safety mode: PASS')

        bad_env = dict(env, SECDEBUG_FIXTURE_BAD='1')
        for attempt in range(2):
            rejected = base / 'rejected'
            result = make(folder=rejected, environment=bad_env, success=False)
            assert result.returncode and 'forbidden_import_for_test' in result.stdout
            assert not (rejected / 'secdebug.kpm').exists()
            assert not (rejected / 'BUILD-METADATA.txt').exists()
        print('repeated prohibited-symbol builds leave no apparent release artifacts: PASS')

        # Real GNU ELF name rendering, with the supported fallback forced.
        wrapper = '''import importlib.util, shutil, sys
spec=importlib.util.spec_from_file_location("verifier", sys.argv[1])
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
original=shutil.which
m.shutil.which=lambda name: None if name == "llvm-readelf" else original(name)
sys.exit(0 if m.verify_kpm(sys.argv[2]) else 1)
'''
        for symbol, accepted in (('task_in_thread_info_offset', True),
                                 ('task_in_thread_info_offset_forbidden', False)):
            source = base / 'long_symbol.c'
            obj = base / 'long_symbol.o'
            source.write_text(f'extern int {symbol}; int probe(void) {{ return {symbol}; }}\n')
            run(['cc', '-c', str(source), '-o', str(obj)])
            result = run([sys.executable, '-c', wrapper,
                          str(ROOT / 'scripts/verify_symbols.py'), str(obj)], success=False)
            assert (result.returncode == 0) == accepted, result.stdout + result.stderr
            if not accepted:
                assert symbol in result.stdout and '[...]' not in result.stdout
        print('GNU readelf accepts allowed long symbol and rejects forbidden long symbol: PASS')

        import zipfile
        sys.path.insert(0, str(ROOT / 'scripts'))
        from package_source import RELEASE_FILES, package
        pack_copy = base / 'pack_copy'
        copy_release_tree(pack_copy)
        for noisy in ('.env', 'notes.txt', 'core', 'dump.bin', 'extra.zip'):
            (pack_copy / noisy).write_text('synthetic local artifact for packaging test\n')
        zip_no_git = base / 'SecDebug-from-tarball.zip'
        package(zip_no_git, root=pack_copy)
        with zipfile.ZipFile(zip_no_git) as zf:
            assert zf.namelist() == [f'secdebug/{rel}' for rel in RELEASE_FILES]
        run(['git', 'init', '-q', str(pack_copy)])
        for rel in RELEASE_FILES:
            run(['git', 'add', '-f', rel], cwd=pack_copy)
        (pack_copy / '.gitignore').write_text((pack_copy / '.gitignore').read_text() + '\n.env\n')
        fsmonitor_marker = base / 'malicious-fsmonitor-executed'
        for repo_cfg in (host / '.git/config', pack_copy / '.git/config'):
            repo_cfg.write_text(
                repo_cfg.read_text() +
                f'\n[core]\n\tfsmonitor = touch {shlex.quote(str(fsmonitor_marker))}\n'
                f'\thooksPath = {shlex.quote(str(base / "evil-hooks"))}\n'
                f'\tpager = touch {shlex.quote(str(fsmonitor_marker))}\n'
                f'[diff]\n\texternal = touch {shlex.quote(str(fsmonitor_marker))}\n'
            )
        make('check-host-contract')
        make('BUILD_DIR=' + str(base / 'output-malicious-cfg'))
        zip_with_git = base / 'SecDebug-from-git.zip'
        package(zip_with_git, root=pack_copy)
        assert not fsmonitor_marker.exists()
        with zipfile.ZipFile(zip_with_git) as zf:
            assert zf.namelist() == [f'secdebug/{rel}' for rel in RELEASE_FILES]
            assert not any(name.endswith(('.env', 'notes.txt', 'core', 'dump.bin', 'extra.zip'))
                           for name in zf.namelist())
        print('release source packaging excludes untracked/ignored local files and isolates local .git/config (fsmonitor/hooks/diff.external): PASS')


if __name__ == '__main__':
    main()
