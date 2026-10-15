#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compile the *actual patched* list_modules functions and test tiny buffers.

These are host harness checks only; the mocked list/RCU are NOT the loader.
"""
from pathlib import Path
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PATCHES = sorted((ROOT / 'host_patches').glob('*.patch'))
assert len(PATCHES) == 2


def extract_function(patch: Path) -> str:
    lines = patch.read_text().splitlines()
    start = next(i for i, l in enumerate(lines) if l == ' int list_modules(char *out_names, int size)')
    end = next(i for i in range(start + 1, len(lines)) if lines[i] == ' int get_module_info(const char *name, char *out_info, int size)')
    code = []
    for row in lines[start:end]:
        if row.startswith((' ', '+')):
            code.append(row[1:])
        elif row.startswith('-'):
            pass
        else:
            raise AssertionError(f'{patch.name}: unexpected diff row {row!r}')
    return '\n'.join(code) + '\n'


PREFIX = r'''
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
struct module {
    struct { const char *name; } info;
    struct module *next;
};
static struct { struct module *list; } modules;
static int rcu_depth;
static void rcu_read_lock(void) { ++rcu_depth; }
static void rcu_read_unlock(void) { --rcu_depth; }
#define list_for_each_entry_rcu(pos, head, link) \
    for ((pos) = *(head); (pos) != NULL; (pos) = (pos)->next)
'''

SUFFIX = r'''
static void run_case(const char **names, int n, int size)
{
    struct module entries[5] = {0};
    unsigned char arena[256];
    char expected[256] = {0};
    int expected_len = 0;
    int i, rc;

    assert(n <= 5 && size <= (int)sizeof(arena));
    for (i = 0; i < n; i++) {
        entries[i].info.name = names[i];
        entries[i].next = i+1 < n ? &entries[i+1] : NULL;
    }
    modules.list = n ? &entries[0] : NULL;
    for (i = 0; i < n; i++) {
        size_t line_len = strlen(names[i]) + 1;
        if (size - expected_len <= (int)line_len)
            break;
        memcpy(expected + expected_len, names[i], line_len - 1);
        expected_len += (int)line_len;
        expected[expected_len - 1] = '\n';
    }
    if (expected_len)
        expected[expected_len - 1] = '\0';

    memset(arena, 0x5a, sizeof(arena));
    rc = list_modules((char *)arena, size);
    assert(rc == expected_len);
    assert(rcu_depth == 0);
    assert(!strcmp((char *)arena, expected));
    for (i = size; i < (int)sizeof(arena); i++)
        assert(arena[i] == 0x5a);
}

int main(void)
{
    const char *names[] = {"A", "Longer_Module_Name", "C", "xyz", "Tail"};
    const char *huge[] = {"This-Name-Is-Much-Longer-Than-A-Tiny-Buffer"};
    int size;
    assert(list_modules(NULL, 10) == -EINVAL);
    assert(list_modules(NULL, 0) == -EINVAL);
    assert(list_modules((char[2]){0}, 0) == -EINVAL);
    assert(list_modules((char[2]){0}, -1) == -EINVAL);
    assert(rcu_depth == 0);
    for (size = 1; size <= 100; size++) {
        run_case(names, 5, size);
        run_case(huge, 1, size);
        run_case(names, 1, size);
        run_case(names, 0, size);
    }
    puts("list_modules bounded output: PASS");
    return 0;
}
'''


def main():
    cc = os.environ.get('CC', 'cc')
    with tempfile.TemporaryDirectory(prefix='secdebug-patch-bounds-') as tmp:
        for patch in PATCHES:
            source = Path(tmp) / (patch.stem + '.c')
            binary = Path(tmp) / patch.stem
            source.write_text(PREFIX + extract_function(patch) + SUFFIX)
            cmd = [cc, '-std=c11', '-O1', '-Wall', '-Wextra', '-Werror', str(source), '-o', str(binary)]
            if os.environ.get('SECDEBUG_TEST_SANITIZE') == '1':
                cmd += ['-g', '-fsanitize=address,undefined', '-fno-omit-frame-pointer']
            elif os.environ.get('SECDEBUG_TEST_SANITIZERS'):
                cmd += ['-g', '-fsanitize=' + os.environ['SECDEBUG_TEST_SANITIZERS'],
                        '-fno-sanitize-recover=all']
            subprocess.run(cmd, check=True)
            subprocess.run([str(binary)], check=True)
            print(f'{patch.name}: bounded output compiled + exercised')
        check_outer_list(tmp, cc)


def check_outer_list(tmp, cc):
    from patch_support import patched_sources, function
    mock = r'''
#define __user
static int copies, copied_bytes, forced_size, copy_result = 2147483647;
static int compat_copy_to_user(char *dst, const char *src, int len)
{
    assert(rcu_depth == 0 && len > 0 && len <= 4096);
    assert(src[len - 1] == '\0');
    ++copies;
    copied_bytes = len;
    if (!dst) return -EFAULT;
    if (copy_result != 2147483647) {
        int result = copy_result;
        if (result > 0) memcpy(dst, src, (size_t)(result < len ? result : len));
        return result;
    }
    memcpy(dst, src, (size_t)len);
    return len;
}
static int injected_list_modules(char *buf, int size)
{
    return forced_size ? forced_size : list_modules(buf, size);
}
static int compat_strncpy_from_user(char *dst, const char *src, int len)
{
    if (!src) return -EFAULT;
    int n = (int)strlen(src);
    if (n >= len) return len;
    memcpy(dst, src, (size_t)n + 1);
    return n;
}
static int get_module_info(const char *name, char *buf, int size)
{
    assert(!strcmp(name, "secdebug"));
    if (forced_size) return forced_size;
    return snprintf(buf, (size_t)size, "name=secdebug\nargs=<redacted>\n");
}
#define list_modules injected_list_modules
'''
    exercise = r'''
#undef list_modules
int main(void)
{
    struct module entry = { { "secdebug" }, NULL };
    char out[128];
    int lengths[] = {-1, 0, 1, 8, 9, 4095, 4096, 8192, 2147483647};
    for (int populated = 0; populated <= 1; ++populated) {
        modules.list = populated ? &entry : NULL;
        const char *expected = populated ? "secdebug" : "";
        int required = (int)strlen(expected) + 1;
        for (unsigned i = 0; i < sizeof(lengths) / sizeof(lengths[0]); ++i) {
            memset(out, 0x5a, sizeof(out));
            copies = copied_bytes = 0;
            int rc = (int)call_kpm_list(out, lengths[i]);
            if (lengths[i] <= 0) assert(rc == -EINVAL && !copies);
            else if (lengths[i] < required) assert(rc == -ENOBUFS && !copies);
            else {
                assert(rc == (populated ? required : 0) && copies == 1 && copied_bytes == required);
                assert(!strcmp(out, expected));
            }
            for (unsigned j = copies ? (unsigned)required : 0; j < sizeof(out); ++j)
                assert(out[j] == 0x5a);
        }
    }
    copies = 0;
    forced_size = -EIO;
    assert(call_kpm_list(out, 8192) == -EIO && copies == 0);
    forced_size = 4097;
    assert(call_kpm_list(out, 8192) == -EOVERFLOW && copies == 0);
    forced_size = 0;
    assert(call_kpm_list(NULL, 8192) == -EFAULT);
    int bad_copy[] = {0, 1, -EFAULT, -EBUSY};
    modules.list = &entry;
    for (unsigned i = 0; i < sizeof(bad_copy)/sizeof(bad_copy[0]); ++i) {
        copy_result = bad_copy[i];
        assert(call_kpm_list(out, sizeof(out)) == -EFAULT);
        assert(call_kpm_info("secdebug", out, sizeof(out)) == -EFAULT);
    }
    copy_result = 2147483647;
    const char *info = "name=secdebug\nargs=<redacted>\n";
    int required = (int)strlen(info) + 1;
    for (int len = 1; len <= required + 2; ++len) {
        memset(out, 0x5a, sizeof(out)); copies = 0;
        int rc = (int)call_kpm_info("secdebug", out, len);
        if (len < required) assert(rc == -ENOBUFS && !copies);
        else assert(rc == required && copies == 1 && !strcmp(info, out));
        for (unsigned j = copies ? (unsigned)required : 0; j < sizeof(out); ++j)
            assert(out[j] == 0x5a);
    }
    copies = 0;
    forced_size = 2048;
    assert(call_kpm_info("secdebug", out, 8192) == -EOVERFLOW && !copies);
    forced_size = -ENOENT;
    assert(call_kpm_info("secdebug", out, 8192) == -ENOENT && !copies);
    forced_size = 0;
    assert(call_kpm_info("secdebug", NULL, 8192) == -EFAULT);
    char huge[80]; memset(huge, 'a', sizeof(huge)); huge[79] = 0;
    assert(call_kpm_info(huge, out, sizeof(out)) == -ENAMETOOLONG);
    assert(rcu_depth == 0);
    puts("list/info outer wrappers: empty/small/oversize/NUL/zero/short/negative copy: PASS");
    return 0;
}
'''
    for patch in PATCHES:
        destination = Path(tmp) / (patch.stem + '-contexts')
        destination.mkdir()
        contents = patched_sources(patch, destination)
        wrappers = contents['kernel/patch/common/supercall.c']
        code = function(wrappers, 'call_kpm_list') + function(wrappers, 'call_kpm_info')
        source = Path(tmp) / (patch.stem + '-outer.c')
        binary = source.with_suffix('')
        source.write_text(PREFIX + extract_function(patch) + mock + code + exercise)
        cmd = [cc, '-std=c11', '-O1', '-Wall', '-Wextra', '-Werror', str(source), '-o', str(binary)]
        sanitizers = os.environ.get('SECDEBUG_TEST_SANITIZERS', '')
        if os.environ.get('SECDEBUG_TEST_SANITIZE') == '1':
            sanitizers = 'address,undefined'
        if sanitizers:
            cmd += ['-g', '-fsanitize=' + sanitizers, '-fno-sanitize-recover=all', '-fno-omit-frame-pointer']
        subprocess.run(cmd, check=True)
        subprocess.run([str(binary)], check=True)
        print(f'{patch.name}: wrapper copy contract exercised')

if __name__ == '__main__':
    main()
