#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compile patched loader functions and exercise controlled interleavings.

Mocks establish the API protocol, not real kernel locking or RCU correctness.
The re-entrant control call models a second request while A has dropped RCU.
"""
from pathlib import Path
import os
import shlex
import subprocess
import tempfile
from patch_support import patched_sources, function

ROOT = Path(__file__).resolve().parents[1]
PREFIX = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define __user
#define KP_EXPORT_SYMBOL(x)
#define KPM_NAME_LEN 32
#define KPM_ARGS_LEN 1024
#define logkfi(...) ((void)0)
#define logkfe(...) ((void)0)
typedef long (*mod_ctl0call_t)(const char *, char *, int);
typedef long (*mod_ctl1call_t)(void *, void *, void *);
typedef long (*mod_exitcall_t)(void *);
struct list_head { struct list_head *next, *prev; };
struct module {
    struct {const char *name;} info;
    char *args, *ctl_args;
    void *start;
    mod_ctl0call_t *ctl0;
    mod_ctl1call_t *ctl1;
    mod_exitcall_t *exit;
    struct list_head list;
    int unloading, ctl_active;
};
static struct module modules;
static int module_lock;
static int lock_held, irq_disabled, rcu_depth, grace_periods;
static int allocs, frees, exec_frees, fail_alloc;
static unsigned long spin_lock_irqsave(int *lock)
{
    assert(lock == &module_lock && !lock_held);
    unsigned long old = (unsigned long)irq_disabled;
    irq_disabled = lock_held = 1;
    return old;
}
static void spin_unlock_irqrestore(int *lock, unsigned long flags)
{
    assert(lock == &module_lock && lock_held && irq_disabled);
    lock_held = 0; irq_disabled = (int)flags;
}
static void rcu_read_lock(void) { ++rcu_depth; }
static void rcu_read_unlock(void) { assert(rcu_depth); --rcu_depth; }
static void real_synchronize_rcu(void)
{
    assert(!rcu_depth && !lock_held && !irq_disabled);
    ++grace_periods;
}
static void (*kf_synchronize_rcu)(void) = real_synchronize_rcu;
static void (*kf___rcu_read_lock)(void) = rcu_read_lock;
static void (*kf___rcu_read_unlock)(void) = rcu_read_unlock;
static unsigned long (*kf__raw_spin_lock_irqsave)(int *) = spin_lock_irqsave;
static void (*kf__raw_spin_unlock_irqrestore)(int *, unsigned long) = spin_unlock_irqrestore;
#define kfunc(x) kf_##x
#define kfunc_call(x, ...) if (kf_##x) return kf_##x(__VA_ARGS__)
#define container_of(ptr, type, field) ((type *)((char *)(ptr) - offsetof(type, field)))
#define list_for_each_entry(pos, head, field) \
    for (struct list_head *it = (head)->next; \
         it != (head) && ((pos) = container_of(it, struct module, field), 1); it = it->next)
static void list_del_rcu(struct list_head *node)
{
    assert(lock_held);
    node->prev->next = node->next; node->next->prev = node->prev;
}
static void *vmalloc(size_t size)
{
    assert(!rcu_depth && !lock_held);
    if (fail_alloc) return NULL;
    void *p = calloc(1, size); assert(p); ++allocs; return p;
}
static void kvfree(void *ptr)
{
    assert(!rcu_depth && !lock_held);
    if (ptr) { ++frees; free(ptr); }
}
static void kp_free_exec(void *ptr) { assert(ptr && !rcu_depth && !lock_held); ++exec_frees; }
'''
SUFFIX = r'''
static int outer_calls, nested_calls, exit_calls, refuse_exit;
static struct module *test_mod;
static long ctl0(const char *args, char *out, int len)
{
    (void)out; (void)len;
    assert(rcu_depth == 1 && test_mod->ctl_active >= 1 && !lock_held);
    rcu_read_unlock();
    assert(unload_module("secdebug", NULL) == -EBUSY);
    if (!strcmp(args, "outer-request-secret")) {
        ++outer_calls;
        assert(module_control0("secdebug", "nested-request", NULL, 0) == 17);
        assert(!strcmp(args, "outer-request-secret"));
    } else {
        assert(!strcmp(args, "nested-request"));
        ++nested_calls;
    }
    rcu_read_lock();
    return 17;
}
static long ctl1(void *a, void *b, void *c)
{
    (void)a; (void)b; (void)c;
    assert(test_mod->ctl_active == 1 && rcu_depth == 1);
    return 19;
}
static long fake_module_exit(void *unused)
{
    (void)unused;
    ++exit_calls;
    assert(!rcu_depth && !lock_held && !irq_disabled);
    assert(test_mod->unloading && !test_mod->ctl_active);
    assert(modules.list.next == &test_mod->list);
    assert(unload_module("secdebug", NULL) == -EBUSY);
    assert(module_control0("secdebug", "nested-request", NULL, 0) == -EBUSY);
    return refuse_exit ? -EBUSY : 0;
}
int main(void)
{
    mod_ctl0call_t c0 = ctl0;
    mod_ctl1call_t c1 = ctl1;
    mod_exitcall_t ex = fake_module_exit;
    modules.list.next = modules.list.prev = &modules.list;
    test_mod = vmalloc(sizeof(*test_mod));
    test_mod->info.name = "secdebug";
    test_mod->args = vmalloc(32); strcpy(test_mod->args, "private-load-token");
    test_mod->start = (void *)1;
    test_mod->ctl0 = &c0; test_mod->ctl1 = &c1; test_mod->exit = &ex;
    test_mod->list.next = test_mod->list.prev = &modules.list;
    modules.list.next = modules.list.prev = &test_mod->list;
    assert(secdebug_host_contract_v1() == 0x53440101UL);
    kf_synchronize_rcu = NULL;
    assert(!secdebug_host_contract_v1());
    assert(unload_module("secdebug", NULL) == -EOPNOTSUPP);
    assert(!test_mod->unloading && !exit_calls && !exec_frees);
    kf_synchronize_rcu = real_synchronize_rcu;
    kf__raw_spin_lock_irqsave = NULL;
    assert(!secdebug_host_contract_v1());
    kf__raw_spin_lock_irqsave = spin_lock_irqsave;
    assert(module_control0("secdebug", "outer-request-secret", NULL, 0) == 17);
    assert(outer_calls == 1 && nested_calls == 1 && !test_mod->ctl_active);
    assert(!test_mod->ctl_args && !grace_periods);
    assert(module_control1("secdebug", NULL, NULL, NULL) == 19);
    fail_alloc = 1;
    assert(module_control0("secdebug", "x", NULL, 0) == -ENOMEM);
    fail_alloc = 0;
    char too_long[KPM_ARGS_LEN + 1]; memset(too_long, 'x', sizeof(too_long));
    too_long[KPM_ARGS_LEN] = 0;
    assert(module_control0("secdebug", too_long, NULL, 0) == -E2BIG);
    refuse_exit = 1;
    assert(unload_module("secdebug", NULL) == -EBUSY);
    assert(exit_calls == 1 && grace_periods == 1 && !exec_frees);
    assert(!test_mod->unloading && !test_mod->ctl_active);
    assert(module_control0("secdebug", "outer-request-secret", NULL, 0) == 17);
    refuse_exit = 0;
    assert(unload_module("secdebug", NULL) == 0);
    assert(exit_calls == 2 && grace_periods == 3 && exec_frees == 1);
    assert(modules.list.next == &modules.list && allocs == frees);
    assert(unload_module("secdebug", NULL) == -ENOENT);
    assert(!lock_held && !irq_disabled && !rcu_depth);
#ifdef HAS_EVENT
    irq_disabled = 1;
    assert(notify_modules_event("irq-event", "args", NULL) == -EOPNOTSUPP);
    assert(notify_modules_event(NULL, NULL, NULL) == -EINVAL);
    assert(!lock_held && allocs == frees);
#endif
    puts("patched loader: real RCU target, missing primitives, request isolation, busy/refused/successful unload, bounded args, IRQ event refusal: PASS");
    return 0;
}
'''

def main():
    compiler = shlex.split(os.environ.get('CC', 'cc'))
    sanitizers = os.environ.get('SECDEBUG_TEST_SANITIZERS', '')
    with tempfile.TemporaryDirectory(prefix='secdebug-host-lifetime-') as tmp:
        for patch in sorted((ROOT / 'host_patches').glob('*.patch')):
            dest = Path(tmp) / patch.stem
            dest.mkdir()
            contents = patched_sources(patch, dest)
            src = contents['kernel/patch/module/module.c']
            wrapper = function(contents['kernel/linux/include/linux/rcupdate.h'], 'synchronize_rcu')
            names = ('find_module_locked', 'module_put_active', 'module_redact_args',
                     'secdebug_host_contract_v1', 'unload_module', 'module_control0', 'module_control1')
            code = PREFIX + wrapper + ''.join(function(src, n) for n in names)
            if 'notify_modules_event(' in src:
                code += '#define HAS_EVENT\n' + function(src, 'notify_modules_event')
            out = dest / 'exercise.c'
            out.write_text(code + SUFFIX)
            flags = ['-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror']
            if sanitizers:
                flags += ['-fsanitize=' + sanitizers, '-fno-sanitize-recover=all', '-fno-omit-frame-pointer']
            subprocess.run([*compiler, *flags, str(out), '-o', str(dest / 'exercise')], check=True)
            subprocess.run([str(dest / 'exercise')], check=True)
            print(patch.name + ': lifecycle exercised')

if __name__ == '__main__':
    main()
