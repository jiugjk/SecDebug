#define _GNU_SOURCE
/* SPDX-License-Identifier: GPL-2.0-only */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>

/* Actual project functions; only the BTI compiler attribute is adapted for
 * this x86 host harness. No real kernel is modified or accessed. */
#include "core_host_adapted.c"
#include "../src/secdebug_mem.c"
#include "session_host_adapted.c"
#include "hwbp_host_adapted.c"
#define syscall audit_syscall
#define getuid audit_getuid
#include "../client/libsecdebug.c"
#undef syscall
#undef getuid

struct mm_struct { unsigned refs; unsigned char bytes[2048]; };
struct task_struct { unsigned refs; int pid; struct mm_struct *mm; int tgid; };
static struct mm_struct target_mm;
static struct task_struct owner = {0, 1234, &target_mm, 1234};
static struct task_struct worker = {0, 1235, &target_mm, 1234};
static struct task_struct peer = {0, 2234, &target_mm, 2234};
static _Thread_local struct task_struct *current_task = &owner;
static int namespace_shift;
static int init_ns;
static _Thread_local int rcu_depth;
static int allocations_under_rcu, frees_under_rcu, copies_under_rcu;
static int fail_alloc, fail_close, fail_alloc_at, live_allocs, copy_fail;
static int copy_result = 2147483647;
static int pause_copy_fail_once;
static int pause_reaper_liveness_once;
static int reaper_reached_liveness;
static pthread_barrier_t copy_race_entered, copy_race_resume;
static pthread_barrier_t reaper_race_entered, reaper_race_resume;
struct perf_event { int enabled; void *handler; void *context; };
static struct perf_event *last_event;
static int live_events, perf_error, perf_enables, perf_atomic_disables, hit_on_enable;
unsigned int kver = 0x060100, kpver = 0x000d05;
static unsigned long host_contract = SECDEBUG_HOST_CONTRACT_V1;
unsigned long secdebug_host_contract_v1(void) { return host_contract; }

static void fake_lock(void) { ++rcu_depth; }
static void fake_unlock(void) { assert(rcu_depth > 0); --rcu_depth; }
static void *fake_vmalloc(unsigned long size)
{
    if (rcu_depth) __atomic_add_fetch(&allocations_under_rcu, 1, __ATOMIC_RELAXED);
    if (fail_alloc || (fail_alloc_at > 0 && --fail_alloc_at == 0)) return NULL;
    void *p = calloc(1, size);
    if (p) __atomic_add_fetch(&live_allocs, 1, __ATOMIC_RELAXED);
    return p;
}
static void fake_kvfree(const void *ptr)
{
    if (rcu_depth) __atomic_add_fetch(&frees_under_rcu, 1, __ATOMIC_RELAXED);
    int left = __atomic_sub_fetch(&live_allocs, 1, __ATOMIC_RELAXED);
    assert(left >= 0);
    free((void *)ptr);
}
static struct task_struct *fake_find(pid_t pid)
{
    if (pid == owner.pid - namespace_shift) return &owner;
    if (pid == worker.pid - namespace_shift) return &worker;
    if (pid == peer.pid - namespace_shift) return &peer;
    return NULL;
}
static struct task_struct *fake_get(struct task_struct *task)
{
    __atomic_add_fetch(&task->refs, 1, __ATOMIC_RELAXED);
    return task;
}
static struct task_struct *fake_find_get(pid_t pid)
{
    struct task_struct *task = fake_find(pid);
    return task ? fake_get(task) : NULL;
}
static void fake_put(struct task_struct *task)
{
    unsigned prev = __atomic_fetch_sub(&task->refs, 1, __ATOMIC_RELAXED);
    assert(prev > 0);
}
static struct mm_struct *fake_get_mm(struct task_struct *task)
{
    if (!task->mm) return NULL;
    __atomic_add_fetch(&task->mm->refs, 1, __ATOMIC_RELAXED);
    return task->mm;
}
static void fake_mmput(struct mm_struct *mm)
{
    unsigned prev = __atomic_fetch_sub(&mm->refs, 1, __ATOMIC_RELAXED);
    assert(prev > 0);
}
static pid_t fake_pid(struct task_struct *task, int type, void *ns)
{
    int nr = type == SECDEBUG_PIDTYPE_TGID ? task->tgid : task->pid;
    if (ns == &init_ns && current_task == &peer && task == &owner &&
        __atomic_exchange_n(&pause_reaper_liveness_once, 0, __ATOMIC_ACQ_REL)) {
        __atomic_store_n(&reaper_reached_liveness, 1, __ATOMIC_RELEASE);
        pthread_barrier_wait(&reaper_race_entered);
        pthread_barrier_wait(&reaper_race_resume);
    }
    return ns == &init_ns ? nr : nr - namespace_shift;
}
static int fake_access(struct mm_struct *mm, unsigned long addr, void *buf,
                       int len, unsigned int flags)
{
    assert(rcu_depth == 0);
    if (addr < 0x10000 || addr - 0x10000 + (unsigned)len > sizeof(mm->bytes)) return -EFAULT;
    if (flags & SECDEBUG_FOLL_WRITE) memcpy(mm->bytes + addr - 0x10000, buf, (size_t)len);
    else memcpy(buf, mm->bytes + addr - 0x10000, (size_t)len);
    return len;
}
static struct perf_event *fake_perf_create(struct perf_event_attr *raw, int cpu,
                                          struct task_struct *task, void *handler, void *context)
{
    const struct secdebug_perf_attr *attr = (const void *)raw;
    assert(rcu_depth == 0 && cpu == -1 && task);
    assert(attr->flags & PERF_DISABLED);
    if (perf_error) return (struct perf_event *)(long)perf_error;
    struct perf_event *event = calloc(1, sizeof(*event));
    assert(event);
    event->handler = handler;
    event->context = context;
    __atomic_add_fetch(&live_events, 1, __ATOMIC_RELAXED);
    last_event = event;
    return event;
}
static void fake_perf_enable(struct perf_event *event)
{
    assert(rcu_depth == 0);
    __atomic_add_fetch(&perf_enables, 1, __ATOMIC_RELAXED);
    event->enabled = 1;
    if (hit_on_enable) {
        struct bp_slot *slot = event->context;
        struct secdebug_bp_unreg_req unreg = {
            .slot_id = slot_lifecycle_id(slot->lifecycle)
        };
        assert(secdebug_hwbp_unregister(&unreg) == -EBUSY);
        struct pt_regs_arm64 regs = {.pc = 0x10000, .sp = 0x20000};
        bp_perf_handler(event, NULL, &regs);
    }
}
static void fake_perf_disable(struct perf_event *event)
{
    assert(rcu_depth == 0);
    event->enabled = 0;
}
static void fake_perf_disable_atomic(struct perf_event *event)
{
    __atomic_add_fetch(&perf_atomic_disables, 1, __ATOMIC_RELAXED);
    event->enabled = 0;
}
static void fake_perf_release(struct perf_event *event)
{
    assert(rcu_depth == 0);
    int left = __atomic_sub_fetch(&live_events, 1, __ATOMIC_RELAXED);
    assert(left >= 0);
    if (event == last_event) last_event = NULL;
    free(event);
}
struct task_struct *get_current(void) { return current_task ? current_task : &owner; }
uid_t current_uid(void) { return 0; }
uid_t audit_getuid(void) { return 0; }
int is_su_allow_uid(uid_t uid) { (void)uid; return 0; }
int printk(const char *fmt, ...) { (void)fmt; return 0; }
int compat_copy_to_user(void *dst, const void *src, int n)
{
    if (rcu_depth) __atomic_add_fetch(&copies_under_rcu, 1, __ATOMIC_RELAXED);
    if (__atomic_exchange_n(&pause_copy_fail_once, 0, __ATOMIC_ACQ_REL)) {
        pthread_barrier_wait(&copy_race_entered);
        pthread_barrier_wait(&copy_race_resume);
        return 0;
    }
    if (copy_fail) { --copy_fail; return 0; }
    if (copy_result != 2147483647) {
        int result = copy_result;
        copy_result = 2147483647;
        if (result > 0) memcpy(dst, src, (size_t)(result < n ? result : n));
        return result;
    }
    memcpy(dst, src, (size_t)n);
    return n;
}
unsigned long kallsyms_lookup_name(const char *name)
{
#define SYM(n, f) if (!strcmp(name, n)) return (unsigned long)(f)
    SYM("vmalloc", fake_vmalloc); SYM("kvfree", fake_kvfree);
    SYM("__rcu_read_lock", fake_lock); SYM("__rcu_read_unlock", fake_unlock);
    SYM("access_remote_vm", fake_access); SYM("find_task_by_vpid", fake_find);
    SYM("find_get_task_by_vpid", fake_find_get); SYM("get_task_struct", fake_get);
    SYM("put_task_struct", fake_put); SYM("get_task_mm", fake_get_mm);
    SYM("mmput", fake_mmput); SYM("__task_pid_nr_ns", fake_pid);
    SYM("init_pid_ns", &init_ns);
    SYM("perf_event_create_kernel_counter", fake_perf_create);
    SYM("perf_event_release_kernel", fake_perf_release);
    SYM("perf_event_enable", fake_perf_enable);
    SYM("perf_event_disable", fake_perf_disable);
    SYM("perf_event_disable_inatomic", fake_perf_disable_atomic);
#undef SYM
    return 0;
}
long audit_syscall(long nr, ...)
{
    if (nr == SYS_gettid) return current_task->pid - namespace_shift;
    va_list ap;
    va_start(ap, nr);
    const char *key = va_arg(ap, const char *);
    unsigned long cmd = (unsigned long)va_arg(ap, long);
    (void)key;
    if ((cmd & 0xffff) == SECDEBUG_HOST_CMD_HELLO) {
        va_end(ap); return SECDEBUG_HOST_KPN_HELLO_RESPONSE;
    }
    (void)va_arg(ap, const char *);
    const char *args = va_arg(ap, const char *);
    char *out = va_arg(ap, char *);
    int len = (int)va_arg(ap, long);
    va_end(ap);
    _Alignas(8) unsigned char decoded[SECDEBUG_ARGS_MAX];
    int n = b64_decode(args, (int)strlen(args), decoded, sizeof(decoded));
    assert(n >= (int)sizeof(struct secdebug_req_header));
    struct secdebug_req_header *req = (void *)decoded;
    fail_alloc = fail_close && req->cmd == SECDEBUG_CMD_MEM_SESSION_CLOSE;
    assert(rcu_depth == 0);
    fake_lock();
    long result = secdebug_control0(args, out, len);
    assert(rcu_depth == 1);
    fake_unlock();
    fail_alloc = 0;
    if (result < 0) { errno = (int)-result; return -1; }
    return result;
}

static void test_breakpoints(struct secdebug_client *client)
{
    uint32_t id = 0;
    struct secdebug_bp_hit_resp hit;
    assert(secdebug_register_bp(client, 1234, SECDEBUG_BP_TYPE_EXEC, 0x10001, 4, &id) == -EINVAL);
    perf_error = -ENOMEM;
    assert(secdebug_register_bp(client, 1234, SECDEBUG_BP_TYPE_EXEC, 0x10000, 4, &id) == -ENOMEM);
    perf_error = 0;
    assert(!live_events && !owner.refs && !live_allocs);
    /* Lose the registration receipt after creation: rollback must release all refs. */
    copy_fail = 1;
    assert(secdebug_register_bp(client, 1234, SECDEBUG_BP_TYPE_EXEC, 0x10000, 4, &id) == -EINPROGRESS);
    assert(!live_events && !owner.refs && !live_allocs);
    for (int fail = 1; fail <= 3; ++fail) {
        fail_alloc_at = fail;
        assert(secdebug_register_bp(client, 1234, SECDEBUG_BP_TYPE_EXEC, 0x10000, 4, &id) == -ENOMEM);
        assert(!live_events && !owner.refs && !live_allocs);
    }
    assert(secdebug_register_bp(client, 1234, SECDEBUG_BP_TYPE_EXEC, 0x10000, 4, &id) == 0);
    assert(id && last_event && live_events == 1 && last_event->enabled);
    struct perf_event *event = last_event;
    struct bp_slot *slot = event->context;
    struct pt_regs_arm64 regs = {.pc = 0x10000, .sp = 0x20000, .pstate = 5};
    regs.regs[7] = 0xabc;
    int disabled = perf_atomic_disables;
    bp_perf_handler(event, NULL, &regs);
    assert(perf_atomic_disables == disabled && !slot->hit_total && event->enabled);
    regs.pstate = 0;
    slot->seq = 1;
    bp_perf_handler(event, NULL, &regs);
    assert(perf_atomic_disables == disabled && !slot->hit_total && event->enabled);
    slot->seq = 0;
    bp_perf_handler(event, NULL, &regs);
    assert(perf_atomic_disables == disabled + 1 && slot->hit_total == 1 && !event->enabled);
    assert(secdebug_get_hit(client, id, false, &hit) == 0);
    assert(hit.hit_count == 1 && hit.regs.regs[7] == 0xabc && hit.trigger_addr == 0x10000);
    const int lost[] = {0, 1, -EFAULT, -EBUSY};
    for (unsigned i = 0; i < sizeof(lost)/sizeof(lost[0]); ++i) {
        copy_result = lost[i];
        assert(secdebug_get_hit(client, id, true, &hit) == -EINPROGRESS);
        assert(slot->hit_consumed == 0);
        assert(secdebug_get_hit(client, id, false, &hit) == 0 && hit.hit_count == 1);
    }
    int enabled = perf_enables;
    assert(secdebug_get_hit(client, id, true, &hit) == 0 && hit.hit_count == 1);
    assert(slot->hit_consumed == 1 && perf_enables == enabled && !event->enabled);
    assert(secdebug_get_hit(client, id, false, &hit) == 0 && hit.hit_count == 0);
    struct secdebug_bp_hit_req hreq = {.slot_id = id, .clear_hit = 0};
    struct secdebug_bp_unreg_req ureq = {.slot_id = id};
    uint64_t total = 0;
    fake_lock();
    assert(secdebug_hwbp_get_hit(&hreq, &hit, &total) == 0);
    assert(secdebug_hwbp_unregister(&ureq) == -EBUSY);
    secdebug_hwbp_finish_hit(&hreq, total, 0);
    assert(rcu_depth == 1);
    fake_unlock();
    assert(secdebug_unregister_bp(client, id) == 0);
    assert(secdebug_unregister_bp(client, id) < 0);
    assert(!live_events && !owner.refs && !live_allocs);
    /* IRQ may fire during enable, when registration still owns BUSY. */
    hit_on_enable = 1;
    assert(secdebug_register_bp(client, 1234, SECDEBUG_BP_TYPE_EXEC, 0x10000, 4, &id) == 0);
    hit_on_enable = 0;
    assert(secdebug_get_hit(client, id, false, &hit) == 0 && hit.hit_count == 1);
    assert(secdebug_unregister_bp(client, id) == 0);
    uint32_t ids[SECDEBUG_MAX_BP_SLOTS];
    for (int i = 0; i < SECDEBUG_MAX_BP_SLOTS; ++i)
        assert(secdebug_register_bp(client, 1234, SECDEBUG_BP_TYPE_WRITE, 0x10000, 8, &ids[i]) == 0);
    assert(secdebug_register_bp(client, 1234, SECDEBUG_BP_TYPE_WRITE, 0x10000, 8, &id) == -ENOSPC);
    for (int i = 0; i < SECDEBUG_MAX_BP_SLOTS; ++i)
        assert(secdebug_unregister_bp(client, ids[i]) == 0);
    assert(!live_events && !owner.refs && !live_allocs);
    puts("HWBP: allocation/create/receipt rollback, EL0 filter, seqlock contention, ACK lease, one-shot, BUSY enable, slot exhaustion: PASS");
}


static void test_namespace_worker(struct secdebug_client *client)
{
    uint32_t id;
    current_task = &worker;
    namespace_shift = 1233;
    /* Visible leader 1 / worker 2; stable init IDs are 1234 / 1235. */
    assert(secdebug_current_pid() == 2);
    assert(secdebug_register_bp(client, 1, SECDEBUG_BP_TYPE_EXEC, 0x10000, 4, &id) == 0);
    struct bp_slot *slot = last_event->context;
    assert(slot->owner == &worker && slot->owner_leader == &owner && slot->owner_tgid == 1234);
    assert(secdebug_unregister_bp(client, id) == 0);
    char data[1024]; size_t done;
    assert(secdebug_read_mem(client, 1, 0x10000, data, sizeof(data), &done) == (int)sizeof(data));
    assert(done == sizeof(data) && !worker.refs && !owner.refs && !target_mm.refs);
    current_task = &owner;
    namespace_shift = 0;
    puts("Nested PID namespace model: non-leader registration and stable-mm multi-block read: PASS");
}

static void *concurrent_session_open_worker(void *arg)
{
    int *rc_out = arg;
    struct secdebug_client client_a;
    char buf[1200];
    size_t done = 0;

    current_task = &owner;
    assert(secdebug_client_init(&client_a, NULL, 0x1234) == 0);
    *rc_out = secdebug_read_mem(&client_a, 1234, 0x10000, buf, sizeof(buf), &done);
    assert(done == 0 && client_a.pending_session_id == 0);
    assert(secdebug_client_cleanup_error(&client_a) == 0);
    assert(secdebug_client_destroy(&client_a) == 0);
    return NULL;
}

static void *concurrent_bp_register_worker(void *arg)
{
    int *rc_out = arg;
    struct secdebug_client client_a;
    uint32_t slot_a = 0;

    current_task = &owner;
    assert(secdebug_client_init(&client_a, NULL, 0x1234) == 0);
    *rc_out = secdebug_register_bp(&client_a, 1234, SECDEBUG_BP_TYPE_EXEC, 0x10000, 4, &slot_a);
    assert(slot_a == 0);
    assert(secdebug_client_destroy(&client_a) == 0);
    return NULL;
}

static void *concurrent_peer_session_worker(void *arg)
{
    int *rc_out = arg;
    struct secdebug_client client_b;
    char buf[1200];
    size_t done = 0;

    current_task = &peer;
    assert(secdebug_client_init(&client_b, NULL, 0x1234) == 0);
    *rc_out = secdebug_read_mem(&client_b, 1234, 0x10000, buf, sizeof(buf), &done);
    assert(*rc_out == (int)sizeof(buf) && done == sizeof(buf));
    assert(secdebug_client_destroy(&client_b) == 0);
    return NULL;
}

static void *concurrent_peer_bp_worker(void *arg)
{
    uint32_t *slot_out = arg;
    struct secdebug_client client_b;

    current_task = &peer;
    assert(secdebug_client_init(&client_b, NULL, 0x1234) == 0);
    assert(secdebug_register_bp(&client_b, 1234, SECDEBUG_BP_TYPE_WRITE, 0x10000, 8, slot_out) == 0);
    assert(*slot_out != 0);
    assert(secdebug_client_destroy(&client_b) == 0);
    return NULL;
}

static int active_session_count(void)
{
    int n = 0;
    for (int i = 0; i < SECDEBUG_MAX_MEM_SESSIONS; ++i) {
        uint32_t st = session_status(__atomic_load_n(&g_sessions[i].lifecycle, __ATOMIC_ACQUIRE));
        if (st != SESSION_FREE)
            ++n;
    }
    return n;
}

static void test_concurrent_create_rollback_leases(void)
{
    pthread_t th_a, th_b;
    int rc_a = 0, rc_b = 0;
    uint32_t slot_b = 0;
    struct secdebug_client client_b;

    assert(!pthread_barrier_init(&copy_race_entered, NULL, 2));
    assert(!pthread_barrier_init(&copy_race_resume, NULL, 2));
    assert(!pthread_barrier_init(&reaper_race_entered, NULL, 2));
    assert(!pthread_barrier_init(&reaper_race_resume, NULL, 2));

    /* Session OPEN: A is paused inside compat_copy_to_user before failing.
     * In the fixed implementation, A's slot stays SESSION_BUSY during copy,
     * so B's reaper skips A's slot and never reaches fake_pid liveness check.
     * In the legacy pre-SD-02 implementation, A published SESSION_ACTIVE early,
     * so B's reaper claims SESSION_BUSY and pauses at reaper_race_entered while
     * A resumes and attempts rollback CLOSE concurrently against B's BUSY lease. */
    __atomic_store_n(&pause_copy_fail_once, 1, __ATOMIC_RELEASE);
    __atomic_store_n(&pause_reaper_liveness_once, 1, __ATOMIC_RELEASE);
    __atomic_store_n(&reaper_reached_liveness, 0, __ATOMIC_RELEASE);
    assert(!pthread_create(&th_a, NULL, concurrent_session_open_worker, &rc_a));
    pthread_barrier_wait(&copy_race_entered);
#ifndef SECDEBUG_LEGACY_PRE_SD02_RACE
    {
        int busy_slots = 0;
        uint32_t id_a = 0;
        for (int i = 0; i < SECDEBUG_MAX_MEM_SESSIONS; ++i) {
            uint64_t life = __atomic_load_n(&g_sessions[i].lifecycle, __ATOMIC_ACQUIRE);
            if (session_status(life) != SESSION_FREE) {
                assert(session_status(life) == SESSION_BUSY);
                id_a = session_id(life);
                ++busy_slots;
            }
        }
        assert(busy_slots == 1 && id_a != 0);
        /* Public close/read cannot steal or observe A's uncommitted creation lease. */
        assert(secdebug_session_close(id_a) == -EBUSY);
    }
#endif
    assert(!pthread_create(&th_b, NULL, concurrent_peer_session_worker, &rc_b));
#ifdef SECDEBUG_LEGACY_PRE_SD02_RACE
    pthread_barrier_wait(&reaper_race_entered);
    assert(__atomic_load_n(&reaper_reached_liveness, __ATOMIC_ACQUIRE) == 1);
    pthread_barrier_wait(&copy_race_resume);
    assert(!pthread_join(th_a, NULL));
    pthread_barrier_wait(&reaper_race_resume);
    assert(!pthread_join(th_b, NULL));
#else
    assert(!pthread_join(th_b, NULL));
    assert(__atomic_load_n(&reaper_reached_liveness, __ATOMIC_ACQUIRE) == 0);
    __atomic_store_n(&pause_reaper_liveness_once, 0, __ATOMIC_RELEASE);
    pthread_barrier_wait(&copy_race_resume);
    assert(!pthread_join(th_a, NULL));
#endif
    current_task = &owner;
    assert(rc_a == -EINPROGRESS && rc_b == 1200);
#ifdef SECDEBUG_LEGACY_PRE_SD02_RACE
    assert(active_session_count() == 1 && target_mm.refs == 1 && owner.refs == 1 && peer.refs == 0);
    secdebug_session_cleanup();
#endif
    assert(active_session_count() == 0 && target_mm.refs == 0 && owner.refs == 0 && peer.refs == 0);
    assert(live_allocs == 0);

    /* Breakpoint REGISTER: same exact overlap test between A's failed copy/rollback
     * and B's reaper BUSY lease. */
    __atomic_store_n(&pause_copy_fail_once, 1, __ATOMIC_RELEASE);
    __atomic_store_n(&pause_reaper_liveness_once, 1, __ATOMIC_RELEASE);
    __atomic_store_n(&reaper_reached_liveness, 0, __ATOMIC_RELEASE);
    rc_a = 0;
    slot_b = 0;
    assert(!pthread_create(&th_a, NULL, concurrent_bp_register_worker, &rc_a));
    pthread_barrier_wait(&copy_race_entered);
#ifndef SECDEBUG_LEGACY_PRE_SD02_RACE
    {
        int busy_slots = 0;
        uint32_t id_a = 0;
        for (int i = 0; i < SECDEBUG_MAX_BP_SLOTS; ++i) {
            uint64_t life = __atomic_load_n(&g_bp_slots[i].lifecycle, __ATOMIC_ACQUIRE);
            if (slot_lifecycle_state(life) != BP_SLOT_FREE) {
                assert(slot_lifecycle_state(life) == BP_SLOT_BUSY);
                id_a = slot_lifecycle_id(life);
                ++busy_slots;
            }
        }
        assert(busy_slots == 1 && id_a != 0);
        struct secdebug_bp_unreg_req unreg_a = { .slot_id = id_a };
        assert(secdebug_hwbp_unregister(&unreg_a) == -EBUSY);
    }
#endif
    assert(!pthread_create(&th_b, NULL, concurrent_peer_bp_worker, &slot_b));
#ifdef SECDEBUG_LEGACY_PRE_SD02_RACE
    pthread_barrier_wait(&reaper_race_entered);
    assert(__atomic_load_n(&reaper_reached_liveness, __ATOMIC_ACQUIRE) == 1);
    pthread_barrier_wait(&copy_race_resume);
    assert(!pthread_join(th_a, NULL));
    pthread_barrier_wait(&reaper_race_resume);
    assert(!pthread_join(th_b, NULL));
#else
    assert(!pthread_join(th_b, NULL));
    assert(__atomic_load_n(&reaper_reached_liveness, __ATOMIC_ACQUIRE) == 0);
    __atomic_store_n(&pause_reaper_liveness_once, 0, __ATOMIC_RELEASE);
    pthread_barrier_wait(&copy_race_resume);
    assert(!pthread_join(th_a, NULL));
#endif
    assert(rc_a == -EINPROGRESS && slot_b != 0);
    current_task = &peer;
    assert(secdebug_client_init(&client_b, NULL, 0x1234) == 0);
    assert(secdebug_unregister_bp(&client_b, slot_b) == 0);
    assert(secdebug_client_destroy(&client_b) == 0);
    current_task = &owner;
#ifdef SECDEBUG_LEGACY_PRE_SD02_RACE
    assert(secdebug_hwbp_active_count() == 1 && live_events == 1 && owner.refs == 3 && peer.refs == 0);
    secdebug_hwbp_cleanup();
    assert(secdebug_hwbp_active_count() == 0 && live_events == 0 && owner.refs == 0 && peer.refs == 0);
    assert(target_mm.refs == 0 && live_allocs == 0);
    assert(!pthread_barrier_destroy(&copy_race_entered));
    assert(!pthread_barrier_destroy(&copy_race_resume));
    assert(!pthread_barrier_destroy(&reaper_race_entered));
    assert(!pthread_barrier_destroy(&reaper_race_resume));
    fprintf(stderr, "SD-02 session and breakpoint races reproduced in legacy mode\n");
    exit(77);
#endif
    assert(secdebug_hwbp_active_count() == 0 && live_events == 0 && owner.refs == 0 && peer.refs == 0);
    assert(target_mm.refs == 0 && live_allocs == 0);

    assert(!pthread_barrier_destroy(&copy_race_entered));
    assert(!pthread_barrier_destroy(&copy_race_resume));
    assert(!pthread_barrier_destroy(&reaper_race_entered));
    assert(!pthread_barrier_destroy(&reaper_race_resume));
    puts("Concurrent session OPEN and breakpoint REGISTER rollback leases against reaper: PASS");
}
static pthread_barrier_t gate_ready, gate_go;
static void *gate_worker(void *unused)
{
    (void)unused;
    assert(secdebug_begin_call());
    pthread_barrier_wait(&gate_ready);
    pthread_barrier_wait(&gate_go);
    secdebug_end_call();
    for (int i = 0; i < 5000; ++i) {
        if (secdebug_begin_call()) {
            if (!(i % 11)) sched_yield();
            secdebug_end_call();
        }
    }
    return NULL;
}
static void test_quiescent_cleanup_and_gate(void)
{
    struct secdebug_session_open_req req = {.target_pid = 1234};
    struct secdebug_session_open_resp resp;
    fake_lock();
    assert(secdebug_session_open(&req, &resp) == 0);
    secdebug_session_finish_open(resp.session_id, 1);
    assert(rcu_depth == 1);
    fake_unlock();
    struct secdebug_mem_session *slot = &g_sessions[resp.session_id & (SECDEBUG_MAX_MEM_SESSIONS - 1)];
    assert(slot->mm && slot->owner);
    /* Fault injection only: a quiescent stale BUSY slot, no operation owns it. */
    __atomic_store_n(&slot->lifecycle, session_state(resp.session_id, SESSION_BUSY), __ATOMIC_RELEASE);
    enum {N = 6}; pthread_t threads[N];
    assert(!pthread_barrier_init(&gate_ready, NULL, N + 1));
    assert(!pthread_barrier_init(&gate_go, NULL, N + 1));
    for (int i = 0; i < N; ++i) assert(!pthread_create(&threads[i], NULL, gate_worker, NULL));
    pthread_barrier_wait(&gate_ready);
    assert(secdebug_exit(NULL) == -EBUSY);
    assert(slot->mm && owner.refs == 1 && target_mm.refs == 1);
    pthread_barrier_wait(&gate_go);
    /* Race closure against callers. Refusal never damages existing state. */
    int rc = -EBUSY;
    for (int i = 0; i < 10000 && rc == -EBUSY; ++i) { rc = (int)secdebug_exit(NULL); sched_yield(); }
    for (int i = 0; i < N; ++i) assert(!pthread_join(threads[i], NULL));
    if (rc == -EBUSY) rc = (int)secdebug_exit(NULL);
    assert(rc == 0 && g_call_state == SECDEBUG_CALLS_CLOSED && !g_initialized);
    assert(!owner.refs && !worker.refs && !target_mm.refs && !slot->lifecycle);
    assert(!pthread_barrier_destroy(&gate_ready) && !pthread_barrier_destroy(&gate_go));
    puts("Six-thread CAS admission/exit race and quiescent BUSY-session cleanup: PASS");
}

int main(void)
{
    char token[] = "0000000000001234";
    host_contract = 0;
    assert(secdebug_init(token, NULL, NULL) == -EOPNOTSUPP);
    host_contract = SECDEBUG_HOST_CONTRACT_V1;
    assert(secdebug_init(token, NULL, NULL) == 0);
    assert(secdebug_begin_call());
    assert(secdebug_exit(NULL) == -EBUSY && g_call_state == 1 && g_initialized);
    secdebug_end_call();
    assert(g_call_state == 0 && g_initialized);
    puts("Runtime host contract refusal and non-destructive busy unload: PASS");
    struct secdebug_client client;
    assert(secdebug_client_init(&client, NULL, 0x1234) == 0);
    struct secdebug_cap_resp cap;
    assert(secdebug_probe(&client, &cap) == 0);
    printf("RCU probe: allocations_under_rcu=%d frees_under_rcu=%d user_copies_under_rcu=%d\n",
           allocations_under_rcu, frees_under_rcu, copies_under_rcu);
    assert(!allocations_under_rcu && !frees_under_rcu && !copies_under_rcu);
    assert(live_allocs == 0);
    for (int i = 1; i <= 2; ++i) {
        fail_alloc_at = i;
        assert(secdebug_probe(&client, &cap) == -ENOMEM);
        assert(live_allocs == 0 && rcu_depth == 0);
    }
    client.auth_token = 0x4321;
    assert(secdebug_probe(&client, &cap) == -EACCES);
    client.auth_token = 0x1234;
    fake_lock();
    assert(secdebug_control0(NULL, NULL, 0) == -EINVAL && rcu_depth == 1);
    fake_unlock();

    fail_close = 1;
    char buf[1200];
    size_t done;
    int ret = secdebug_read_mem(&client, 1234, 0x10000, buf, sizeof(buf), &done);
    assert(ret == 1200 && done == 1200);
    assert(secdebug_client_cleanup_error(&client) == -ENOMEM);
    assert(client.pending_session_id && target_mm.refs == 1 && owner.refs == 1);
    for (int i = 0; i < 16; ++i) {
        ret = secdebug_read_mem(&client, 1234, 0x10000, buf, sizeof(buf), &done);
        assert(ret == -ENOMEM && done == 0 && target_mm.refs == 1 && owner.refs == 1);
    }
    assert(secdebug_client_destroy(&client) == -ENOMEM && client.auth_token == 0x1234);
    fail_close = 0;
    assert(secdebug_client_cleanup(&client) == 0);
    assert(target_mm.refs == 0 && owner.refs == 0);
    for (int i = 0; i < 16; ++i) {
        assert(secdebug_read_mem(&client, 1234, 0x10000, buf, sizeof(buf), &done) == 1200);
        assert(target_mm.refs == 0 && owner.refs == 0 && client.pending_session_id == 0);
    }
    puts("CLOSE allocation failure: handle retained; no slot accumulation; recovery releases all refs: PASS");
    copy_fail = 1;
    assert(secdebug_read_mem(&client, 1234, 0x10000, buf, sizeof(buf), &done) == -EINPROGRESS);
    assert(target_mm.refs == 0 && owner.refs == 0 && live_allocs == 0);
    puts("OPEN response-copy failure rolls back session and restores RCU: PASS");

    test_breakpoints(&client);
    test_namespace_worker(&client);
    test_concurrent_create_rollback_leases();

    unsigned random = 0x93112512u;
    unsigned char decoded[1024];
    char encoded[1024];
    char output[640];
    for (int iteration = 0; iteration < 10000; ++iteration) {
        random = random * 1664525u + 1013904223u;
        int size = (int)(random & 1023u);
        for (int i = 0; i < size; ++i) {
            random = random * 1664525u + 1013904223u;
            encoded[i] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="[random % 65];
        }
        encoded[size] = 0;
        (void)b64_decode(encoded, size, decoded, sizeof(decoded));
        fake_lock();
        (void)secdebug_control0(encoded, output, sizeof(output));
        assert(rcu_depth == 1);
        fake_unlock();
    }
    puts("Malformed input sample: 10000 deterministic cases completed (not exhaustive fuzzing).");
    assert(!allocations_under_rcu && !frees_under_rcu && !copies_under_rcu);
    assert(live_allocs == 0 && target_mm.refs == 0 && owner.refs == 0);
    assert(secdebug_client_destroy(&client) == 0);
    test_quiescent_cleanup_and_gate();
    assert(rcu_depth == 0);
    assert(!secdebug_begin_call() && g_call_state == SECDEBUG_CALLS_CLOSED);
    assert(!live_events && !owner.refs && !target_mm.refs && !live_allocs);
    puts("Closed admission cannot increment the count after exit: PASS");
    return 0;
}
