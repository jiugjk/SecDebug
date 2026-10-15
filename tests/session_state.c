/* SPDX-License-Identifier: Apache-2.0 */
/* Exercise the ACTUAL KPM memory-session state machine against fake mm/task
 * refs (unit test only; not proof of kernel RCU or architecture correctness). */
#include <stdio.h>
#include <string.h>
#include "../src/secdebug_session.c"

struct mm_struct { unsigned refs; unsigned char bytes[64]; };
struct task_struct { unsigned refs; int alive; };
static struct mm_struct mm_a, mm_b;
static struct mm_struct *current_pid_mm;
static struct task_struct task_a, task_b;
static struct task_struct *current_owner;
struct secdebug_syms g_syms;
uint32_t g_page_size;
uint32_t g_cap_flags;
uint64_t g_auth_token;

static void fake_mmput(struct mm_struct *mm) { mm->refs--; }
static void fake_put(struct task_struct *task) { task->refs--; }
static struct task_struct *fake_get(struct task_struct *task) { task->refs++; return task; }
static int g_init_ns_object;
void *g_init_pid_ns;

static pid_t fake_task_pid(struct task_struct *task, int type, void *ns)
{
    (void)type;
    /* NULL follows the caller namespace and must not count as liveness. */
    if (ns != g_init_pid_ns)
        return 0;
    return task && task->alive ? 4242 : 0;
}
static int fake_access(struct mm_struct *mm, unsigned long addr, void *data,
                       int len, unsigned int flags)
{
    (void)addr;
    if (len > (int)sizeof(mm->bytes)) return -EINVAL;
    if (flags & SECDEBUG_FOLL_WRITE) memcpy(mm->bytes, data, (size_t)len);
    else memcpy(data, mm->bytes, (size_t)len);
    return len;
}
int secdebug_remote_mem_ready(void) { return 1; }
int secdebug_caller_id_ready(void) { return 1; }
struct task_struct *secdebug_current_task(void) { return current_owner; }
struct task_struct *secdebug_pin_current(void)
{
    current_owner->refs++;
    return current_owner;
}
void secdebug_task_put(struct task_struct *task) { fake_put(task); }
void secdebug_rcu_drop(int *dropped) { *dropped = 1; }
void secdebug_rcu_restore(int *dropped) { *dropped = 0; }
unsigned int secdebug_foll_force(void) { return 0x10u; }
int secdebug_pin_mm(pid_t pid, struct mm_struct **out, int *dropped)
{
    if (pid != 4242) return -ESRCH;
    current_pid_mm->refs++;
    *out = current_pid_mm;
    *dropped = 1;
    return 0;
}

#define TEST_CHECK(condition, message) do { \
    if (!(condition)) { fprintf(stderr, "session state: %s at %d\n", (message), __LINE__); \
                       return 1; } \
} while (0)

int main(void)
{
    struct secdebug_session_open_req open_req = { 4242, 0 };
    struct secdebug_session_open_resp open_resp;
    struct secdebug_session_read_req read_req;
    struct secdebug_session_write_req write_req;
    unsigned char data[8];
    uint32_t n;
    unsigned id[SECDEBUG_MAX_MEM_SESSIONS];
    int i;

    g_init_pid_ns = &g_init_ns_object;
    memset(&g_syms, 0, sizeof(g_syms));
    g_syms.access_remote_vm = fake_access;
    g_syms.mmput = fake_mmput;
    g_syms.put_task_struct = fake_put;
    g_syms.get_task_struct = fake_get;
    g_syms.task_pid_nr_ns = fake_task_pid;
    current_pid_mm = &mm_a;
    current_owner = &task_a;
    task_a.alive = 1; task_b.alive = 1;
    memset(mm_a.bytes, 'A', sizeof(mm_a.bytes));
    memset(mm_b.bytes, 'B', sizeof(mm_b.bytes));
    secdebug_session_init();
    TEST_CHECK(secdebug_session_ready(), "backend unavailable");
    TEST_CHECK(secdebug_session_open(&open_req, &open_resp) == 0, "open failed");
    TEST_CHECK(mm_a.refs == 1 && task_a.refs == 1, "missing pinned references");
    current_pid_mm = &mm_b; /* Simulate PID reuse after first chunk. */
    read_req.session_id = open_resp.session_id;
    read_req.read_len = sizeof(data);
    read_req.target_addr = 0x1234;
    TEST_CHECK(secdebug_session_read(&read_req, data, &n) == 0 && n == 8,
               "stable read failed");
    TEST_CHECK(data[0] == 'A', "PID reuse switched the target mm");
    memset(data, 'C', sizeof(data));
    write_req.session_id = open_resp.session_id;
    write_req.write_len = sizeof(data);
    write_req.target_addr = 0x1234;
    TEST_CHECK(secdebug_session_write(&write_req, data, &n) == 0 && n == 8,
               "stable write failed");
    TEST_CHECK(mm_a.bytes[0] == 'C' && mm_b.bytes[0] == 'B',
               "PID reuse corrupted the new process");

    current_owner = &task_b;
    TEST_CHECK(secdebug_session_read(&read_req, data, &n) == -EPERM,
               "wrong-thread access was permitted");
    current_owner = &task_a;
    TEST_CHECK(secdebug_session_close(open_resp.session_id) == 0, "close failed");
    TEST_CHECK(mm_a.refs == 0 && task_a.refs == 0, "close leaked refs");
    TEST_CHECK(secdebug_session_read(&read_req, data, &n) == -ENOENT,
               "stale generation was accepted");

    /* A live owner must survive reap from another thread, even though a
     * caller-namespace pid lookup would report 0. */
    {
        uint32_t kept;

        current_pid_mm = &mm_a;
        current_owner = &task_a;
        TEST_CHECK(secdebug_session_open(&open_req, &open_resp) == 0, "keep-open failed");
        kept = open_resp.session_id;
        current_owner = &task_b;
        TEST_CHECK(secdebug_session_open(&open_req, &open_resp) == 0,
                   "cross-namespace open failed");
        current_owner = &task_a;
        read_req.session_id = kept;
        TEST_CHECK(secdebug_session_read(&read_req, data, &n) == 0,
                   "live session was reaped from another pid namespace");
        current_owner = &task_b;
        TEST_CHECK(secdebug_session_close(open_resp.session_id) == 0,
                   "close cross-namespace session");
        current_owner = &task_a;
        TEST_CHECK(secdebug_session_close(kept) == 0, "close kept session");
    }

    /* Owner task exits without close. The next open must reclaim its slot. */
    current_pid_mm = &mm_a;
    current_owner = &task_a;
    TEST_CHECK(secdebug_session_open(&open_req, &open_resp) == 0, "reopen failed");
    task_a.alive = 0;
    current_owner = &task_b;
    TEST_CHECK(secdebug_session_open(&open_req, &open_resp) == 0,
               "orphan reap failed");
    TEST_CHECK(mm_a.refs == 1 && task_a.refs == 0,
               "orphan refs not reaped");
    TEST_CHECK(secdebug_session_close(open_resp.session_id) == 0, "close after reap");
    TEST_CHECK(mm_a.refs == 0 && task_b.refs == 0, "reap close leaks");

    for (i = 0; i < SECDEBUG_MAX_MEM_SESSIONS; ++i) {
        TEST_CHECK(secdebug_session_open(&open_req, &open_resp) == 0,
                   "early session exhaustion");
        id[i] = open_resp.session_id;
    }
    TEST_CHECK(secdebug_session_open(&open_req, &open_resp) == -ENOSPC,
               "slot exhaustion not enforced");
    for (i = 0; i < SECDEBUG_MAX_MEM_SESSIONS; ++i)
        TEST_CHECK(secdebug_session_close(id[i]) == 0, "pool close failed");
    TEST_CHECK(mm_a.refs == 0 && task_b.refs == 0, "pool refs leaked");
    /* Wrapped ids must not alias a slot that is still open. */
    {
        uint32_t first;

        current_owner = &task_b;
        task_a.alive = 1;
        task_b.alive = 1;
        TEST_CHECK(secdebug_session_open(&open_req, &open_resp) == 0, "wrap seed open");
        first = open_resp.session_id;
        g_next_session_id = first;
        TEST_CHECK(secdebug_session_open(&open_req, &open_resp) == 0, "wrap second open");
        TEST_CHECK(open_resp.session_id != 0 && open_resp.session_id != first,
                   "wrapped id collided with a live session");
        TEST_CHECK(secdebug_session_close(first) == 0, "close wrap seed");
        TEST_CHECK(secdebug_session_close(open_resp.session_id) == 0, "close wrap second");
    }
    secdebug_session_cleanup();
    puts("session state: PASS");
    return 0;
}
