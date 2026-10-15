/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * secdebug_mem.c - Safe cross-process memory read and write implementations
 */

#include "secdebug_internal.h"
#include <asm/current.h>


/*
 * FOLL_FORCE's numeric value is not implied by kver. Vendor trees backport
 * the 6.3 enum layout onto older version numbers. The build must pass the
 * value from the target kernel's mm headers. Unset means "do not force".
 */
unsigned int secdebug_foll_force(void)
{
#if defined(SECDEBUG_FOLL_FORCE)
    return (unsigned int)(SECDEBUG_FOLL_FORCE);
#else
    return 0;
#endif
}

void *g_init_pid_ns;

typedef void *(*fn_vmalloc)(unsigned long size);
typedef void (*fn_kvfree)(const void *ptr);

static fn_vmalloc g_vmalloc;
static fn_kvfree g_kvfree;

void secdebug_bind_runtime(void)
{
    g_vmalloc = (fn_vmalloc)kallsyms_lookup_name("vmalloc");
    if (!g_vmalloc)
        g_vmalloc = (fn_vmalloc)kallsyms_lookup_name("vmalloc_noprof");
    g_kvfree = (fn_kvfree)kallsyms_lookup_name("kvfree");
    if (!g_kvfree)
        g_kvfree = (fn_kvfree)kallsyms_lookup_name("vfree");
    g_init_pid_ns = (void *)kallsyms_lookup_name("init_pid_ns");
}

int secdebug_alloc_ready(void)
{
    return g_vmalloc != NULL && g_kvfree != NULL;
}

void *secdebug_alloc(unsigned long size)
{
    void *ptr;

    if (!size || !g_vmalloc)
        return NULL;
    ptr = g_vmalloc(size);
    if (ptr)
        memset(ptr, 0, size);
    return ptr;
}

void secdebug_free(void *ptr, unsigned long size)
{
    volatile unsigned char *bytes;
    unsigned long i;

    if (!ptr)
        return;
    bytes = (volatile unsigned char *)ptr;
    for (i = 0; i < size; i++)
        bytes[i] = 0;
    if (g_kvfree)
        g_kvfree(ptr);
}

struct task_struct *secdebug_current_task(void)
{
    /* Use the host SDK's architecture helper instead of duplicating it here. */
    return get_current();
}

pid_t secdebug_current_pid(void)
{
    struct task_struct *cur = secdebug_current_task();
    pid_t pid;

    if (!cur || !g_syms.task_pid_nr_ns)
        return -1;
    pid = g_syms.task_pid_nr_ns(cur, 0, NULL);
    if (pid <= 0)
        return -1;
    return pid;
}

int secdebug_caller_id_ready(void)
{
    return secdebug_current_pid() > 0;
}

static int secdebug_find_ready(void)
{
    if (g_syms.find_get_task_by_vpid)
        return 1;
    /* find_task_by_vpid is only safe while the host RCU section is held. */
    if (!(g_syms.rcu_read_lock && g_syms.rcu_read_unlock))
        return 0;
    if (g_syms.find_task_by_vpid && g_syms.get_task_struct)
        return 1;
    if (g_syms.find_vpid && g_syms.pid_task && g_syms.get_task_struct)
        return 1;
    return 0;
}

static int secdebug_find_borrowed_ready(void)
{
    if (!g_syms.rcu_read_lock || !g_syms.rcu_read_unlock)
        return 0;
    return g_syms.find_task_by_vpid || (g_syms.find_vpid && g_syms.pid_task);
}

int secdebug_remote_mem_ready(void)
{
    return g_syms.access_remote_vm && g_syms.get_task_mm && g_syms.mmput &&
           secdebug_find_borrowed_ready();
}

int secdebug_mem_ops_ready(void)
{
    /*
     * Preferred memory path pins mm_struct while the task is protected by RCU,
     * then uses access_remote_vm() after dropping the host's outer RCU section.
     * This avoids guessing task_struct.usage just to release a task reference.
     */
    if (secdebug_remote_mem_ready())
        return 1;

    /* Conservative fallback for kernels that expose a real task put helper. */
    return g_syms.access_process_vm && secdebug_task_ops_ready();
}

int secdebug_task_ops_ready(void)
{
    /*
     * Refuse the old task_struct usage-offset heuristic. A guessed refcount
     * layout is not a stable kernel ABI and can corrupt task lifetime state.
     */
    if (!g_syms.put_task_struct)
        return 0;
    if (!g_syms.rcu_read_lock || !g_syms.rcu_read_unlock)
        return 0;
    return secdebug_find_ready() && g_syms.get_task_mm && g_syms.mmput;
}

void secdebug_task_put(struct task_struct *task)
{
    if (task && g_syms.put_task_struct)
        g_syms.put_task_struct(task);
}

void secdebug_rcu_drop(int *rcu_dropped)
{
    *rcu_dropped = 0;
    if (g_syms.rcu_read_lock && g_syms.rcu_read_unlock) {
        g_syms.rcu_read_unlock();
        *rcu_dropped = 1;
    }
}

void secdebug_rcu_restore(int *rcu_dropped)
{
    if (rcu_dropped && *rcu_dropped && g_syms.rcu_read_lock) {
        g_syms.rcu_read_lock();
        *rcu_dropped = 0;
    }
}

void secdebug_task_init(void)
{
    /* No layout probing: capability detection will fail closed if helpers are missing. */
}

struct task_struct *secdebug_pin_current(void)
{
    struct task_struct *cur = secdebug_current_task();
    struct task_struct *got;
    pid_t pid;

    if (!cur || !g_syms.put_task_struct)
        return NULL;

    if (g_syms.find_get_task_by_vpid) {
        pid = secdebug_current_pid();
        if (pid <= 0)
            return NULL;
        got = g_syms.find_get_task_by_vpid(pid);
        if (got != cur) {
            if (got)
                secdebug_task_put(got);
            return NULL;
        }
        return cur;
    }

    if (g_syms.get_task_struct) {
        /* The symbol is sometimes a void inline. Ignore x0. */
        g_syms.get_task_struct(cur);
        return cur;
    }
    return NULL;
}


int secdebug_pin_task(pid_t pid, struct task_struct **out, int *rcu_dropped)
{
    struct task_struct *task = NULL;
    struct mm_struct *mm;

    *out = NULL;
    *rcu_dropped = 0;

    if (pid <= 0)
        return -EINVAL;
    if (!secdebug_task_ops_ready())
        return -EOPNOTSUPP;

    if (g_syms.find_get_task_by_vpid) {
        task = g_syms.find_get_task_by_vpid(pid);
    } else if (g_syms.find_task_by_vpid && g_syms.get_task_struct) {
        task = g_syms.find_task_by_vpid(pid);
        if (task)
            g_syms.get_task_struct(task);
    } else if (g_syms.find_vpid && g_syms.pid_task && g_syms.get_task_struct) {
        struct pid *kpid = g_syms.find_vpid(pid);
        if (kpid) {
            task = g_syms.pid_task(kpid, 0);
            if (task)
                g_syms.get_task_struct(task);
        }
    }

    if (!task)
        return -ESRCH;

    secdebug_rcu_drop(rcu_dropped);

    mm = g_syms.get_task_mm(task);
    if (!mm) {
        secdebug_task_put(task);
        secdebug_rcu_restore(rcu_dropped);
        return -ESRCH;
    }
    g_syms.mmput(mm);

    *out = task;
    return 0;
}

int secdebug_pin_mm(pid_t pid, struct mm_struct **out, int *rcu_dropped)
{
    struct task_struct *task = NULL;
    struct mm_struct *mm = NULL;

    if (!out || !rcu_dropped || pid <= 0)
        return -EINVAL;
    *out = NULL;
    *rcu_dropped = 0;
    if (!g_syms.get_task_mm || !g_syms.mmput || !secdebug_find_borrowed_ready())
        return -EOPNOTSUPP;

    /* Take our own nested RCU read section for the borrowed task lookup. */
    g_syms.rcu_read_lock();
    if (g_syms.find_task_by_vpid)
        task = g_syms.find_task_by_vpid(pid);
    else {
        struct pid *kpid = g_syms.find_vpid(pid);
        if (kpid)
            task = g_syms.pid_task(kpid, 0);
    }
    if (task)
        mm = g_syms.get_task_mm(task);
    g_syms.rcu_read_unlock();

    if (!mm)
        return -ESRCH;

    /* module_control0 is entered under the loader's outer RCU section. */
    secdebug_rcu_drop(rcu_dropped);
    *out = mm;
    return 0;
}

int secdebug_mem_read(const struct secdebug_mem_read_req *req, void *out_buf, uint32_t *out_len)
{
    struct task_struct *task = NULL;
    struct mm_struct *mm = NULL;
    int rcu_dropped = 0;
    int bytes_read;
    int rc;
    uint64_t addr;

    if (!req || !out_buf || !out_len)
        return -EINVAL;
    if (req->read_len == 0 || req->read_len > SECDEBUG_MAX_PAYLOAD)
        return -EINVAL;
    if (!secdebug_is_user_address(req->target_addr, req->read_len))
        return -EFAULT;

    addr = secdebug_untag_user(req->target_addr);
    if (secdebug_remote_mem_ready()) {
        rc = secdebug_pin_mm(req->target_pid, &mm, &rcu_dropped);
        if (rc)
            return rc;
        bytes_read = g_syms.access_remote_vm(mm, (unsigned long)addr, out_buf,
                                             (int)req->read_len, secdebug_foll_force());
        g_syms.mmput(mm);
    } else if (g_syms.access_process_vm && secdebug_task_ops_ready()) {
        rc = secdebug_pin_task(req->target_pid, &task, &rcu_dropped);
        if (rc)
            return rc;
        bytes_read = g_syms.access_process_vm(task, (unsigned long)addr, out_buf,
                                               (int)req->read_len, secdebug_foll_force());
        secdebug_task_put(task);
    } else {
        return -EOPNOTSUPP;
    }
    if (bytes_read > (int)req->read_len)
        bytes_read = (int)req->read_len;
    secdebug_rcu_restore(&rcu_dropped);

    if (bytes_read <= 0) {
        *out_len = 0;
        return bytes_read < 0 ? bytes_read : -EFAULT;
    }

    *out_len = (uint32_t)bytes_read;
    return 0;
}

int secdebug_mem_write(const struct secdebug_mem_write_req *req, const void *in_data, uint32_t *bytes_written)
{
    struct task_struct *task = NULL;
    struct mm_struct *mm = NULL;
    int rcu_dropped = 0;
    int written;
    int rc;
    uint64_t addr;

    if (!req || !in_data || !bytes_written)
        return -EINVAL;
    if (req->write_len == 0 || req->write_len > SECDEBUG_MAX_PAYLOAD)
        return -EINVAL;
    if (!secdebug_is_user_address(req->target_addr, req->write_len))
        return -EFAULT;

    addr = secdebug_untag_user(req->target_addr);
    if (secdebug_remote_mem_ready()) {
        rc = secdebug_pin_mm(req->target_pid, &mm, &rcu_dropped);
        if (rc)
            return rc;
        written = g_syms.access_remote_vm(mm, (unsigned long)addr, (void *)in_data,
                                           (int)req->write_len,
                                           SECDEBUG_FOLL_WRITE | secdebug_foll_force());
        g_syms.mmput(mm);
    } else if (g_syms.access_process_vm && secdebug_task_ops_ready()) {
        rc = secdebug_pin_task(req->target_pid, &task, &rcu_dropped);
        if (rc)
            return rc;
        written = g_syms.access_process_vm(task, (unsigned long)addr, (void *)in_data,
                                            (int)req->write_len,
                                            SECDEBUG_FOLL_WRITE | secdebug_foll_force());
        secdebug_task_put(task);
    } else {
        return -EOPNOTSUPP;
    }
    if (written > (int)req->write_len)
        written = (int)req->write_len;
    secdebug_rcu_restore(&rcu_dropped);

    if (written <= 0) {
        *bytes_written = 0;
        return written < 0 ? written : -EFAULT;
    }

    *bytes_written = (uint32_t)written;
    return 0;
}
