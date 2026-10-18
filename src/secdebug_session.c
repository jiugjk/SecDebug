/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Stable-mm memory sessions. The mm_struct remains pinned across every SDK
 * chunk so PID reuse can never redirect a partially completed transfer to a
 * different process. Handles are owned by the *calling thread* and finite.
 */
#include "secdebug_internal.h"

#define SESSION_FREE 0u
#define SESSION_OPENING 1u
#define SESSION_ACTIVE 2u
#define SESSION_BUSY 3u
#define SESSION_CLOSING 4u

struct secdebug_mem_session {
    uint64_t lifecycle; /* upper 32 bits: generation, lower 32: state */
    struct mm_struct *mm;
    struct task_struct *owner;
    pid_t owner_init_pid; /* init-namespace PID captured at open; 0 if unknown */
};

static struct secdebug_mem_session g_sessions[SECDEBUG_MAX_MEM_SESSIONS];
static uint32_t g_next_session_id = 1;

static uint64_t session_state(uint32_t id, uint32_t state)
{
    return ((uint64_t)id << 32) | state;
}

static uint32_t session_id(uint64_t lifecycle)
{
    return (uint32_t)(lifecycle >> 32);
}

static uint32_t session_status(uint64_t lifecycle)
{
    return (uint32_t)lifecycle;
}

static int session_id_in_use(uint32_t id)
{
    int i;

    if (!id)
        return 1;
    for (i = 0; i < SECDEBUG_MAX_MEM_SESSIONS; i++) {
        uint64_t life = __atomic_load_n(&g_sessions[i].lifecycle, __ATOMIC_ACQUIRE);

        if (session_status(life) != SESSION_FREE && session_id(life) == id)
            return 1;
    }
    return 0;
}

_Static_assert((SECDEBUG_MAX_MEM_SESSIONS & (SECDEBUG_MAX_MEM_SESSIONS - 1)) == 0,
               "session slots must be a power of two");

static uint32_t next_session_id(int slot_index)
{
    int spins = 0;
    uint32_t seq;
    uint32_t id;

    /* Low 3 bits are the slot index, so wrap cannot alias another slot. */
    do {
        seq = __atomic_fetch_add(&g_next_session_id, 1, __ATOMIC_RELAXED);
        id = (seq << 3) | (uint32_t)slot_index;
        if (id && !session_id_in_use(id))
            return id;
    } while (++spins < SECDEBUG_MAX_MEM_SESSIONS + 2);
    return 0;
}

int secdebug_session_ready(void)
{
    return secdebug_remote_mem_ready() && g_syms.put_task_struct &&
           (g_syms.get_task_struct || g_syms.find_get_task_by_vpid) &&
           secdebug_caller_id_ready() && g_init_pid_ns && g_syms.task_pid_nr_ns;
}

void secdebug_session_init(void)
{
    memset(g_sessions, 0, sizeof(g_sessions));
}

/* Caller must own this slot in SESSION_CLOSING. Can sleep. */
static void session_free(struct secdebug_mem_session *slot)
{
    struct mm_struct *mm = slot->mm;
    struct task_struct *owner = slot->owner;

    slot->mm = NULL;
    slot->owner = NULL;
    slot->owner_init_pid = 0;
    if (mm)
        g_syms.mmput(mm);
    if (owner)
        secdebug_task_put(owner);
    __atomic_store_n(&slot->lifecycle, 0, __ATOMIC_RELEASE);
}

/*
 * Reap only when the pinned owner is gone in init_pid_ns. A NULL namespace
 * argument follows the caller and must not be treated as a liveness proof.
 * owner_init_pid == 0 means the id was never captured; leave the session up.
 */
static void session_reap(void)
{
    int i;

    for (i = 0; i < SECDEBUG_MAX_MEM_SESSIONS; ++i) {
        struct secdebug_mem_session *slot = &g_sessions[i];
        uint64_t state = __atomic_load_n(&slot->lifecycle, __ATOMIC_ACQUIRE);
        int dropped = 0;
        uint32_t id = session_id(state);
        pid_t now;

        if (session_status(state) != SESSION_ACTIVE)
            continue;
        if (!__atomic_compare_exchange_n(&slot->lifecycle, &state,
                                         session_state(id, SESSION_BUSY), 0,
                                         __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            continue;
        now = secdebug_init_pid(slot->owner, 0);
        if (slot->owner_init_pid <= 0 || now < 0 || now == slot->owner_init_pid) {
            __atomic_store_n(&slot->lifecycle, session_state(id, SESSION_ACTIVE),
                             __ATOMIC_RELEASE);
            continue;
        }
        __atomic_store_n(&slot->lifecycle, session_state(id, SESSION_CLOSING),
                         __ATOMIC_RELEASE);
        secdebug_rcu_drop(&dropped);
        session_free(slot);
        secdebug_rcu_restore(&dropped);
    }
}

int secdebug_session_open(const struct secdebug_session_open_req *req,
                          struct secdebug_session_open_resp *resp)
{
    struct secdebug_mem_session *slot = NULL;
    struct task_struct *owner = NULL;
    struct mm_struct *mm = NULL;
    uint32_t id = 0;
    int dropped = 0;
    int rc;
    int i;

    if (!req || !resp || req->target_pid <= 0 || req->reserved)
        return -EINVAL;
    if (!secdebug_session_ready())
        return -EOPNOTSUPP;

    session_reap();
    for (i = 0; i < SECDEBUG_MAX_MEM_SESSIONS; ++i) {
        uint64_t old = 0;
        if (__atomic_compare_exchange_n(&g_sessions[i].lifecycle, &old,
                                        session_state(0, SESSION_OPENING), 0,
                                        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
            slot = &g_sessions[i];
            id = next_session_id(i);
            if (!id) {
                __atomic_store_n(&slot->lifecycle, 0, __ATOMIC_RELEASE);
                slot = NULL;
            }
            break;
        }
    }
    if (!slot)
        return -ENOSPC;

    rc = secdebug_pin_mm(req->target_pid, &mm, &dropped);
    if (rc)
        goto fail;
    owner = secdebug_pin_current();
    if (!owner) {
        rc = -EOPNOTSUPP;
        goto fail;
    }

    slot->mm = mm;
    slot->owner = owner;
    slot->owner_init_pid = secdebug_init_pid(owner, 0);
    if (slot->owner_init_pid < 0)
        slot->owner_init_pid = 0;
    /* Hold SESSION_BUSY until the response copy completes in finish_open(). */
    __atomic_store_n(&slot->lifecycle, session_state(id, SESSION_BUSY),
                     __ATOMIC_RELEASE);
    resp->session_id = id;
    resp->reserved = 0;
    secdebug_rcu_restore(&dropped);
    return 0;

fail:
    if (mm)
        g_syms.mmput(mm);
    if (owner)
        secdebug_task_put(owner);
    slot->owner_init_pid = 0;
    __atomic_store_n(&slot->lifecycle, 0, __ATOMIC_RELEASE);
    secdebug_rcu_restore(&dropped);
    return rc;
}

void secdebug_session_finish_open(uint32_t id, int delivered)
{
    int idx;
    int dropped = 0;
    struct secdebug_mem_session *slot;
    uint64_t expected;

    if (!id)
        return;
    idx = (int)(id & (SECDEBUG_MAX_MEM_SESSIONS - 1));
    slot = &g_sessions[idx];
    expected = session_state(id, SESSION_BUSY);
    if (delivered) {
        __atomic_compare_exchange_n(&slot->lifecycle, &expected,
                                    session_state(id, SESSION_ACTIVE), 0,
                                    __ATOMIC_RELEASE, __ATOMIC_RELAXED);
        return;
    }
    if (!__atomic_compare_exchange_n(&slot->lifecycle, &expected,
                                     session_state(id, SESSION_CLOSING), 0,
                                     __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
        return;
    secdebug_rcu_drop(&dropped);
    session_free(slot);
    secdebug_rcu_restore(&dropped);
}

/* A successful claim is a lease; its owner MUST release it before returning. */
static int session_claim(uint32_t id, struct secdebug_mem_session **out)
{
    int idx;
    struct secdebug_mem_session *slot;
    uint64_t old;

    if (!id || !out)
        return -EINVAL;
    *out = NULL;
    idx = (int)(id & (SECDEBUG_MAX_MEM_SESSIONS - 1));
    slot = &g_sessions[idx];
    old = __atomic_load_n(&slot->lifecycle, __ATOMIC_ACQUIRE);
    if (session_id(old) != id)
        return -ENOENT;
    if (old != session_state(id, SESSION_ACTIVE))
        return -EBUSY;
    if (!__atomic_compare_exchange_n(&slot->lifecycle, &old,
                                     session_state(id, SESSION_BUSY), 0,
                                     __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        return -EBUSY;
    if (slot->owner != secdebug_current_task()) {
        __atomic_store_n(&slot->lifecycle, session_state(id, SESSION_ACTIVE),
                         __ATOMIC_RELEASE);
        return -EPERM;
    }
    *out = slot;
    return 0;
}

int secdebug_session_close(uint32_t id)
{
    struct secdebug_mem_session *slot;
    int rc = session_claim(id, &slot);
    int dropped = 0;

    if (rc)
        return rc;
    __atomic_store_n(&slot->lifecycle, session_state(id, SESSION_CLOSING),
                     __ATOMIC_RELEASE);
    secdebug_rcu_drop(&dropped);
    session_free(slot);
    secdebug_rcu_restore(&dropped);
    return 0;
}

/* The session's mm ref stays valid even if its original PID exits/reuses. */
static int session_access(uint32_t id, uint64_t addr, void *data, uint32_t len,
                          int write, uint32_t *transferred)
{
    struct secdebug_mem_session *slot;
    int dropped = 0;
    int rc;
    int n;

    if (!data || !transferred || !len || len > SECDEBUG_MAX_PAYLOAD)
        return -EINVAL;
    *transferred = 0;
    if (!secdebug_is_user_address(addr, len))
        return -EFAULT;
    rc = session_claim(id, &slot);
    if (rc)
        return rc;

    secdebug_rcu_drop(&dropped);
    n = g_syms.access_remote_vm(slot->mm, (unsigned long)secdebug_untag_user(addr),
                                data, (int)len,
                                (write ? SECDEBUG_FOLL_WRITE : 0u) |
                                secdebug_foll_force());
    secdebug_rcu_restore(&dropped);
    __atomic_store_n(&slot->lifecycle, session_state(id, SESSION_ACTIVE),
                     __ATOMIC_RELEASE);
    if (n <= 0)
        return n < 0 ? n : -EFAULT;
    if ((uint32_t)n > len)
        n = (int)len;
    *transferred = (uint32_t)n;
    return 0;
}

int secdebug_session_read(const struct secdebug_session_read_req *req,
                          void *out, uint32_t *len)
{
    if (!req)
        return -EINVAL;
    return session_access(req->session_id, req->target_addr,
                          out, req->read_len, 0, len);
}

int secdebug_session_write(const struct secdebug_session_write_req *req,
                           const void *data, uint32_t *written)
{
    if (!req)
        return -EINVAL;
    return session_access(req->session_id, req->target_addr,
                          (void *)data, req->write_len, 1, written);
}

void secdebug_session_cleanup(void)
{
    int i;

    /* Exit executes only after all control calls finished on a safe loader. */
    for (i = 0; i < SECDEBUG_MAX_MEM_SESSIONS; ++i) {
        struct secdebug_mem_session *slot = &g_sessions[i];
        uint64_t old = __atomic_load_n(&slot->lifecycle, __ATOMIC_ACQUIRE);
        unsigned int state = session_status(old);
        /* Admission is closed and all control calls have returned. BUSY is
         * handled defensively here, never stolen from a live operation. */
        if (state != SESSION_ACTIVE && state != SESSION_BUSY)
            continue;
        if (__atomic_compare_exchange_n(&slot->lifecycle, &old,
                                          session_state(session_id(old), SESSION_CLOSING),
                                          0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            session_free(slot);
    }
}
