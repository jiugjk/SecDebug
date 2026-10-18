/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * secdebug_hwbp.c - Hardware Breakpoint and Watchpoint management subsystem
 */

#include "secdebug_internal.h"
#include "secdebug_perf_abi.h"

#define PERF_TYPE_BREAKPOINT 5

/* include/uapi/linux/hw_breakpoint.h */
#define HW_BREAKPOINT_LEN_4  0x4
#define HW_BREAKPOINT_LEN_8  0x8

#define HW_BREAKPOINT_R      1
#define HW_BREAKPOINT_W      2
#define HW_BREAKPOINT_RW     (HW_BREAKPOINT_R | HW_BREAKPOINT_W)
#define HW_BREAKPOINT_X      4

#define PERF_DISABLED        (1ULL << 0)
#define PERF_PINNED          (1ULL << 2)
#define PERF_EXCLUDE_KERNEL  (1ULL << 5)
#define PERF_EXCLUDE_HV      (1ULL << 6)

/* linux/pid.h: PIDTYPE_PID is 0, PIDTYPE_TGID is 1. */
#define SECDEBUG_PIDTYPE_TGID 1

/*
 * Prefix of struct perf_event_attr through bp_len. attr->size is 128 so
 * perf_copy_attr() stops there. The in-kernel create path may assign the
 * whole kernel struct, so the heap object is a zeroed 512-byte buffer.
 */

#define SECDEBUG_PERF_ATTR_BUF  512
#define SECDEBUG_PERF_ATTR_SIZE 128
/* Layout assertions reside in include/secdebug_perf_abi.h. */
_Static_assert(SECDEBUG_PERF_ATTR_BUF >= SECDEBUG_PERF_ATTR_SIZE,
               "perf attr storage smaller than claimed ABI");

struct pt_regs_arm64 {
    uint64_t regs[31];
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
};

#define BP_SLOT_FREE        0
#define BP_SLOT_ALLOCATING  1
#define BP_SLOT_ACTIVE      2
#define BP_SLOT_BUSY        3
#define BP_SLOT_DRAINING    4

struct bp_slot {
    uint64_t lifecycle; /* high 32: public_id, low 32: BP_SLOT_* */
    pid_t target_tid;
    struct task_struct *owner;
    struct task_struct *owner_leader;
    int leader_extra;
    pid_t owner_tgid;
    uint32_t bp_type;
    uint64_t target_addr;
    struct perf_event *event;
    struct task_struct *task;
    uint64_t hit_total;
    uint64_t hit_consumed;
    uint64_t trigger_addr;
    uint32_t seq;
    struct secdebug_regs_snapshot last_regs;
};

static struct bp_slot g_bp_slots[SECDEBUG_MAX_BP_SLOTS];
static uint32_t g_bp_generation = 1;

static int public_id_in_use(uint32_t id)
{
    int i;

    if (id == 0)
        return 1;
    for (i = 0; i < SECDEBUG_MAX_BP_SLOTS; i++) {
        uint64_t lifecycle = __atomic_load_n(&g_bp_slots[i].lifecycle, __ATOMIC_ACQUIRE);

        if ((uint32_t)lifecycle != BP_SLOT_FREE &&
            (uint32_t)(lifecycle >> 32) == id)
            return 1;
    }
    return 0;
}

_Static_assert((SECDEBUG_MAX_BP_SLOTS & (SECDEBUG_MAX_BP_SLOTS - 1)) == 0,
               "breakpoint slots must be a power of two");

static uint32_t alloc_public_id(int slot_index)
{
    int spins = 0;
    uint32_t seq;
    uint32_t id;

    /* Low bits are the slot index, so wrap cannot alias a different slot. */
    do {
        seq = __atomic_fetch_add(&g_bp_generation, 1, __ATOMIC_RELAXED);
        id = (seq << 2) | (uint32_t)slot_index;
        if (id != 0 && !public_id_in_use(id))
            return id;
    } while (++spins < SECDEBUG_MAX_BP_SLOTS + 2);
    return 0;
}

static int slot_index_from_id(uint32_t id)
{
    int idx;
    uint64_t lifecycle;

    if (id == 0)
        return -1;
    idx = (int)(id & (SECDEBUG_MAX_BP_SLOTS - 1));
    lifecycle = __atomic_load_n(&g_bp_slots[idx].lifecycle, __ATOMIC_ACQUIRE);
    if ((uint32_t)(lifecycle >> 32) != id)
        return -1;
    return idx;
}

static uint64_t slot_lifecycle(uint32_t id, uint32_t state)
{
    return ((uint64_t)id << 32) | state;
}

static uint32_t slot_lifecycle_id(uint64_t lifecycle)
{
    return (uint32_t)(lifecycle >> 32);
}

static uint32_t slot_lifecycle_state(uint64_t lifecycle)
{
    return (uint32_t)lifecycle;
}

static int slot_claim_active(struct bp_slot *slot, uint32_t id)
{
    uint64_t expect = slot_lifecycle(id, BP_SLOT_ACTIVE);
    uint64_t busy = slot_lifecycle(id, BP_SLOT_BUSY);

    if (__atomic_compare_exchange_n(&slot->lifecycle, &expect, busy, 0,
                                    __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        return 0;
    if (slot_lifecycle_id(expect) != id)
        return -ENOENT;
    if (slot_lifecycle_state(expect) != BP_SLOT_ACTIVE)
        return -EBUSY;
    return -EAGAIN;
}

static void slot_restore_active(struct bp_slot *slot, uint32_t id)
{
    __atomic_store_n(&slot->lifecycle, slot_lifecycle(id, BP_SLOT_ACTIVE), __ATOMIC_RELEASE);
}

static int slot_snapshot(struct bp_slot *slot, struct secdebug_bp_hit_resp *resp,
                         uint64_t *total_out)
{
    uint32_t s1;
    uint32_t s2;
    int retries = 0;

    do {
        s1 = __atomic_load_n(&slot->seq, __ATOMIC_ACQUIRE);
        if (s1 & 1)
            continue;

        if (resp) {
            int i;

            resp->trigger_addr = __atomic_load_n(&slot->trigger_addr, __ATOMIC_RELAXED);
            for (i = 0; i < 31; i++)
                resp->regs.regs[i] = __atomic_load_n(&slot->last_regs.regs[i], __ATOMIC_RELAXED);
            resp->regs.sp = __atomic_load_n(&slot->last_regs.sp, __ATOMIC_RELAXED);
            resp->regs.pc = __atomic_load_n(&slot->last_regs.pc, __ATOMIC_RELAXED);
            resp->regs.pstate = __atomic_load_n(&slot->last_regs.pstate, __ATOMIC_RELAXED);
        }
        *total_out = __atomic_load_n(&slot->hit_total, __ATOMIC_RELAXED);
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
        s2 = __atomic_load_n(&slot->seq, __ATOMIC_ACQUIRE);
        if (s1 == s2 && !(s2 & 1))
            return 0;
    } while (++retries < 100);

    return -EAGAIN;
}

static void slot_record_hit(struct bp_slot *slot, struct perf_event *event,
                            struct pt_regs_arm64 *regs)
{
    uint64_t lifecycle;
    uint32_t state;
    uint32_t seq;
    int retries = 0;

    lifecycle = __atomic_load_n(&slot->lifecycle, __ATOMIC_ACQUIRE);
    state = slot_lifecycle_state(lifecycle);
    if (state != BP_SLOT_ACTIVE && state != BP_SLOT_BUSY)
        return;

    /* EL0t is mode 0. Anything else is outside this module's user watch scope. */
    if (!regs || (regs->pstate & 0xfull) != 0)
        return;

    /* Acquire the record writer before disabling a one-shot perf event.
     * If all IRQ-safe CAS attempts fail, leave the event armed so a later
     * overflow can be captured instead of silently losing it forever. */
    do {
        uint32_t expect;

        seq = __atomic_load_n(&slot->seq, __ATOMIC_ACQUIRE);
        if (seq & 1)
            continue;
        expect = seq;
        if (__atomic_compare_exchange_n(&slot->seq, &expect, seq + 1u, 0,
                                        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            break;
    } while (++retries < 16);
    if (retries >= 16)
        return;

    if (g_syms.perf_event_disable_inatomic)
        g_syms.perf_event_disable_inatomic(event);

    {
        uint64_t total = __atomic_load_n(&slot->hit_total, __ATOMIC_RELAXED);
        int i;

        if (total != ~0ULL)
            __atomic_store_n(&slot->hit_total, total + 1, __ATOMIC_RELAXED);
        if (slot->bp_type == SECDEBUG_BP_TYPE_EXEC)
            __atomic_store_n(&slot->trigger_addr, regs->pc, __ATOMIC_RELAXED);
        else
            __atomic_store_n(&slot->trigger_addr, slot->target_addr, __ATOMIC_RELAXED);
        for (i = 0; i < 31; i++)
            __atomic_store_n(&slot->last_regs.regs[i], regs->regs[i], __ATOMIC_RELAXED);
        __atomic_store_n(&slot->last_regs.sp, regs->sp, __ATOMIC_RELAXED);
        __atomic_store_n(&slot->last_regs.pc, regs->pc, __ATOMIC_RELAXED);
        __atomic_store_n(&slot->last_regs.pstate, regs->pstate, __ATOMIC_RELAXED);
    }

    __atomic_store_n(&slot->seq, seq + 2u, __ATOMIC_RELEASE);
}

/*
 * Events are created disabled. The event pointer is published while the slot
 * stays BUSY; this excludes concurrent unregister/get_hit until enable returns.
 * Overflow callbacks can record a hit even while the slot is BUSY.
 */
__attribute__((noinline, target("branch-protection=bti")))
static void bp_perf_handler(struct perf_event *event, void *data, struct pt_regs_arm64 *regs)
{
    int i;

    (void)data;
    for (i = 0; i < SECDEBUG_MAX_BP_SLOTS; i++) {
        struct perf_event *ev = NULL;

        __atomic_load(&g_bp_slots[i].event, &ev, __ATOMIC_ACQUIRE);
        if (ev == event) {
            slot_record_hit(&g_bp_slots[i], event, regs);
            return;
        }
    }

    /* Unknown kernel event should never reach this handler; fail closed. */
    if (g_syms.perf_event_disable_inatomic)
        g_syms.perf_event_disable_inatomic(event);
}

/* Get a ref to the TRUE thread-group leader. The caller may have dropped
 * the host's RCU section while creating a perf event. Never substitute an
 * arbitrary worker-thread owner for the leader. */
static struct task_struct *pin_leader(pid_t tgid)
{
    struct task_struct *leader = NULL;

    if (tgid <= 0)
        return NULL;
    if (g_syms.find_get_task_by_vpid) {
        leader = g_syms.find_get_task_by_vpid(tgid);
    } else if (g_syms.get_task_struct && g_syms.rcu_read_lock &&
               g_syms.rcu_read_unlock) {
        /* Protected nested lookup; released after taking a task ref. */
        g_syms.rcu_read_lock();
        if (g_syms.find_task_by_vpid)
            leader = g_syms.find_task_by_vpid(tgid);
        else if (g_syms.find_vpid && g_syms.pid_task) {
            struct pid *pid = g_syms.find_vpid(tgid);
            if (pid)
                leader = g_syms.pid_task(pid, 0);
        }
        if (leader)
            g_syms.get_task_struct(leader);
        g_syms.rcu_read_unlock();
    }

    if (!leader)
        return NULL;
    if (g_syms.task_pid_nr_ns(leader, 0, NULL) != tgid ||
        g_syms.task_pid_nr_ns(leader, SECDEBUG_PIDTYPE_TGID, NULL) != tgid) {
        secdebug_task_put(leader);
        return NULL;
    }
    return leader;
}

/* 1 if the leader's init-namespace TGID is unchanged. Unknown stays alive. */
static int slot_leader_alive(const struct bp_slot *slot)
{
    pid_t tgid;

    if (!slot->owner_leader || slot->owner_tgid <= 0)
        return 0;
    tgid = secdebug_init_pid(slot->owner_leader, SECDEBUG_PIDTYPE_TGID);
    if (tgid < 0)
        return 1;
    return tgid == slot->owner_tgid;
}

static int slot_owner_ok(const struct bp_slot *slot)
{
    struct task_struct *cur = secdebug_current_task();
    pid_t cur_tgid;
    pid_t leader_tgid;

    if (!cur)
        return 0;
    if (slot->owner == cur)
        return 1;
    /* Compare init-namespace TGIDs so a sibling in another pid ns still matches. */
    leader_tgid = secdebug_init_pid(slot->owner_leader, SECDEBUG_PIDTYPE_TGID);
    if (leader_tgid <= 0)
        return 0;
    cur_tgid = secdebug_init_pid(cur, SECDEBUG_PIDTYPE_TGID);
    return cur_tgid > 0 && cur_tgid == leader_tgid;
}

/* perf_event_release_kernel() synchronizes with the overflow handler. */
static void slot_quiesce(struct bp_slot *slot)
{
    struct perf_event *ev = __atomic_load_n(&slot->event, __ATOMIC_ACQUIRE);
    struct task_struct *tsk = slot->task;
    struct task_struct *own = slot->owner;
    struct task_struct *leader = slot->owner_leader;
    int leader_extra = slot->leader_extra;

    if (ev && g_syms.perf_event_release_kernel)
        g_syms.perf_event_release_kernel(ev);
    __atomic_store_n(&slot->event, (struct perf_event *)0, __ATOMIC_RELEASE);

    if (tsk)
        secdebug_task_put(tsk);
    if (leader_extra && leader)
        secdebug_task_put(leader);
    if (own)
        secdebug_task_put(own);

    slot->task = NULL;
    slot->owner = NULL;
    slot->owner_leader = NULL;
    slot->leader_extra = 0;
    slot->owner_tgid = 0;
    slot->target_tid = 0;
    slot->bp_type = 0;
    slot->target_addr = 0;
    slot->hit_total = 0;
    slot->hit_consumed = 0;
    slot->trigger_addr = 0;
    slot->seq = 0;
    memset(&slot->last_regs, 0, sizeof(slot->last_regs));
    __atomic_store_n(&slot->lifecycle, 0, __ATOMIC_RELEASE);
}

static void slot_release_claim(struct bp_slot *slot, uint32_t id)
{
    uint64_t expect = slot_lifecycle(id, BP_SLOT_ALLOCATING);

    slot->target_tid = 0;
    slot->bp_type = 0;
    slot->target_addr = 0;
    slot->hit_total = 0;
    slot->hit_consumed = 0;
    slot->trigger_addr = 0;
    slot->seq = 0;
    memset(&slot->last_regs, 0, sizeof(slot->last_regs));
    __atomic_compare_exchange_n(&slot->lifecycle, &expect, 0, 0,
                                __ATOMIC_RELEASE, __ATOMIC_RELAXED);
}

int secdebug_hwbp_init(void)
{
    int i;

    for (i = 0; i < SECDEBUG_MAX_BP_SLOTS; i++)
        memset(&g_bp_slots[i], 0, sizeof(struct bp_slot));
    return 0;
}

/* Drop breakpoints whose owning thread group has been reaped. ctl0 holds RCU. */
static void secdebug_hwbp_reap(void)
{
    int i;

    for (i = 0; i < SECDEBUG_MAX_BP_SLOTS; i++) {
        struct bp_slot *slot = &g_bp_slots[i];
        uint64_t lifecycle = __atomic_load_n(&slot->lifecycle, __ATOMIC_ACQUIRE);
        uint32_t id = slot_lifecycle_id(lifecycle);
        int rcu_dropped = 0;

        if (slot_lifecycle_state(lifecycle) != BP_SLOT_ACTIVE)
            continue;
        if (!__atomic_compare_exchange_n(&slot->lifecycle, &lifecycle,
                                         slot_lifecycle(id, BP_SLOT_BUSY), 0,
                                         __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            continue;
        if (slot_leader_alive(slot)) {
            slot_restore_active(slot, id);
            continue;
        }

        __atomic_store_n(&slot->lifecycle, slot_lifecycle(id, BP_SLOT_DRAINING),
                         __ATOMIC_RELEASE);
        secdebug_rcu_drop(&rcu_dropped);
        slot_quiesce(slot);
        secdebug_rcu_restore(&rcu_dropped);
    }
}

uint32_t secdebug_hwbp_active_count(void)
{
    int i;
    uint32_t count = 0;

    /* PROBE_CAP must not reap. Reaping runs on the register path only. */
    for (i = 0; i < SECDEBUG_MAX_BP_SLOTS; i++) {
        uint32_t state = slot_lifecycle_state(
            __atomic_load_n(&g_bp_slots[i].lifecycle, __ATOMIC_ACQUIRE));

        if (state == BP_SLOT_ACTIVE || state == BP_SLOT_BUSY)
            count++;
    }
    return count;
}

int secdebug_hwbp_register(const struct secdebug_bp_reg_req *req, struct secdebug_bp_reg_resp *resp)
{
    int i;
    int slot_idx = -1;
    int rcu_dropped = 0;
    int rc;
    struct bp_slot *slot;
    struct task_struct *target_task = NULL;
    struct perf_event *event;
    unsigned char *attr_buf = NULL;
    struct secdebug_perf_attr *attr;
    uint64_t addr;
    uint64_t span;
    uint32_t align_mask;
    uint32_t public_id = 0;
    struct task_struct *owner = NULL;
    struct task_struct *leader = NULL;
    int leader_extra = 0;
    pid_t caller_tgid = 0;
    pid_t init_tgid = 0;

    if (!req || !resp)
        return -EINVAL;
    if (!g_syms.perf_event_create_kernel_counter || !g_syms.perf_event_release_kernel ||
        !g_syms.perf_event_enable || !g_syms.perf_event_disable ||
        !g_syms.perf_event_disable_inatomic)
        return -EOPNOTSUPP;
    if (!secdebug_caller_id_ready() || !g_init_pid_ns)
        return -EOPNOTSUPP;
    rc = secdebug_hwbp_prerequisites_ready();
    if (rc)
        return rc;

    secdebug_hwbp_reap();

    span = (req->bp_type == SECDEBUG_BP_TYPE_EXEC) ? 4 : (uint64_t)req->bp_len;
    if (!secdebug_is_user_address(req->target_addr, span))
        return -EFAULT;
    addr = secdebug_untag_user(req->target_addr);

    switch (req->bp_type) {
    case SECDEBUG_BP_TYPE_EXEC:
        /* ARM64 execution breakpoints cover one 4-byte instruction. */
        if (req->bp_len != 4 || (addr & 3))
            return -EINVAL;
        break;
    case SECDEBUG_BP_TYPE_READ:
    case SECDEBUG_BP_TYPE_WRITE:
    case SECDEBUG_BP_TYPE_RW:
        if (req->bp_len != 4 && req->bp_len != 8)
            return -EINVAL;
        align_mask = req->bp_len - 1;
        if (addr & align_mask)
            return -EINVAL;
        break;
    default:
        return -EINVAL;
    }

    for (i = 0; i < SECDEBUG_MAX_BP_SLOTS; i++) {
        uint64_t free_lifecycle = 0;
        uint64_t reserving = slot_lifecycle(0, BP_SLOT_ALLOCATING);

        if (__atomic_compare_exchange_n(&g_bp_slots[i].lifecycle, &free_lifecycle, reserving,
                                        0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
            public_id = alloc_public_id(i);
            if (!public_id) {
                __atomic_store_n(&g_bp_slots[i].lifecycle, 0, __ATOMIC_RELEASE);
                return -ENOSPC;
            }
            slot_idx = i;
            __atomic_store_n(&g_bp_slots[i].lifecycle,
                             slot_lifecycle(public_id, BP_SLOT_ALLOCATING),
                             __ATOMIC_RELEASE);
            break;
        }
    }
    if (slot_idx < 0)
        return -ENOSPC;

    slot = &g_bp_slots[slot_idx];
    rc = secdebug_pin_task(req->target_tid, &target_task, &rcu_dropped);
    if (rc) {
        slot_release_claim(slot, public_id);
        return rc;
    }

    owner = secdebug_pin_current();
    if (!owner) {
        secdebug_task_put(target_task);
        secdebug_rcu_restore(&rcu_dropped);
        slot_release_claim(slot, public_id);
        return -EOPNOTSUPP;
    }

    caller_tgid = g_syms.task_pid_nr_ns(owner, SECDEBUG_PIDTYPE_TGID, NULL);
    init_tgid = secdebug_init_pid(owner, SECDEBUG_PIDTYPE_TGID);
    if (caller_tgid <= 0 || init_tgid <= 0) {
        secdebug_task_put(target_task);
        secdebug_task_put(owner);
        secdebug_rcu_restore(&rcu_dropped);
        slot_release_claim(slot, public_id);
        return -EOPNOTSUPP;
    }
    leader = pin_leader(caller_tgid);
    if (!leader ||
        secdebug_init_pid(leader, 0) != init_tgid ||
        secdebug_init_pid(leader, SECDEBUG_PIDTYPE_TGID) != init_tgid) {
        if (leader)
            secdebug_task_put(leader);
        secdebug_task_put(target_task);
        secdebug_task_put(owner);
        secdebug_rcu_restore(&rcu_dropped);
        slot_release_claim(slot, public_id);
        return -ESRCH;
    }
    leader_extra = 1;

    slot->target_tid = req->target_tid;
    slot->owner = owner;
    slot->owner_leader = leader;
    slot->leader_extra = leader_extra;
    slot->owner_tgid = init_tgid;
    slot->bp_type = req->bp_type;
    slot->target_addr = addr;
    slot->hit_total = 0;
    slot->hit_consumed = 0;
    slot->trigger_addr = 0;
    slot->seq = 0;
    memset(&slot->last_regs, 0, sizeof(slot->last_regs));

    attr_buf = secdebug_alloc(SECDEBUG_PERF_ATTR_BUF);
    if (!attr_buf) {
        slot->owner = NULL;
        slot->owner_leader = NULL;
        slot->leader_extra = 0;
        slot->owner_tgid = 0;
        secdebug_task_put(target_task);
        secdebug_task_put(leader);
        secdebug_task_put(owner);
        secdebug_rcu_restore(&rcu_dropped);
        slot_release_claim(slot, public_id);
        return -ENOMEM;
    }
    memset(attr_buf, 0, SECDEBUG_PERF_ATTR_BUF);
    attr = (struct secdebug_perf_attr *)attr_buf;
    attr->type = PERF_TYPE_BREAKPOINT;
    attr->size = SECDEBUG_PERF_ATTR_SIZE;
    attr->sample_period = 1;
    attr->bp_addr = addr;
    attr->flags = PERF_DISABLED | PERF_PINNED | PERF_EXCLUDE_KERNEL | PERF_EXCLUDE_HV;

    switch (req->bp_type) {
    case SECDEBUG_BP_TYPE_EXEC:
        attr->bp_type = HW_BREAKPOINT_X;
        attr->bp_len = HW_BREAKPOINT_LEN_4;
        break;
    case SECDEBUG_BP_TYPE_READ:
        attr->bp_type = HW_BREAKPOINT_R;
        attr->bp_len = (req->bp_len == 8) ? HW_BREAKPOINT_LEN_8 : HW_BREAKPOINT_LEN_4;
        break;
    case SECDEBUG_BP_TYPE_WRITE:
        attr->bp_type = HW_BREAKPOINT_W;
        attr->bp_len = (req->bp_len == 8) ? HW_BREAKPOINT_LEN_8 : HW_BREAKPOINT_LEN_4;
        break;
    default:
        attr->bp_type = HW_BREAKPOINT_RW;
        attr->bp_len = (req->bp_len == 8) ? HW_BREAKPOINT_LEN_8 : HW_BREAKPOINT_LEN_4;
        break;
    }

    __sync_synchronize();
    event = g_syms.perf_event_create_kernel_counter((struct perf_event_attr *)attr, -1,
                                                    target_task, (void *)bp_perf_handler, slot);
    secdebug_free(attr_buf, SECDEBUG_PERF_ATTR_BUF);
    attr_buf = NULL;
    if (!event || IS_ERR(event)) {
        int err = event ? (int)PTR_ERR(event) : -EINVAL;

        if (err == -ENODEV || err == -ENOSYS || err == -EOPNOTSUPP || err == -ENOENT) {
            __atomic_fetch_and(&g_cap_flags,
                               ~(uint32_t)(SECDEBUG_CAP_HW_BREAK | SECDEBUG_CAP_HW_WATCH),
                               __ATOMIC_RELEASE);
            printk("secdebug: breakpoint create failed (%d); HW caps cleared\n", err);
        }
        slot->owner = NULL;
        slot->owner_leader = NULL;
        slot->leader_extra = 0;
        slot->owner_tgid = 0;
        slot->target_addr = 0;
        slot->bp_type = 0;
        secdebug_task_put(target_task);
        if (leader_extra && leader)
            secdebug_task_put(leader);
        secdebug_task_put(owner);
        secdebug_rcu_restore(&rcu_dropped);
        slot_release_claim(slot, public_id);
        return err;
    }

    slot->task = target_task;
    __atomic_store_n(&slot->event, event, __ATOMIC_RELEASE);
    /* Keep concurrent control calls from freeing event until enable returns. */
    __atomic_store_n(&slot->lifecycle, slot_lifecycle(public_id, BP_SLOT_BUSY),
                     __ATOMIC_RELEASE);

    /* A hardware hit during enable is already supported in the BUSY state.
     * Keep BP_SLOT_BUSY until finish_register() commits or rolls back. */
    g_syms.perf_event_enable(event);
    resp->slot_id = public_id;
    resp->reserved = 0;
    secdebug_rcu_restore(&rcu_dropped);
    return 0;
}

void secdebug_hwbp_finish_register(uint32_t slot_id, int delivered)
{
    int idx;
    int rcu_dropped = 0;
    struct bp_slot *slot;
    uint64_t expected;

    idx = slot_index_from_id(slot_id);
    if (idx < 0)
        return;
    slot = &g_bp_slots[idx];
    expected = slot_lifecycle(slot_id, BP_SLOT_BUSY);
    if (delivered) {
        __atomic_compare_exchange_n(&slot->lifecycle, &expected,
                                    slot_lifecycle(slot_id, BP_SLOT_ACTIVE), 0,
                                    __ATOMIC_RELEASE, __ATOMIC_RELAXED);
        return;
    }
    if (!__atomic_compare_exchange_n(&slot->lifecycle, &expected,
                                     slot_lifecycle(slot_id, BP_SLOT_DRAINING), 0,
                                     __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
        return;
    secdebug_rcu_drop(&rcu_dropped);
    slot_quiesce(slot);
    secdebug_rcu_restore(&rcu_dropped);
}

int secdebug_hwbp_unregister(const struct secdebug_bp_unreg_req *req)
{
    int idx;
    int rc;
    int rcu_dropped = 0;
    struct bp_slot *slot;

    if (!req)
        return -EINVAL;

    idx = slot_index_from_id(req->slot_id);
    if (idx < 0)
        return -EINVAL;

    slot = &g_bp_slots[idx];
    rc = slot_claim_active(slot, req->slot_id);
    if (rc)
        return rc;
    if (!slot_owner_ok(slot)) {
        slot_restore_active(slot, req->slot_id);
        return -EPERM;
    }

    __atomic_store_n(&slot->lifecycle,
                     slot_lifecycle(req->slot_id, BP_SLOT_DRAINING),
                     __ATOMIC_RELEASE);
    secdebug_rcu_drop(&rcu_dropped);
    slot_quiesce(slot);
    secdebug_rcu_restore(&rcu_dropped);
    return 0;
}

int secdebug_hwbp_get_hit(const struct secdebug_bp_hit_req *req,
                          struct secdebug_bp_hit_resp *resp,
                          uint64_t *snapshot_total)
{
    int idx;
    int rc;
    struct bp_slot *slot;
    uint64_t total = 0;
    uint64_t consumed;
    uint64_t pending;

    if (!req || !resp || !snapshot_total)
        return -EINVAL;

    idx = slot_index_from_id(req->slot_id);
    if (idx < 0)
        return -EINVAL;

    slot = &g_bp_slots[idx];
    rc = slot_claim_active(slot, req->slot_id);
    if (rc)
        return rc;
    if (!slot_owner_ok(slot)) {
        slot_restore_active(slot, req->slot_id);
        return -EPERM;
    }

    memset(resp, 0, sizeof(*resp));
    resp->slot_id = req->slot_id;
    rc = slot_snapshot(slot, resp, &total);
    if (rc) {
        slot_restore_active(slot, req->slot_id);
        return rc;
    }

    consumed = __atomic_load_n(&slot->hit_consumed, __ATOMIC_ACQUIRE);
    pending = total >= consumed ? total - consumed : 0;
    resp->hit_count = pending > 0xffffffffULL ? 0xffffffffU : (uint32_t)pending;
    *snapshot_total = total;

    /* Keep BUSY until the caller has copied the result and committed ACK.
     * This lease makes GET_HIT vs UNREGISTER linearizable. */
    return 0;
}

void secdebug_hwbp_finish_hit(const struct secdebug_bp_hit_req *req,
                             uint64_t snapshot_total, int delivered)
{
    int idx;
    int rcu_dropped = 0;
    struct bp_slot *slot;
    struct perf_event *event;
    uint64_t current_total;
    uint64_t consumed;

    if (!req)
        return;
    idx = slot_index_from_id(req->slot_id);
    if (idx < 0)
        return; /* impossible while this call owns the BUSY lease */
    slot = &g_bp_slots[idx];
    if (__atomic_load_n(&slot->lifecycle, __ATOMIC_ACQUIRE) !=
        slot_lifecycle(req->slot_id, BP_SLOT_BUSY))
        return; /* never release another generation */

    if (delivered && req->clear_hit && snapshot_total != 0) {
        event = __atomic_load_n(&slot->event, __ATOMIC_ACQUIRE);
        if (event) {
            /* Synchronously disable before committing the acknowledgement. */
            secdebug_rcu_drop(&rcu_dropped);
            g_syms.perf_event_disable(event);
            secdebug_rcu_restore(&rcu_dropped);
        }
        current_total = __atomic_load_n(&slot->hit_total, __ATOMIC_ACQUIRE);
        consumed = __atomic_load_n(&slot->hit_consumed, __ATOMIC_ACQUIRE);
        if (snapshot_total > consumed) {
            consumed = snapshot_total < current_total ? snapshot_total : current_total;
            __atomic_store_n(&slot->hit_consumed, consumed, __ATOMIC_RELEASE);
        }
        /* Acknowledging a hit never re-enables this one-shot event. This
         * avoids dereferencing guessed private perf_event/irq_work offsets.
         * Unregister and register a fresh event to observe a later hit. */
    }
    slot_restore_active(slot, req->slot_id);
}

/*
 * Dependency gate only. This does NOT test hardware or mark a hit observed.
 * The optional userspace smoke test can check an actual self-process hit
 * on an authorized ARM64 device; it must not run from PROBE_CAP.
 */
int secdebug_hwbp_prerequisites_ready(void)
{
    if (!g_syms.perf_event_create_kernel_counter || !g_syms.perf_event_release_kernel ||
        !g_syms.perf_event_enable || !g_syms.perf_event_disable ||
        !g_syms.perf_event_disable_inatomic || !g_init_pid_ns)
        return -EOPNOTSUPP;
    return 0;
}

void secdebug_hwbp_cleanup(void)
{
    int i;

    /* Host compatibility requirement: KPM_EXIT must run outside RCU read-side. */
    for (i = 0; i < SECDEBUG_MAX_BP_SLOTS; i++) {
        struct bp_slot *slot = &g_bp_slots[i];
        uint64_t lifecycle = __atomic_load_n(&slot->lifecycle, __ATOMIC_ACQUIRE);
        uint32_t state = slot_lifecycle_state(lifecycle);
        uint32_t id = slot_lifecycle_id(lifecycle);

        if (state != BP_SLOT_ACTIVE && state != BP_SLOT_BUSY)
            continue;
        if (!__atomic_compare_exchange_n(&slot->lifecycle, &lifecycle,
                                         slot_lifecycle(id, BP_SLOT_DRAINING), 0,
                                         __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            continue;
        slot_quiesce(slot);
    }
}
