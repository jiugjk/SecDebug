/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * secdebug_internal.h - Internal definitions and dynamic symbol dispatch
 */

#ifndef _SECDEBUG_INTERNAL_H_
#define _SECDEBUG_INTERNAL_H_

#include <compiler.h>
#include <ktypes.h>
#include <kpmodule.h>
#include <kputils.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/err.h>
#include <uapi/asm-generic/errno.h>

/* Prototype for common export in KernelPatch/KPatch-Next */
int is_su_allow_uid(uid_t uid);

/* Mandatory loader import: old kpimg and the unsupported LKM loader fail
 * relocation before KPM_INIT. The return value also checks live primitives. */
#define SECDEBUG_HOST_CONTRACT_V1 0x53440101UL
extern unsigned long secdebug_host_contract_v1(void);

/* A raw internal perf_event offset is not a target ABI proof. Keep hardware
 * breakpoints one-shot until a typed, target-built rearm API is available. */
#ifdef SECDEBUG_PERF_PENDING_OFFSET
#error "SECDEBUG_PERF_PENDING_OFFSET is unsupported: use unregister/register for a new one-shot event"
#endif

#include "secdebug_proto.h"

/* Forward declarations of Linux kernel opaque types */
struct task_struct;
struct pid;
struct mm_struct;
struct perf_event;
struct perf_event_attr;
struct pt_regs;

/* 52-bit user VA, after the TBI/MTE tag byte is removed. Bit 55 stays clear. */
#define SECDEBUG_USER_VA_MAX 0x0010000000000000ULL

/* Dynamic function pointers resolved via kallsyms_lookup_name */
typedef int (*fn_access_process_vm)(struct task_struct *tsk, unsigned long addr,
                                   void *buf, int len, unsigned int gup_flags);
typedef int (*fn_access_remote_vm)(struct mm_struct *mm, unsigned long addr,
                                  void *buf, int len, unsigned int gup_flags);

typedef struct task_struct *(*fn_find_task_by_vpid)(pid_t vnr);
typedef struct task_struct *(*fn_find_get_task_by_vpid)(pid_t nr);
typedef struct pid *(*fn_find_vpid)(int nr);
typedef struct task_struct *(*fn_pid_task)(struct pid *pid, int type);
typedef struct task_struct *(*fn_get_task_struct)(struct task_struct *t);
typedef void (*fn_put_task_struct)(struct task_struct *t);
typedef struct mm_struct *(*fn_get_task_mm)(struct task_struct *t);
typedef void (*fn_mmput)(struct mm_struct *mm);
typedef pid_t (*fn_task_pid_nr_ns)(struct task_struct *task, int type, void *ns);
typedef void (*fn_rcu_read_lock)(void);
typedef void (*fn_rcu_read_unlock)(void);

typedef struct perf_event *(*fn_perf_event_create_kernel_counter)(
    struct perf_event_attr *attr, int cpu, struct task_struct *task,
    void *overflow_handler, void *context);
typedef void (*fn_perf_event_release_kernel)(struct perf_event *event);
typedef void (*fn_perf_event_enable)(struct perf_event *event);
typedef void (*fn_perf_event_disable)(struct perf_event *event);
typedef void (*fn_perf_event_disable_inatomic)(struct perf_event *event);

struct secdebug_syms {
    fn_access_process_vm              access_process_vm;
    fn_access_remote_vm               access_remote_vm;
    fn_find_task_by_vpid              find_task_by_vpid;
    fn_find_get_task_by_vpid          find_get_task_by_vpid;
    fn_find_vpid                      find_vpid;
    fn_pid_task                       pid_task;
    fn_get_task_struct                get_task_struct;
    fn_put_task_struct                put_task_struct;
    fn_get_task_mm                    get_task_mm;
    fn_mmput                          mmput;
    fn_task_pid_nr_ns                 task_pid_nr_ns;
    fn_rcu_read_lock                  rcu_read_lock;
    fn_rcu_read_unlock                rcu_read_unlock;
    fn_perf_event_create_kernel_counter perf_event_create_kernel_counter;
    fn_perf_event_release_kernel        perf_event_release_kernel;
    fn_perf_event_enable                perf_event_enable;
    fn_perf_event_disable               perf_event_disable;
    fn_perf_event_disable_inatomic      perf_event_disable_inatomic;
};

extern struct secdebug_syms g_syms;

/* init_pid_ns address, or NULL if the symbol did not resolve. */
extern void *g_init_pid_ns;

/* PID in the init namespace. -1 if it cannot be named, 0 if the task is gone. */
static inline pid_t secdebug_init_pid(struct task_struct *task, int type)
{
    if (!task || !g_syms.task_pid_nr_ns || !g_init_pid_ns)
        return -1;
    return g_syms.task_pid_nr_ns(task, type, g_init_pid_ns);
}

extern uint32_t g_page_size;
extern uint32_t g_cap_flags;
extern uint64_t g_auth_token;

/* Symbol initialization */
int secdebug_resolve_symbols(void);
void secdebug_task_init(void);

/* Memory read / write subsystem */
int secdebug_mem_read(const struct secdebug_mem_read_req *req, void *out_buf, uint32_t *out_len);
int secdebug_mem_write(const struct secdebug_mem_write_req *req, const void *in_data, uint32_t *bytes_written);
#define SECDEBUG_FOLL_WRITE 0x01u
unsigned int secdebug_foll_force(void);
int secdebug_alloc_ready(void);
void secdebug_bind_runtime(void);
void *secdebug_alloc(unsigned long size);
void secdebug_free(void *ptr, unsigned long size);
int secdebug_remote_mem_ready(void);
int secdebug_pin_mm(pid_t pid, struct mm_struct **out, int *rcu_dropped);

#define SECDEBUG_MAX_MEM_SESSIONS 8
void secdebug_session_init(void);
void secdebug_session_cleanup(void);
int secdebug_session_ready(void);
int secdebug_session_open(const struct secdebug_session_open_req *req,
                          struct secdebug_session_open_resp *resp);
/* open() holds SESSION_BUSY on success; finish_open() MUST run. */
void secdebug_session_finish_open(uint32_t id, int delivered);
int secdebug_session_read(const struct secdebug_session_read_req *req,
                          void *out, uint32_t *len);
int secdebug_session_write(const struct secdebug_session_write_req *req,
                           const void *data, uint32_t *written);
int secdebug_session_close(uint32_t id);

/* Hardware breakpoint subsystem */
#define SECDEBUG_MAX_BP_SLOTS 4

int secdebug_hwbp_init(void);
void secdebug_hwbp_cleanup(void);
int secdebug_hwbp_register(const struct secdebug_bp_reg_req *req, struct secdebug_bp_reg_resp *resp);
/* register() holds BP_SLOT_BUSY on success; finish_register() MUST run. */
void secdebug_hwbp_finish_register(uint32_t slot_id, int delivered);
int secdebug_hwbp_unregister(const struct secdebug_bp_unreg_req *req);
int secdebug_hwbp_get_hit(const struct secdebug_bp_hit_req *req, struct secdebug_bp_hit_resp *resp,
                          uint64_t *snapshot_total);
/* get_hit() holds BUSY on success; finish_hit() MUST run, even if copy fails. */
void secdebug_hwbp_finish_hit(const struct secdebug_bp_hit_req *req,
                             uint64_t snapshot_total, int delivered);
uint32_t secdebug_hwbp_active_count(void);
/* Dependency gate only; actual event creation failures clear HW caps. */
int secdebug_hwbp_prerequisites_ready(void);

/*
 * Pin a user task. module_control0 holds one RCU read-side critical section
 * for the whole callback. On success the task ref is held and that section
 * is dropped so the caller may sleep. secdebug_rcu_restore() puts the
 * section back before returning to the host. A failure before the drop
 * leaves the section held. A failure after the drop restores it.
 *
 * secdebug_pin_current() takes a ref on the caller and does not change the
 * RCU nest. Compare the returned pointer with secdebug_current_task().
 * The caller must put it.
 */
int secdebug_pin_task(pid_t pid, struct task_struct **task, int *rcu_dropped);
struct task_struct *secdebug_pin_current(void);
struct task_struct *secdebug_current_task(void);
void secdebug_task_put(struct task_struct *task);
void secdebug_rcu_drop(int *rcu_dropped);
void secdebug_rcu_restore(int *rcu_dropped);
int secdebug_task_ops_ready(void);
int secdebug_mem_ops_ready(void);
int secdebug_caller_id_ready(void);
pid_t secdebug_current_pid(void);

static inline uint64_t secdebug_untag_user(uint64_t addr)
{
    return addr & 0x00FFFFFFFFFFFFFFULL;
}

/* True when [addr, addr+len) sits entirely in the user VA range. */
static inline int secdebug_is_user_address(uint64_t addr, uint64_t len)
{
    addr = secdebug_untag_user(addr);
    if (len == 0 || len > SECDEBUG_USER_VA_MAX)
        return 0;
    if (addr >= SECDEBUG_USER_VA_MAX)
        return 0;
    if (addr + len < addr)
        return 0;
    if (addr + len > SECDEBUG_USER_VA_MAX)
        return 0;
    return 1;
}

#endif /* _SECDEBUG_INTERNAL_H_ */
