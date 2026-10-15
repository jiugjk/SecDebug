/* SPDX-License-Identifier: Apache-2.0 */
/*
 * libsecdebug.h - Userspace client SDK header for secdebug KPM
 */

#ifndef _LIBSECDEBUG_H_
#define _LIBSECDEBUG_H_

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "../include/secdebug_proto.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SECDEBUG_HOST_UNKNOWN = 0,
    SECDEBUG_HOST_KERNELPATCH,     /* KernelPatch: 5-arg SuperCall with key */
    SECDEBUG_HOST_KPATCH_NEXT,     /* KPatch-Next: 4-arg SuperCall with root UID */
} secdebug_host_type_t;

struct secdebug_client {
    secdebug_host_type_t host_type;
    char superkey[128];
    char module_name[32];
    uint64_t auth_token;
    uint32_t seq;
    /* Private SDK state; compile consumers against this header. */
    uint32_t mem_busy;
    uint32_t pending_session_id;
    int64_t pending_session_owner_tid;
    int cleanup_error;
};

/**
 * Initialize a fresh context, detecting the host automatically. Do not
 * reinitialize or copy a live context; destroy it successfully first.
 */
int secdebug_client_init(struct secdebug_client *client, const char *superkey, uint64_t auth_token);

/**
 * Close a retained session, then scrub credentials. Returns 0 on success.
 * On failure the context is preserved: retry cleanup/destroy on the thread
 * that opened the session. Init/destroy require no concurrent SDK calls.
 */
int secdebug_client_destroy(struct secdebug_client *client);

/**
 * Retry a pending CLOSE (at most three attempts); never repeats data writes.
 * Must run on the opening thread. 0 means no cleanup remains. A failure
 * retains the handle and blocks new memory transfers until cleanup succeeds.
 */
int secdebug_client_cleanup(struct secdebug_client *client);

/**
 * Last cleanup result, independent of the last data operation's return value.
 * Check this after read/write even if the full byte count was returned.
 * Prefer one client per thread; simultaneous memory/cleanup calls on a
 * shared client return -EBUSY instead of sharing session ownership.
 */
int secdebug_client_cleanup_error(const struct secdebug_client *client);

/**
 * Probe module presence and capabilities
 */
int secdebug_probe(struct secdebug_client *client, struct secdebug_cap_resp *cap);

/**
 * Read memory from target process.
 * On success returns the byte count (it may be shorter than len when the
 * target itself stops early, with no later error). If a later chunk fails,
 * returns that negative errno and, when bytes_done is non-NULL, stores the
 * confirmed prefix length there. bytes_done may be NULL.
 * A read itself has no target-memory side effect. -EINPROGRESS is possible
 * if a session OPEN receipt is lost/corrupt; do not blindly repeat OPEN.
 * Transfers longer than 512 bytes pin one mm with a memory session; the
 * creating thread must perform all chunks. Old modules without that feature
 * return -EOPNOTSUPP instead of risking PID reuse.
 * The byte count and bytes_done describe data only; inspect cleanup_error
 * separately. Cleanup failure never turns a completed write into a retry.
 */
int secdebug_read_mem(struct secdebug_client *client, int target_pid, uint64_t addr,
                      void *buf, size_t len, size_t *bytes_done);

/**
 * Write memory to target process. Returns bytes completed. Multi-chunk writes
 * are not atomic; a positive partial byte count can be returned on a later
 * definite error. -EINPROGRESS means the response copy was lost (-EFAULT)
 * or corrupt after a command that may have written or opened a session.
 * Definite errors remain negative if no earlier chunk completed.
 * Never blindly retry -EINPROGRESS or assume zero side effects.
 * Inspect secdebug_client_cleanup_error() independently even on success;
 * a failed CLOSE must not cause an already completed write to be repeated.
 */
int secdebug_write_mem(struct secdebug_client *client, int target_pid, uint64_t addr, const void *buf, size_t len);

/**
 * Register hardware breakpoint or watchpoint. -EINPROGRESS means the
 * register receipt was lost. Authentication and resource errors are returned
 * unchanged and can be retried once the cause is fixed.
 */
int secdebug_register_bp(struct secdebug_client *client, int target_tid, uint32_t bp_type,
                         uint64_t addr, uint32_t bp_len, uint32_t *slot_id);

/**
 * Unregister hardware breakpoint
 */
int secdebug_unregister_bp(struct secdebug_client *client, uint32_t slot_id);

/**
 * Poll or clear breakpoint hit context. clear_hit == 0 is not mutating.
 * clear_hit != 0 maps a lost receipt to -EINPROGRESS. Clearing acknowledges
 * the snapshot only: the event stays disarmed after its first hit. Unregister
 * and register a fresh event to arm again; private perf offsets are forbidden.
 */
int secdebug_get_hit(struct secdebug_client *client, uint32_t slot_id, bool clear_hit,
                     struct secdebug_bp_hit_resp *resp);

#ifdef __cplusplus
}
#endif

#endif /* _LIBSECDEBUG_H_ */
