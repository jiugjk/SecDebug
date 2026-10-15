/* SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0 */
/* Minimum perf_event_attr prefix used by this KPM. Target ABI validation is
 * still required; these compile-time checks only guard accidental layout drift. */
#ifndef _SECDEBUG_PERF_ABI_H_
#define _SECDEBUG_PERF_ABI_H_
#include "secdebug_proto.h"

struct secdebug_perf_attr {
    uint32_t type;
    uint32_t size;
    uint64_t config;
    uint64_t sample_period;
    uint64_t sample_type;
    uint64_t read_format;
    uint64_t flags;
    uint32_t wakeup_events;
    uint32_t bp_type;
    uint64_t bp_addr;
    uint64_t bp_len;
};
_Static_assert(__builtin_offsetof(struct secdebug_perf_attr, flags) == 40,
               "perf flags ABI mismatch");
_Static_assert(__builtin_offsetof(struct secdebug_perf_attr, bp_type) == 52,
               "perf bp_type ABI mismatch");
_Static_assert(__builtin_offsetof(struct secdebug_perf_attr, bp_addr) == 56,
               "perf bp_addr ABI mismatch");
_Static_assert(__builtin_offsetof(struct secdebug_perf_attr, bp_len) == 64,
               "perf bp_len ABI mismatch");
_Static_assert(sizeof(struct secdebug_perf_attr) == 72,
               "perf prefix ABI mismatch");

#ifdef SECDEBUG_VERIFY_TARGET_PERF_ABI
#include <linux/perf_event.h>
_Static_assert(__builtin_offsetof(struct secdebug_perf_attr, type) ==
               __builtin_offsetof(struct perf_event_attr, type), "perf type ABI");
_Static_assert(__builtin_offsetof(struct secdebug_perf_attr, size) ==
               __builtin_offsetof(struct perf_event_attr, size), "perf size ABI");
_Static_assert(__builtin_offsetof(struct secdebug_perf_attr, bp_type) ==
               __builtin_offsetof(struct perf_event_attr, bp_type), "perf bp_type ABI");
_Static_assert(__builtin_offsetof(struct secdebug_perf_attr, bp_addr) ==
               __builtin_offsetof(struct perf_event_attr, bp_addr), "perf bp_addr ABI");
_Static_assert(__builtin_offsetof(struct secdebug_perf_attr, bp_len) ==
               __builtin_offsetof(struct perf_event_attr, bp_len), "perf bp_len ABI");
_Static_assert(sizeof(struct perf_event_attr) >= sizeof(struct secdebug_perf_attr),
               "target perf_event_attr smaller than prefix");
#endif
#endif
