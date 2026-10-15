/* SPDX-License-Identifier: Apache-2.0 */
/* Compare the minimal perf prefix with the Linux UAPI headers available on
 * the build machine. This does NOT substitute for target-kernel validation. */
#include <stddef.h>
#include <linux/perf_event.h>
#include "secdebug_perf_abi.h"

_Static_assert(offsetof(struct secdebug_perf_attr, type) ==
               offsetof(struct perf_event_attr, type), "perf type ABI");
_Static_assert(offsetof(struct secdebug_perf_attr, size) ==
               offsetof(struct perf_event_attr, size), "perf size ABI");
_Static_assert(offsetof(struct secdebug_perf_attr, config) ==
               offsetof(struct perf_event_attr, config), "perf config ABI");
_Static_assert(offsetof(struct secdebug_perf_attr, sample_period) ==
               offsetof(struct perf_event_attr, sample_period), "perf period ABI");
_Static_assert(offsetof(struct secdebug_perf_attr, sample_type) ==
               offsetof(struct perf_event_attr, sample_type), "perf sample ABI");
_Static_assert(offsetof(struct secdebug_perf_attr, bp_type) ==
               offsetof(struct perf_event_attr, bp_type), "perf type ABI");
_Static_assert(offsetof(struct secdebug_perf_attr, bp_addr) ==
               offsetof(struct perf_event_attr, bp_addr), "perf addr ABI");
_Static_assert(offsetof(struct secdebug_perf_attr, bp_len) ==
               offsetof(struct perf_event_attr, bp_len), "perf len ABI");
int main(void) { return 0; }
