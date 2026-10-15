#define _POSIX_C_SOURCE 200809L
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * test_secdebug.c - Minimal CLI smoke test for libsecdebug.
 *
 * Secrets arrive via environment instead of argv (so they are not part of
 * the ordinary command line). Never print their values; remove the environment
 * bindings after client initialization and explicitly zero the client state.
 */

#include "libsecdebug.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

static int parse_token(const char *text, uint64_t *out)
{
    char *end = NULL;
    unsigned long long value;

    if (!text || !out || strlen(text) != 16)
        return -1;
    errno = 0;
    value = strtoull(text, &end, 16);
    if (errno || !end || *end != '\0' || value == 0)
        return -1;
    *out = (uint64_t)value;
    return 0;
}

/*
 * Explicitly opt-in on a disposable ARM64 test device. Unlike PROBE_CAP,
 * this actually arms a watchpoint on THIS process, executes a watched write
 * and requires an observed perf overflow with a saved user PC.
 * Never guess an address or watch another process in this smoke test.
 */
static int run_self_watchpoint(struct secdebug_client *client)
{
    volatile uint64_t watched __attribute__((aligned(8))) = 0;
    uint64_t addr = (uint64_t)(uintptr_t)&watched;
    uint32_t slot_id = 0;
    struct secdebug_bp_hit_resp hit = { 0 };
    struct timespec pause = { .tv_sec = 0, .tv_nsec = 10000000L };
    int rc;
    int cleanup_rc;
    int observed = 0;
    int attempt;

    /* This CLI runs on one main thread, so its PID is also its TID. */
    rc = secdebug_register_bp(client, (int)getpid(), SECDEBUG_BP_TYPE_WRITE,
                              addr, 8, &slot_id);
    if (rc != 0) {
        fprintf(stderr, "Self-watchpoint register failed: %d\n", rc);
        if (rc == -EINPROGRESS)
            fprintf(stderr, "Ambiguous register receipt: do not blindly retry.\n");
        return 1;
    }

    /* A volatile atomic store ensures the watched address is really written. */
    __atomic_store_n(&watched, 0x5863c4152b0679a1ULL, __ATOMIC_SEQ_CST);
    for (attempt = 0; attempt < 50; attempt++) {
        rc = secdebug_get_hit(client, slot_id, false, &hit);
        if (rc != 0) {
            fprintf(stderr, "Self-watchpoint hit query failed: %d\n", rc);
            break;
        }
        if (hit.hit_count > 0 && hit.trigger_addr == addr && hit.regs.pc != 0) {
            observed = 1;
            break;
        }
        (void)nanosleep(&pause, NULL);
    }

    /* Do not request clear/rearm; the test needs only one observed hit. */
    cleanup_rc = secdebug_unregister_bp(client, slot_id);
    if (cleanup_rc != 0) {
        fprintf(stderr, "Self-watchpoint cleanup failed: %d; check device state.\n", cleanup_rc);
        if (cleanup_rc == -EINPROGRESS)
            fprintf(stderr, "Ambiguous unregister receipt: do not blindly retry.\n");
        return 1;
    }
    if (!observed) {
        fprintf(stderr, "Self-watchpoint did not observe a valid hardware hit.\n");
        return 1;
    }
    puts("Self-watchpoint: observed a hardware hit with register PC; cleanup passed.");
    return 0;
}

int main(void)
{
    const char *key = getenv("SECDEBUG_SUPERKEY");
    const char *token_text = getenv("SECDEBUG_AUTH_TOKEN");
    uint64_t token = 0;
    const char *hwbp_env = getenv("SECDEBUG_HWBP_SMOKE");
    int run_hwbp = hwbp_env && strcmp(hwbp_env, "1") == 0;
    struct secdebug_client client = { 0 };
    struct secdebug_cap_resp cap;
    pid_t my_pid;
    uint64_t test_val = 0x1122334455667788ULL;
    uint64_t read_buf = 0;
    int rc;
    int exit_code = 1;

    if (parse_token(token_text, &token) != 0) {
        fprintf(stderr, "Set SECDEBUG_AUTH_TOKEN to the 16-hex-digit module token.\n");
        exit_code = 2;
        goto done;
    }

    rc = secdebug_client_init(&client, key, token);
    /* getenv() pointers are invalid after unsetenv(): do not use them again. */
    (void)unsetenv("SECDEBUG_SUPERKEY");
    (void)unsetenv("SECDEBUG_AUTH_TOKEN");
    (void)unsetenv("SECDEBUG_HWBP_SMOKE");
    token = 0;
    if (rc != 0) {
        fprintf(stderr, "Host detection failed: %d\n", rc);
        goto done;
    }

    rc = secdebug_probe(&client, &cap);
    if (rc != 0) {
        fprintf(stderr, "Module probe failed: %d\n", rc);
        goto done;
    }

    printf("secdebug: host=%s proto=0x%08x kernel=0x%08x page=%u caps=0x%08x bp=%u/%u\n",
           client.host_type == SECDEBUG_HOST_KERNELPATCH ? "KernelPatch" : "KPatch-Next",
           cap.kpm_ver, cap.linux_ver, cap.page_size, cap.cap_flags,
           cap.active_bp_cnt, cap.max_bp_slots);

    my_pid = getpid();
    rc = secdebug_read_mem(&client, my_pid, (uint64_t)(uintptr_t)&test_val,
                           &read_buf, sizeof(read_buf), NULL);
    if (rc != (int)sizeof(read_buf) || read_buf != test_val) {
        fprintf(stderr, "Self-read failed: rc=%d value=0x%016llx\n",
                rc, (unsigned long long)read_buf);
        goto done;
    }

    printf("Self-read passed: 0x%016llx\n", (unsigned long long)read_buf);
    if (run_hwbp) {
        if (!(cap.cap_flags & SECDEBUG_CAP_HW_WATCH)) {
            fputs("HW watchpoints are unavailable in the capability probe.\n", stderr);
            goto done;
        }
        if (run_self_watchpoint(&client) != 0)
            goto done;
    }
    exit_code = 0;

done:
    (void)unsetenv("SECDEBUG_SUPERKEY");
    (void)unsetenv("SECDEBUG_AUTH_TOKEN");
    (void)unsetenv("SECDEBUG_HWBP_SMOKE");
    rc = secdebug_client_destroy(&client);
    if (rc) {
        fprintf(stderr, "Session cleanup failed: %d (retry on the opening thread)\n", rc);
        exit_code = 1;
    }
    return exit_code;
}
