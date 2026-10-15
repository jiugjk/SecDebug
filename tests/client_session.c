/* SPDX-License-Identifier: Apache-2.0 */
/* Mock safe host and verify that multi-block I/O targets one mm session,
 * carries opaque session_id, and never performs per-chunk PID lookup. */
#define getuid secdebug_test_uid
#define syscall secdebug_test_syscall
#include "../client/libsecdebug.c"
#undef syscall
#undef getuid
#include <stdarg.h>

static int g_session_open, g_session_close, g_session_read, g_session_write;
static int g_unsafe_path, g_fail_write, g_fail_read, g_write_enomem, g_bad_session, g_hello;
static uint32_t g_session_id = 0xaabb0123u;
static long g_tid = 1234;
static int g_close_failures, g_close_errno, g_close_lost_receipt, g_session_active;
static struct secdebug_client *g_client;
static int g_reenter, g_reenter_result;

static int b64_value(unsigned char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static size_t test_decode(const char *src, unsigned char *out)
{
    size_t used = 0;
    uint32_t acc = 0;
    unsigned bits = 0;
    for (; *src; src++) {
        int v = b64_value((unsigned char)*src);
        if (*src == '=') break;
        if (v < 0) return 0;
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[used++] = (unsigned char)((acc >> bits) & 255u);
        }
    }
    return used;
}

uid_t secdebug_test_uid(void) { return 0; }

long secdebug_test_syscall(long nr, ...)
{
    va_list ap;
    const char *pathname;
    uint64_t word;
    if (nr == SYS_gettid)
        return g_tid;
    va_start(ap, nr);
    pathname = va_arg(ap, const char *);
    word = (uint64_t)va_arg(ap, long);
    if (pathname != NULL) g_unsafe_path++;
    if ((word & 0xffffu) == SECDEBUG_HOST_CMD_HELLO) {
        g_hello++;
        va_end(ap);
        return SECDEBUG_HOST_KPN_HELLO_RESPONSE;
    }
    if ((word & 0xffffu) == SECDEBUG_HOST_CMD_KPM_CONTROL) {
        const char *module = va_arg(ap, const char *);
        const char *encoded = va_arg(ap, const char *);
        unsigned char *out = va_arg(ap, unsigned char *);
        long cap = va_arg(ap, long);
        unsigned char data[SECDEBUG_ARGS_MAX];
        struct secdebug_req_header *req;
        struct secdebug_resp_header *resp;
        uint32_t requested;
        (void)module;
        va_end(ap);
        if (test_decode(encoded, data) < sizeof(struct secdebug_req_header) ||
            cap < (long)sizeof(struct secdebug_resp_header))
            return -EINVAL;
        req = (struct secdebug_req_header *)data;
        resp = (struct secdebug_resp_header *)out;
        memset(out, 0, (size_t)cap);
        resp->magic = SECDEBUG_MAGIC;
        resp->proto_ver = SECDEBUG_PROTO_VER;
        resp->seq = req->seq;
        switch (req->cmd) {
        case SECDEBUG_CMD_MEM_SESSION_OPEN: {
            struct secdebug_session_open_req *q = (void *)(data + sizeof(*req));
            struct secdebug_session_open_resp *r = (void *)(out + sizeof(*resp));
            g_session_open++;
            g_session_active = 1;
            if (q->target_pid != 1234 || q->reserved != 0) return -EINVAL;
            r->session_id = g_session_id;
            resp->payload_len = sizeof(*r);
            return 0;
        }
        case SECDEBUG_CMD_MEM_SESSION_CLOSE: {
            struct secdebug_session_close_req *q = (void *)(data + sizeof(*req));
            g_session_close++;
            if (q->session_id != g_session_id) g_bad_session++;
            if (g_close_failures) {
                if (g_close_failures > 0) --g_close_failures;
                return g_close_errno;
            }
            if (!g_session_active) { resp->status = -ENOENT; return 0; }
            g_session_active = 0;
            if (g_close_lost_receipt) {
                g_close_lost_receipt = 0;
                return -EFAULT;
            }
            return 0;
        }
        case SECDEBUG_CMD_MEM_SESSION_READ: {
            struct secdebug_session_read_req *q = (void *)(data + sizeof(*req));
            if (g_reenter) {
                char byte;
                g_reenter = 0;
                g_reenter_result = secdebug_read_mem(g_client, 1234, 0x10000u,
                                                    &byte, 1, NULL);
            }
            g_session_read++;
            if (q->session_id != g_session_id) g_bad_session++;
            if (g_fail_read && g_session_read == 2)
                return -EACCES;
            requested = q->read_len;
            memset(out + sizeof(*resp), 'R', requested);
            resp->payload_len = requested;
            return 0;
        }
        case SECDEBUG_CMD_MEM_SESSION_WRITE: {
            struct secdebug_session_write_req *q = (void *)(data + sizeof(*req));
            struct secdebug_mem_write_resp *r = (void *)(out + sizeof(*resp));
            g_session_write++;
            if (q->session_id != g_session_id) g_bad_session++;
            if (g_write_enomem)
                return -ENOMEM;
            if (g_fail_write && g_session_write == 2)
                return -EFAULT; /* Simulate lost receipt after side effect. */
            r->bytes_written = q->write_len;
            resp->payload_len = sizeof(*r);
            return 0;
        }
        default:
            return -EINVAL;
        }
    }
    va_end(ap);
    return -EINVAL;
}

static int check(int ok, const char *msg)
{
    if (!ok) {
        fprintf(stderr, "client session: FAIL: %s\n", msg);
        return 0;
    }
    return 1;
}

int main(void)
{
    struct secdebug_client client;
    unsigned char buf[1200];
    size_t done = 0;
    int rc;
    memset(buf, 0, sizeof(buf));
    rc = secdebug_client_init(&client, "superkey-path-not-for-safe-mode", 0x1234u);
    if (!check(rc == 0 && client.host_type == SECDEBUG_HOST_KPATCH_NEXT,
               "did not select pathname-free hello") ||
        !check(g_unsafe_path == 0, "unsafe truncate pathname was passed") ||
        !check(g_hello == 1, "unexpected number of hello calls")) return 1;

    g_client = &client;
    g_reenter = 1;
    rc = secdebug_read_mem(&client, 1234, 0x10000u, buf, sizeof(buf), &done);
    if (!check(rc == (int)sizeof(buf) && done == sizeof(buf), "session read length mismatch") ||
        !check(g_reenter_result == -EBUSY, "reentrant call took over live session") ||
        !check(buf[0] == 'R' && buf[1199] == 'R', "session read payload corrupted") ||
        !check(g_session_open == 1 && g_session_read == 3 && g_session_close == 1,
               "read did not hold single session over three chunks")) return 1;

    g_session_read = 0;
    g_fail_read = 1;
    done = 0;
    memset(buf, 0, sizeof(buf));
    rc = secdebug_read_mem(&client, 1234, 0x10000u, buf, sizeof(buf), &done);
    if (!check(rc == -EACCES, "later read error was reported as a short success") ||
        !check(done == 512, "confirmed prefix was not reported")) return 1;
    g_fail_read = 0;

    rc = secdebug_write_mem(&client, 1234, 0x20000u, buf, sizeof(buf));
    if (!check(rc == (int)sizeof(buf), "session write length mismatch") ||
        !check(g_session_open == 3 && g_session_write == 3 && g_session_close == 3,
               "write did not hold single session") ||
        !check(g_bad_session == 0, "chunk referred to wrong mm session")) return 1;

    g_session_write = 0;
    g_write_enomem = 1;
    rc = secdebug_write_mem(&client, 1234, 0x28000u, buf, sizeof(buf));
    if (!check(rc == -ENOMEM, "definite allocation failure was folded into EINPROGRESS"))
        return 1;
    g_write_enomem = 0;

    g_session_write = 0;
    g_fail_write = 1;
    rc = secdebug_write_mem(&client, 1234, 0x30000u, buf, sizeof(buf));
    if (!check(rc == -EINPROGRESS, "lost write receipt should be indeterminate") ||
        !check(g_session_close == 5, "failed write did not close session")) return 1;

    g_fail_write = 0;
    g_close_failures = -1;
    g_close_errno = -ENOMEM;
    int before_close = g_session_close;
    rc = secdebug_read_mem(&client, 1234, 0x10000u, buf, sizeof(buf), &done);
    if (!check(rc == 1200 && done == 1200, "cleanup changed completed data result") ||
        !check(secdebug_client_cleanup_error(&client) == -ENOMEM &&
               client.pending_session_id == g_session_id, "failed CLOSE lost handle") ||
        !check(g_session_close == before_close + 3, "CLOSE retry is not bounded")) return 1;
    int before_open = g_session_open;
    rc = secdebug_read_mem(&client, 1234, 0x10000u, buf, sizeof(buf), &done);
    if (!check(rc == -ENOMEM && done == 0 && before_open == g_session_open,
               "opened another session while cleanup pending") ||
        !check(secdebug_client_destroy(&client) == -ENOMEM && client.auth_token != 0 &&
               client.pending_session_id != 0, "destroy discarded cleanup credentials")) return 1;
    g_tid = 4321;
    before_close = g_session_close;
    if (!check(secdebug_client_cleanup(&client) == -EPERM &&
               before_close == g_session_close, "wrong thread attempted CLOSE")) return 1;
    g_tid = 1234;
    g_close_failures = 0;
    if (!check(secdebug_client_cleanup(&client) == 0 &&
               client.pending_session_id == 0 && secdebug_client_cleanup_error(&client) == 0,
               "pending session not recovered")) return 1;

    g_close_failures = 1;
    g_close_errno = -EBUSY;
    before_close = g_session_close;
    rc = secdebug_read_mem(&client, 1234, 0x10000u, buf, sizeof(buf), &done);
    if (!check(rc == 1200 && g_session_close == before_close + 2 &&
               !client.pending_session_id, "temporary CLOSE busy not recovered")) return 1;
    g_close_lost_receipt = 1;
    before_close = g_session_close;
    rc = secdebug_read_mem(&client, 1234, 0x10000u, buf, sizeof(buf), &done);
    if (!check(rc == 1200 && g_session_close == before_close + 2 &&
               !client.pending_session_id, "lost CLOSE receipt not confirmed by ENOENT")) return 1;

    g_close_failures = -1;
    g_close_errno = -ENOMEM;
    int before_write = g_session_write;
    rc = secdebug_write_mem(&client, 1234, 0x10000u, buf, sizeof(buf));
    if (!check(rc == 1200 && g_session_write == before_write + 3 &&
               secdebug_client_cleanup_error(&client) == -ENOMEM,
               "write result confused with cleanup failure")) return 1;
    before_write = g_session_write;
    rc = secdebug_write_mem(&client, 1234, 0x10000u, buf, sizeof(buf));
    if (!check(rc == -ENOMEM && before_write == g_session_write,
               "data write repeated while cleanup pending")) return 1;
    g_close_failures = 0;
    if (!check(secdebug_client_destroy(&client) == 0,
               "destroy did not retry pending cleanup")) return 1;
    if (!check(client.auth_token == 0 && client.host_type == SECDEBUG_HOST_UNKNOWN,
               "client credentials were not cleared")) return 1;
    puts("client session: PASS");
    return 0;
}
