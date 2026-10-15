/* SPDX-License-Identifier: Apache-2.0 */
/* Regression tests for strict userspace protocol validation. */

/* Explicitly test the quarantined legacy mode; normal SDK builds disable it. */
#define SECDEBUG_ALLOW_LEGACY_TRUNCATE_SYSCALL 1
#define syscall secdebug_test_syscall
#include "../client/libsecdebug.c"
#undef syscall

#include <stdarg.h>

static int g_mode;
static int g_syscall_count;

enum {
    MODE_REGISTER_SHORT = 1,
    MODE_REGISTER_OVERSIZE,
    MODE_ERROR_WITH_PAYLOAD,
    MODE_PROBE_VALID,
    MODE_SYSCALL_EPERM,
    MODE_SYSCALL_ENOMEM,
};

static int test_b64_value(unsigned char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static int test_b64_decode(const char *in, unsigned char *out, size_t out_max)
{
    size_t len = strlen(in);
    size_t i = 0;
    size_t j = 0;

    if ((len & 3u) != 0)
        return -1;
    while (i < len) {
        int v[4];
        int k;
        for (k = 0; k < 4; k++) {
            unsigned char c = (unsigned char)in[i++];
            v[k] = c == '=' ? -2 : test_b64_value(c);
            if (v[k] < 0 && v[k] != -2)
                return -1;
        }
        if (j >= out_max) return -1;
        out[j++] = (unsigned char)((v[0] << 2) | (v[1] >> 4));
        if (v[2] == -2) break;
        if (j >= out_max) return -1;
        out[j++] = (unsigned char)(((v[1] & 0xf) << 4) | (v[2] >> 2));
        if (v[3] == -2) break;
        if (j >= out_max) return -1;
        out[j++] = (unsigned char)(((v[2] & 3) << 6) | v[3]);
    }
    return (int)j;
}

long secdebug_test_syscall(long number, ...)
{
    va_list ap;
    const char *key;
    uint64_t command;

    if (number == SYS_gettid)
        return 1234;
    g_syscall_count++;
    va_start(ap, number);
    key = va_arg(ap, const char *);
    command = (uint64_t)va_arg(ap, long);
    (void)key;

    if ((command & 0xffffu) == SECDEBUG_HOST_CMD_HELLO) {
        va_end(ap);
        return SECDEBUG_HOST_KP_HELLO_RESPONSE;
    }

    if ((command & 0xffffu) == SECDEBUG_HOST_CMD_KPM_CONTROL && g_mode == MODE_SYSCALL_EPERM) {
        va_end(ap);
        errno = EPERM;
        return -1;
    }
    if ((command & 0xffffu) == SECDEBUG_HOST_CMD_KPM_CONTROL && g_mode == MODE_SYSCALL_ENOMEM) {
        va_end(ap);
        errno = ENOMEM;
        return -1;
    }

    if ((command & 0xffffu) == SECDEBUG_HOST_CMD_KPM_CONTROL) {
        const char *module_name = va_arg(ap, const char *);
        const char *args = va_arg(ap, const char *);
        char *out_msg = va_arg(ap, char *);
        long outlen = va_arg(ap, long);
        unsigned char decoded[SECDEBUG_ARGS_MAX];
        struct secdebug_req_header *request;
        struct secdebug_resp_header *response;
        int decoded_len;

        (void)module_name;
        va_end(ap);
        decoded_len = test_b64_decode(args, decoded, sizeof(decoded));
        if (decoded_len < (int)sizeof(*request) || outlen < (long)sizeof(*response))
            return -1;
        request = (struct secdebug_req_header *)decoded;
        response = (struct secdebug_resp_header *)out_msg;
        memset(out_msg, 0, (size_t)outlen);
        response->magic = SECDEBUG_MAGIC;
        response->proto_ver = SECDEBUG_PROTO_VER;
        response->seq = request->seq;

        switch (g_mode) {
        case MODE_REGISTER_SHORT:
            response->status = 0;
            response->payload_len = 0;
            break;
        case MODE_REGISTER_OVERSIZE:
            response->status = 0;
            response->payload_len = 16;
            break;
        case MODE_ERROR_WITH_PAYLOAD:
            response->status = -EINVAL;
            response->payload_len = 1;
            break;
        case MODE_PROBE_VALID: {
            struct secdebug_cap_resp *cap =
                (struct secdebug_cap_resp *)(out_msg + sizeof(*response));
            response->status = 0;
            response->payload_len = sizeof(*cap);
            cap->kpm_ver = SECDEBUG_PROTO_VER;
            cap->page_size = 4096;
            cap->cap_flags = SECDEBUG_CAP_MEM_READ;
            cap->max_bp_slots = SECDEBUG_MAX_PAYLOAD / 128;
            break;
        }
        default:
            return -1;
        }
        return 0;
    }

    va_end(ap);
    return -1;
}

static int check(int condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "client protocol: FAIL: %s\n", message);
        return 0;
    }
    return 1;
}

static int check_base64_vectors(void)
{
    static const struct {
        const char *plain;
        const char *encoded;
    } vectors[] = {
        { "", "" },
        { "f", "Zg==" },
        { "fo", "Zm8=" },
        { "foo", "Zm9v" },
        { "foobar", "Zm9vYmFy" },
    };
    char out[32];
    size_t i;

    for (i = 0; i < sizeof(vectors) / sizeof(vectors[0]); i++) {
        int rc = b64_encode((const unsigned char *)vectors[i].plain,
                            (int)strlen(vectors[i].plain), out, sizeof(out));
        if (rc < 0 || strcmp(out, vectors[i].encoded) != 0)
            return check(0, "RFC 4648 Base64 vector mismatch");
    }

    if (b64_encode((const unsigned char *)"foo", 3, out, 4) != -1)
        return check(0, "Base64 encoder accepted output buffer without NUL room");
    return 1;
}

int main(void)
{
    struct secdebug_client client;
    struct secdebug_cap_resp cap;
    char long_key[129];
    uint32_t slot = 0xdeadbeefu;
    int before;
    int rc;

    if (!check_base64_vectors())
        return 1;

    memset(long_key, 'x', sizeof(long_key) - 1);
    long_key[sizeof(long_key) - 1] = '\0';
    before = g_syscall_count;
    rc = secdebug_client_init(&client, long_key, 0x123456789abcdef0ULL);
    if (!check(rc == -ENAMETOOLONG, "long key was not rejected") ||
        !check(g_syscall_count == before, "long key reached syscall"))
        return 1;

    rc = secdebug_client_init(&client, "secdebug-test-key-that-does-not-exist",
                              0x123456789abcdef0ULL);
    if (!check(rc == 0, "mock KernelPatch hello failed"))
        return 1;

    g_mode = MODE_REGISTER_SHORT;
    rc = secdebug_register_bp(&client, 123, SECDEBUG_BP_TYPE_EXEC, 0x1000, 4, &slot);
    if (!check(rc == -EINPROGRESS, "short register response incorrectly assumed safe") ||
        !check(slot == 0, "slot output not cleared on short response"))
        return 1;

    g_mode = MODE_REGISTER_OVERSIZE;
    rc = secdebug_register_bp(&client, 123, SECDEBUG_BP_TYPE_EXEC, 0x1000, 4, &slot);
    if (!check(rc == -EINPROGRESS, "oversized register response incorrectly assumed safe"))
        return 1;

    g_mode = MODE_ERROR_WITH_PAYLOAD;
    rc = secdebug_unregister_bp(&client, 0x00010001u);
    if (!check(rc == -EINPROGRESS, "error response with payload incorrectly assumed safe"))
        return 1;

    g_mode = MODE_SYSCALL_EPERM;
    slot = 0xdeadbeefu;
    rc = secdebug_register_bp(&client, 123, SECDEBUG_BP_TYPE_EXEC, 0x1000, 4, &slot);
    if (!check(rc == -EPERM, "authentication failure was reported as EINPROGRESS") ||
        !check(slot == 0, "slot output not cleared on auth failure"))
        return 1;

    g_mode = MODE_SYSCALL_ENOMEM;
    rc = secdebug_unregister_bp(&client, 0x00010001u);
    if (!check(rc == -ENOMEM, "ENOMEM was reported as EINPROGRESS"))
        return 1;

    g_mode = MODE_PROBE_VALID;
    rc = secdebug_probe(&client, &cap);
    if (!check(rc == 0, "valid probe rejected") ||
        !check(cap.page_size == 4096, "valid probe payload not copied"))
        return 1;

    puts("client protocol: PASS");
    return 0;
}
