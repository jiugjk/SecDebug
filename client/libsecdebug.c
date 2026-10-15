#define _GNU_SOURCE
/* SPDX-License-Identifier: Apache-2.0 */
/*
 * libsecdebug.c - Userspace Client SDK implementation
 */

#include "libsecdebug.h"
#include "secdebug_host_abi.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <errno.h>
#include <limits.h>

/* Legacy KernelPatch's syscall 45 falls through to truncate(2) if the host
 * vanishes. No pathname pre-check can close that TOCTOU. Opt-in only. */
#ifndef SECDEBUG_ALLOW_LEGACY_TRUNCATE_SYSCALL
#define SECDEBUG_ALLOW_LEGACY_TRUNCATE_SYSCALL 0
#endif

static void secure_zero(void *ptr, size_t n)
{
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (n--) *p++ = 0;
}

int secdebug_client_destroy(struct secdebug_client *client)
{
    int rc = secdebug_client_cleanup(client);
    if (rc)
        return rc;
    secure_zero(client, sizeof(*client));
    return 0;
}

/*
 * receipt_ambiguous is true only when the kernel may already have committed
 * a side effect before the response copy. Auth, protocol, busy and allocation
 * failures happen before that and keep their errno. -EFAULT on an ambiguous
 * command means the receipt was lost.
 */

static const char base64_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* RFC 4648 encoder, implemented as independent 3-byte / 4-character blocks. */
static int b64_encode(const unsigned char *in, int in_len, char *out, int out_max)
{
    int in_pos = 0;
    int out_pos = 0;
    int encoded_len;

    if (!out || in_len < 0 || out_max <= 0 || (in_len > 0 && !in))
        return -1;
    if (in_len > (INT_MAX - 2) / 3)
        return -1;

    encoded_len = ((in_len + 2) / 3) * 4;
    if (encoded_len >= out_max)
        return -1;

    while (in_pos + 3 <= in_len) {
        uint32_t block = ((uint32_t)in[in_pos] << 16) |
                         ((uint32_t)in[in_pos + 1] << 8) |
                         (uint32_t)in[in_pos + 2];

        out[out_pos++] = base64_chars[(block >> 18) & 0x3fu];
        out[out_pos++] = base64_chars[(block >> 12) & 0x3fu];
        out[out_pos++] = base64_chars[(block >> 6) & 0x3fu];
        out[out_pos++] = base64_chars[block & 0x3fu];
        in_pos += 3;
    }

    if (in_pos < in_len) {
        uint32_t block = (uint32_t)in[in_pos] << 16;
        int remaining = in_len - in_pos;

        if (remaining == 2)
            block |= (uint32_t)in[in_pos + 1] << 8;

        out[out_pos++] = base64_chars[(block >> 18) & 0x3fu];
        out[out_pos++] = base64_chars[(block >> 12) & 0x3fu];
        if (remaining == 2) {
            out[out_pos++] = base64_chars[(block >> 6) & 0x3fu];
            out[out_pos++] = '=';
        } else {
            out[out_pos++] = '=';
            out[out_pos++] = '=';
        }
    }

    out[out_pos] = '\0';
    return out_pos;
}

/* libc turns kernel errnos into -1. */
static int secdebug_syscall_err(long rc)
{
    if (rc == -1)
        return -errno;
    if (rc < 0)
        return (int)rc;
    return -EIO;
}

/*
 * Syscall 45 is truncate when the host does not claim the call. Refuse a key
 * that already names a filesystem object so a failed hello cannot change it.
 */
#if SECDEBUG_ALLOW_LEGACY_TRUNCATE_SYSCALL
static int secdebug_key_names_file(const char *key)
{
    struct stat st;

    if (!key || !key[0])
        return 0;
    if (stat(key, &st) == 0)
        return 1;
    return 0;
}
#endif

static long sc_kpm_control_dispatch(struct secdebug_client *client, const char *args, char *out_msg, long outlen)
{
    if (!client || !args || !out_msg || outlen <= 0)
        return -EINVAL;

    if (client->host_type == SECDEBUG_HOST_KERNELPATCH) {
#if !SECDEBUG_ALLOW_LEGACY_TRUNCATE_SYSCALL
        return -EOPNOTSUPP;
#else
        /* Unsafe opt-in: pathname stat cannot remove kernel/FS TOCTOU. */
        if (secdebug_key_names_file(client->superkey))
            return -EEXIST;
        /*
         * KernelPatch:
         * syscall(SECDEBUG_HOST_SYSCALL_NR, key, ver_and_cmd, name, args, out_msg, outlen)
         */
        return syscall(SECDEBUG_HOST_SYSCALL_NR, client->superkey,
                       (long)secdebug_host_command_word(SECDEBUG_HOST_KP_ABI_VERSION, SECDEBUG_HOST_KP_FAMILY_TAG, SECDEBUG_HOST_CMD_KPM_CONTROL),
                       client->module_name, args, out_msg, outlen);
#endif
    } else if (client->host_type == SECDEBUG_HOST_KPATCH_NEXT) {
        /*
         * KPatch-Next:
         * syscall(SECDEBUG_HOST_SYSCALL_NR, NULL, compact_cmd, name, args, out_msg, outlen)
         * Middle magic 0x2026, version 0.13.5. The host version check is
         * still commented out; send the real code anyway.
         */
        return syscall(SECDEBUG_HOST_SYSCALL_NR, NULL,
                       (long)secdebug_host_command_word(SECDEBUG_HOST_KPN_ABI_VERSION, SECDEBUG_HOST_KPN_FAMILY_TAG, SECDEBUG_HOST_CMD_KPM_CONTROL),
                       client->module_name, args, out_msg, outlen);
    }
    return -ENODEV;
}

int secdebug_client_init(struct secdebug_client *client, const char *superkey, uint64_t auth_token)
{
    size_t key_len = 0;

    if (!client)
        return -EINVAL;
    memset(client, 0, sizeof(*client));
    if (auth_token == 0)
        return -EINVAL;
    if (superkey && superkey[0]) {
        key_len = strlen(superkey);
        if (key_len >= sizeof(client->superkey))
            return -ENAMETOOLONG;
    }
    memcpy(client->module_name, SECDEBUG_MOD_NAME, sizeof(SECDEBUG_MOD_NAME));
    client->auth_token = auth_token;
    client->seq = 1;

#if SECDEBUG_ALLOW_LEGACY_TRUNCATE_SYSCALL
    if (key_len) {
        long ret;
        if (secdebug_key_names_file(superkey)) {
            secdebug_client_destroy(client);
            return -EEXIST;
        }
        memcpy(client->superkey, superkey, key_len + 1);
        ret = syscall(SECDEBUG_HOST_SYSCALL_NR, client->superkey,
                      (long)secdebug_host_command_word(SECDEBUG_HOST_KP_ABI_VERSION,
                            SECDEBUG_HOST_KP_FAMILY_TAG, SECDEBUG_HOST_CMD_HELLO));
        if (ret == SECDEBUG_HOST_KP_HELLO_RESPONSE) {
            client->host_type = SECDEBUG_HOST_KERNELPATCH;
            return 0;
        }
    }
#else
    (void)key_len;
#endif

    /* Default safe path: KPatch-Next passes a NULL pathname. With no loader,
     * syscall 45 then fails EFAULT rather than truncating a filesystem object. */
    if (getuid() == 0) {
        long ret = syscall(SECDEBUG_HOST_SYSCALL_NR, NULL,
                           (long)secdebug_host_command_word(SECDEBUG_HOST_KPN_ABI_VERSION,
                              SECDEBUG_HOST_KPN_FAMILY_TAG, SECDEBUG_HOST_CMD_HELLO));
        if (ret == SECDEBUG_HOST_KPN_HELLO_RESPONSE) {
            client->host_type = SECDEBUG_HOST_KPATCH_NEXT;
            secure_zero(client->superkey, sizeof(client->superkey));
            return 0;
        }
    }

    secdebug_client_destroy(client);
    return -ENODEV;
}

/* A lost response copy, or a corrupt header, on an ambiguous command is
 * indeterminate. Every other transport errno is returned unchanged. */
static int secdebug_execute_cmd(struct secdebug_client *client, uint32_t cmd,
                               const void *req_payload, uint32_t req_len,
                               void *resp_payload, uint32_t *resp_len, uint32_t max_resp,
                               int receipt_ambiguous)
{
    unsigned char raw_req[SECDEBUG_ARGS_MAX];
    char b64_req[SECDEBUG_ARGS_MAX * 2];
    unsigned char raw_resp[SECDEBUG_RESP_MAX];
    struct secdebug_req_header *req_hdr = (struct secdebug_req_header *)raw_req;
    struct secdebug_resp_header *resp_hdr = (struct secdebug_resp_header *)raw_resp;
    uint32_t seq;
    int raw_req_len;
    int result = 0;
    long rc;

    (void)cmd;
    if (!client || client->host_type == SECDEBUG_HOST_UNKNOWN)
        return -ENODEV;
    if (req_len > 0 && !req_payload)
        return -EINVAL;
    if ((resp_payload == NULL) != (resp_len == NULL))
        return -EINVAL;
    if (!resp_payload && max_resp != 0)
        return -EINVAL;
    if (resp_len)
        *resp_len = 0;

    if (sizeof(struct secdebug_req_header) + (uint64_t)req_len > sizeof(raw_req))
        return -E2BIG;
#if !SECDEBUG_ALLOW_LEGACY_TRUNCATE_SYSCALL
    if (client->host_type == SECDEBUG_HOST_KERNELPATCH)
        return -EOPNOTSUPP;
#endif

    seq = __atomic_fetch_add(&client->seq, 1u, __ATOMIC_RELAXED);
    if (!seq)
        seq = __atomic_fetch_add(&client->seq, 1u, __ATOMIC_RELAXED);
    req_hdr->magic = SECDEBUG_MAGIC;
    req_hdr->proto_ver = SECDEBUG_PROTO_VER;
    req_hdr->cmd = cmd;
    req_hdr->seq = seq;
    req_hdr->payload_len = req_len;
    req_hdr->auth_token = client->auth_token;

    if (req_len)
        memcpy(raw_req + sizeof(struct secdebug_req_header), req_payload, req_len);

    raw_req_len = (int)sizeof(struct secdebug_req_header) + (int)req_len;
    if (b64_encode(raw_req, raw_req_len, b64_req, sizeof(b64_req)) <= 0) {
        result = -EINVAL;
        goto scrub;
    }

    memset(raw_resp, 0, sizeof(raw_resp));
    rc = sc_kpm_control_dispatch(client, b64_req, (char *)raw_resp, sizeof(raw_resp));
    if (rc != 0) {
        int err = secdebug_syscall_err(rc);

        result = (receipt_ambiguous && err == -EFAULT) ? -EINPROGRESS : err;
        goto scrub;
    }
    if (resp_hdr->magic != SECDEBUG_MAGIC || resp_hdr->proto_ver != SECDEBUG_PROTO_VER ||
        resp_hdr->seq != seq || resp_hdr->status > 0 || resp_hdr->status < -4095 ||
        resp_hdr->payload_len > sizeof(raw_resp) - sizeof(struct secdebug_resp_header) ||
        (resp_hdr->status != 0 && resp_hdr->payload_len != 0)) {
        result = receipt_ambiguous ? -EINPROGRESS : -EPROTO;
        goto scrub;
    }
    if (resp_hdr->status != 0) {
        result = resp_hdr->status; /* Valid response from module: definite failure. */
        goto scrub;
    }
    if (resp_hdr->payload_len > max_resp ||
        (resp_hdr->payload_len && (!resp_payload || !resp_len))) {
        result = receipt_ambiguous ? -EINPROGRESS : -EMSGSIZE;
        goto scrub;
    }
    if (resp_hdr->payload_len)
        memcpy(resp_payload, raw_resp + sizeof(struct secdebug_resp_header), resp_hdr->payload_len);
    if (resp_len)
        *resp_len = resp_hdr->payload_len;

scrub:
    secure_zero(raw_req, sizeof(raw_req));
    secure_zero(b64_req, sizeof(b64_req));
    secure_zero(raw_resp, sizeof(raw_resp));
    return result;
}

int secdebug_probe(struct secdebug_client *client, struct secdebug_cap_resp *cap)
{
    uint32_t resp_len = 0;
    int ret;

    if (!client || !cap)
        return -EINVAL;
    memset(cap, 0, sizeof(*cap));
    ret = secdebug_execute_cmd(client, SECDEBUG_CMD_PROBE_CAP, NULL, 0,
                               cap, &resp_len, sizeof(*cap), 0);
    if (ret)
        return ret;
    if (resp_len != sizeof(*cap)) {
        memset(cap, 0, sizeof(*cap));
        return -EPROTO;
    }
    return 0;
}

/* Multi-block transfers MUST pin mm with the session protocol. Legacy
 * one-block commands remain available and wire-compatible with v1.0. */
static int secdebug_open_mem_session(struct secdebug_client *client, int target_pid,
                                      uint32_t *session_id)
{
    struct secdebug_session_open_req req = { target_pid, 0 };
    struct secdebug_session_open_resp resp = { 0, 0 };
    uint32_t out_len = 0;
    int rc = secdebug_execute_cmd(client, SECDEBUG_CMD_MEM_SESSION_OPEN,
                                  &req, sizeof(req), &resp, &out_len, sizeof(resp), 1);
    if (rc)
        return rc;
    if (out_len != sizeof(resp) || resp.session_id == 0)
        return -EINPROGRESS; /* Might have opened: caller cannot safely retry. */
    *session_id = resp.session_id;
    return 0;
}

static int secdebug_close_mem_session(struct secdebug_client *client, uint32_t session_id)
{
    struct secdebug_session_close_req req = { session_id, 0 };
    return secdebug_execute_cmd(client, SECDEBUG_CMD_MEM_SESSION_CLOSE,
                                &req, sizeof(req), NULL, NULL, 0, 1);
}

static int secdebug_memory_lock(struct secdebug_client *client)
{
    uint32_t expected = 0;
    if (!client)
        return -EINVAL;
    return __atomic_compare_exchange_n(&client->mem_busy, &expected, 1, 0,
                                        __ATOMIC_ACQUIRE, __ATOMIC_RELAXED) ? 0 : -EBUSY;
}

static void secdebug_memory_unlock(struct secdebug_client *client)
{
    __atomic_store_n(&client->mem_busy, 0, __ATOMIC_RELEASE);
}

/* mem_busy protects the handle and its owner across open/data/close. */
static int secdebug_cleanup_locked(struct secdebug_client *client)
{
    int rc = 0;
    int attempt;

    if (!client->pending_session_id)
        goto done;
    if ((int64_t)syscall(SYS_gettid) != client->pending_session_owner_tid) {
        rc = -EPERM;
        goto done;
    }
    for (attempt = 0; attempt < 3; ++attempt) {
        rc = secdebug_close_mem_session(client, client->pending_session_id);
        /* CLOSE is idempotent by handle. A lost receipt can be retried;
         * ENOENT confirms the prior CLOSE (or owner reaping) completed. */
        if (rc == 0 || rc == -ENOENT) {
            client->pending_session_id = 0;
            client->pending_session_owner_tid = 0;
            rc = 0;
            break;
        }
        if (rc != -ENOMEM && rc != -EBUSY && rc != -EINPROGRESS)
            break;
    }
done:
    __atomic_store_n(&client->cleanup_error, rc, __ATOMIC_RELEASE);
    return rc;
}

int secdebug_client_cleanup(struct secdebug_client *client)
{
    int rc = secdebug_memory_lock(client);
    if (rc)
        return rc;
    rc = secdebug_cleanup_locked(client);
    secdebug_memory_unlock(client);
    return rc;
}

int secdebug_client_cleanup_error(const struct secdebug_client *client)
{
    return client ? __atomic_load_n(&client->cleanup_error, __ATOMIC_ACQUIRE) : -EINVAL;
}

static int secdebug_begin_transfer(struct secdebug_client *client)
{
    int rc = secdebug_memory_lock(client);
    if (rc)
        return rc;
    rc = secdebug_cleanup_locked(client);
    if (rc)
        secdebug_memory_unlock(client);
    return rc;
}

static int secdebug_open_tracked_session(struct secdebug_client *client, int target_pid,
                                         uint32_t *session_id)
{
    long tid = syscall(SYS_gettid);
    int rc;
    if (tid <= 0)
        return tid == -1 ? -errno : -EIO;
    rc = secdebug_open_mem_session(client, target_pid, session_id);
    if (!rc) {
        client->pending_session_id = *session_id;
        client->pending_session_owner_tid = (int64_t)tid;
    }
    return rc;
}

int secdebug_read_mem(struct secdebug_client *client, int target_pid, uint64_t addr, void *buf, size_t len,
                       size_t *bytes_done)
{
    size_t total = 0;
    uint32_t session_id = 0;
    int error = 0;

    if (bytes_done)
        *bytes_done = 0;

    if (!client || target_pid <= 0 || (len > 0 && !buf))
        return -EINVAL;
    if (len > (size_t)INT_MAX || len > UINT64_MAX - addr)
        return -EOVERFLOW;
    if (!len)
        return 0;
    error = secdebug_begin_transfer(client);
    if (error)
        return error;
    if (len > SECDEBUG_MAX_PAYLOAD) {
        error = secdebug_open_tracked_session(client, target_pid, &session_id);
        if (error)
            goto finish;
    }

    while (total < len) {
        size_t chunk = len - total;
        uint32_t out_len = 0;
        int rc;

        if (chunk > SECDEBUG_MAX_PAYLOAD)
            chunk = SECDEBUG_MAX_PAYLOAD;
        if (session_id) {
            struct secdebug_session_read_req req = { session_id, (uint32_t)chunk,
                                                     addr + total };
            rc = secdebug_execute_cmd(client, SECDEBUG_CMD_MEM_SESSION_READ,
                                       &req, sizeof(req), (char *)buf + total,
                                       &out_len, (uint32_t)chunk, 0);
        } else {
            struct secdebug_mem_read_req req = { target_pid, (uint32_t)chunk,
                                                 addr + total };
            rc = secdebug_execute_cmd(client, SECDEBUG_CMD_MEM_READ,
                                       &req, sizeof(req), (char *)buf + total,
                                       &out_len, (uint32_t)chunk, 0);
        }
        if (rc) {
            error = rc;
            break;
        }
        if (!out_len || out_len > chunk) {
            error = -EPROTO;
            break;
        }
        total += out_len;
        if (out_len < chunk)
            break;
    }
finish:
    /* Keep data and cleanup outcomes separate; retain any unclosed handle. */
    (void)secdebug_cleanup_locked(client);
    secdebug_memory_unlock(client);
    if (bytes_done)
        *bytes_done = total;
    /* A later chunk error must not look like a clean short read. */
    if (error)
        return error;
    return (int)total;
}

int secdebug_write_mem(struct secdebug_client *client, int target_pid, uint64_t addr,
                       const void *buf, size_t len)
{
    size_t total = 0;
    uint32_t session_id = 0;
    unsigned char chunk_buf[sizeof(struct secdebug_session_write_req) + SECDEBUG_MAX_PAYLOAD];
    int error = 0;

    if (!client || target_pid <= 0 || (len > 0 && !buf))
        return -EINVAL;
    if (len > (size_t)INT_MAX || len > UINT64_MAX - addr)
        return -EOVERFLOW;
    if (!len)
        return 0;
    error = secdebug_begin_transfer(client);
    if (error)
        return error;
    if (len > SECDEBUG_MAX_PAYLOAD) {
        error = secdebug_open_tracked_session(client, target_pid, &session_id);
        if (error)
            goto finish;
    }

    while (total < len) {
        size_t chunk = len - total;
        struct secdebug_mem_write_resp wresp = { 0, 0 };
        uint32_t out_len = 0;
        uint32_t cmd;
        int rc;

        if (chunk > SECDEBUG_MAX_PAYLOAD)
            chunk = SECDEBUG_MAX_PAYLOAD;
        if (session_id) {
            struct secdebug_session_write_req *req =
                (struct secdebug_session_write_req *)chunk_buf;
            req->session_id = session_id;
            req->write_len = (uint32_t)chunk;
            req->target_addr = addr + total;
            cmd = SECDEBUG_CMD_MEM_SESSION_WRITE;
        } else {
            struct secdebug_mem_write_req *req =
                (struct secdebug_mem_write_req *)chunk_buf;
            req->target_pid = target_pid;
            req->write_len = (uint32_t)chunk;
            req->target_addr = addr + total;
            cmd = SECDEBUG_CMD_MEM_WRITE;
        }
        memcpy(chunk_buf + sizeof(struct secdebug_session_write_req),
               (const char *)buf + total, chunk);
        rc = secdebug_execute_cmd(client, cmd, chunk_buf,
                                  (uint32_t)(sizeof(struct secdebug_session_write_req) + chunk),
                                  &wresp, &out_len, sizeof(wresp), 1);
        if (rc) {
            error = rc;
            break;
        }
        if (out_len != sizeof(wresp) || wresp.bytes_written == 0 ||
            wresp.bytes_written > chunk) {
            error = -EINPROGRESS; /* Treat malformed write receipt as ambiguous. */
            break;
        }
        total += wresp.bytes_written;
        if (wresp.bytes_written < chunk)
            break;
    }
finish:
    secure_zero(chunk_buf, sizeof(chunk_buf));
    (void)secdebug_cleanup_locked(client);
    secdebug_memory_unlock(client);
    /* If a write receipt was lost, even the last chunk's outcome is unknown.
     * Do not return a reassuring byte count for only the previous chunks. */
    if (error == -EINPROGRESS)
        return error;
    return total ? (int)total : error;
}

int secdebug_register_bp(struct secdebug_client *client, int target_tid, uint32_t bp_type,
                         uint64_t addr, uint32_t bp_len, uint32_t *slot_id)
{
    struct secdebug_bp_reg_req req;
    struct secdebug_bp_reg_resp resp;
    uint32_t out_len = 0;
    int ret;

    if (!client || !slot_id || target_tid <= 0)
        return -EINVAL;
    *slot_id = 0;
    memset(&resp, 0, sizeof(resp));
    req.target_tid = target_tid;
    req.bp_type = bp_type;
    req.target_addr = addr;
    req.bp_len = bp_len;
    req.reserved = 0;

    ret = secdebug_execute_cmd(client, SECDEBUG_CMD_HW_BP_REGISTER, &req, sizeof(req),
                               &resp, &out_len, sizeof(resp), 1);
    if (ret)
        return ret;
    if (out_len != sizeof(resp) || resp.slot_id == 0)
        return -EINPROGRESS; /* BP may be registered but receipt is lost. */
    *slot_id = resp.slot_id;
    return 0;
}

int secdebug_unregister_bp(struct secdebug_client *client, uint32_t slot_id)
{
    struct secdebug_bp_unreg_req req;

    if (!client || slot_id == 0)
        return -EINVAL;
    req.slot_id = slot_id;
    req.reserved = 0;
    return secdebug_execute_cmd(client, SECDEBUG_CMD_HW_BP_UNREGISTER,
                                &req, sizeof(req), NULL, NULL, 0, 1);
}

int secdebug_get_hit(struct secdebug_client *client, uint32_t slot_id, bool clear_hit,
                     struct secdebug_bp_hit_resp *resp)
{
    struct secdebug_bp_hit_req req;
    uint32_t out_len = 0;
    int ret;

    if (!client || !resp || slot_id == 0)
        return -EINVAL;
    memset(resp, 0, sizeof(*resp));
    req.slot_id = slot_id;
    req.clear_hit = clear_hit ? 1 : 0;

    ret = secdebug_execute_cmd(client, SECDEBUG_CMD_HW_BP_GET_HIT, &req, sizeof(req),
                               resp, &out_len, sizeof(*resp), clear_hit ? 1 : 0);
    if (ret)
        return ret;
    if (out_len != sizeof(*resp) || resp->slot_id != slot_id) {
        memset(resp, 0, sizeof(*resp));
        return clear_hit ? -EINPROGRESS : -EPROTO;
    }
    return 0;
}
