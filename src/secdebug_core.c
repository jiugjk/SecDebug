/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * secdebug_core.c - Main module lifecycle, symbol resolver & control dispatcher
 */

#include "secdebug_internal.h"

KPM_NAME(SECDEBUG_MOD_NAME);
KPM_VERSION(SECDEBUG_MOD_VER);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("secdebug contributors");
KPM_DESCRIPTION("Kernel-level security debug and memory introspection module");

struct secdebug_syms g_syms = { 0 };
uint32_t g_page_size = 0;
uint32_t g_cap_flags = 0;
uint64_t g_auth_token = 0;

/* One atomic word makes admission and closing mutually exclusive. The host
 * reference is still essential: this word cannot protect entry/return text. */
#define SECDEBUG_CALLS_CLOSED (1u << 31)
static unsigned int g_call_state;
static int g_initialized;

static unsigned long lookup_sym(const char *name)
{
    return kallsyms_lookup_name(name);
}

static int b64_value(unsigned char c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if (c >= '0' && c <= '9')
        return c - '0' + 52;
    if (c == '+')
        return 62;
    if (c == '/')
        return 63;
    return -1;
}

/* Strict RFC 4648 decoder: padding is accepted only in the final quartet. */
static int b64_decode(const char *in, int in_len, unsigned char *out, int out_max)
{
    int in_pos;
    int out_pos = 0;

    if (!in || !out || in_len < 0 || out_max < 0 || (in_len & 3) != 0)
        return -1;

    for (in_pos = 0; in_pos < in_len; in_pos += 4) {
        unsigned char c0 = (unsigned char)in[in_pos];
        unsigned char c1 = (unsigned char)in[in_pos + 1];
        unsigned char c2 = (unsigned char)in[in_pos + 2];
        unsigned char c3 = (unsigned char)in[in_pos + 3];
        int v0 = b64_value(c0);
        int v1 = b64_value(c1);
        int v2 = (c2 == '=') ? 0 : b64_value(c2);
        int v3 = (c3 == '=') ? 0 : b64_value(c3);
        int pad2 = (c2 == '=');
        int pad3 = (c3 == '=');
        int final_quartet = (in_pos + 4 == in_len);
        int emit = pad2 ? 1 : (pad3 ? 2 : 3);
        uint32_t block;

        if (v0 < 0 || v1 < 0 || v2 < 0 || v3 < 0)
            return -1;
        if (pad2 && !pad3)
            return -1;
        if ((pad2 || pad3) && !final_quartet)
            return -1;
        if (pad2 && (v1 & 0x0f) != 0)
            return -1;
        if (pad3 && !pad2 && (v2 & 0x03) != 0)
            return -1;
        if (emit > out_max - out_pos)
            return -1;

        block = ((uint32_t)v0 << 18) | ((uint32_t)v1 << 12) |
                ((uint32_t)v2 << 6) | (uint32_t)v3;
        out[out_pos++] = (unsigned char)(block >> 16);
        if (emit >= 2)
            out[out_pos++] = (unsigned char)(block >> 8);
        if (emit == 3)
            out[out_pos++] = (unsigned char)block;
    }

    return out_pos;
}

static int bounded_len(const char *s, int max)
{
    int i;

    if (!s)
        return -1;
    for (i = 0; i < max; i++) {
        if (s[i] == '\0')
            return i;
    }
    return -1;
}

static int parse_auth_token(const char *args, uint64_t *out)
{
    uint64_t token = 0;
    int i;

    if (!args)
        return -EINVAL;
    for (i = 0; i < 16; i++) {
        char c = args[i];
        int v;

        if (c >= '0' && c <= '9')
            v = c - '0';
        else if (c >= 'a' && c <= 'f')
            v = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F')
            v = c - 'A' + 10;
        else
            return -EINVAL;
        token = (token << 4) | (uint64_t)v;
    }
    if (args[16] != '\0' || token == 0)
        return -EINVAL;
    *out = token;
    return 0;
}

/* PAGE_SHIFT is normally a build-time constant, NOT a kallsyms variable.
 * Only report a value supplied by a target-specific, verified build. */
static void read_page_size(void)
{
#if defined(SECDEBUG_TARGET_PAGE_SHIFT)
#if SECDEBUG_TARGET_PAGE_SHIFT != 12 && SECDEBUG_TARGET_PAGE_SHIFT != 14 && SECDEBUG_TARGET_PAGE_SHIFT != 16
#error "Unsupported SECDEBUG_TARGET_PAGE_SHIFT (expected 12, 14 or 16)"
#endif
    g_page_size = 1u << SECDEBUG_TARGET_PAGE_SHIFT;
#else
    g_page_size = 0; /* unknown: do not falsely report 4 KiB */
#endif
}

int secdebug_resolve_symbols(void)
{
    g_syms.access_process_vm = (fn_access_process_vm)lookup_sym("access_process_vm");
    g_syms.access_remote_vm = (fn_access_remote_vm)lookup_sym("access_remote_vm");
    g_syms.find_task_by_vpid = (fn_find_task_by_vpid)lookup_sym("find_task_by_vpid");
    g_syms.find_get_task_by_vpid = (fn_find_get_task_by_vpid)lookup_sym("find_get_task_by_vpid");
    g_syms.find_vpid = (fn_find_vpid)lookup_sym("find_vpid");
    g_syms.pid_task = (fn_pid_task)lookup_sym("pid_task");
    g_syms.get_task_struct = (fn_get_task_struct)lookup_sym("get_task_struct");
    g_syms.put_task_struct = (fn_put_task_struct)lookup_sym("put_task_struct");
    g_syms.get_task_mm = (fn_get_task_mm)lookup_sym("get_task_mm");
    g_syms.mmput = (fn_mmput)lookup_sym("mmput");
    g_syms.task_pid_nr_ns = (fn_task_pid_nr_ns)lookup_sym("__task_pid_nr_ns");
    g_syms.rcu_read_lock = (fn_rcu_read_lock)lookup_sym("__rcu_read_lock");
    g_syms.rcu_read_unlock = (fn_rcu_read_unlock)lookup_sym("__rcu_read_unlock");

    g_syms.perf_event_create_kernel_counter =
        (fn_perf_event_create_kernel_counter)lookup_sym("perf_event_create_kernel_counter");
    g_syms.perf_event_release_kernel =
        (fn_perf_event_release_kernel)lookup_sym("perf_event_release_kernel");
    g_syms.perf_event_enable =
        (fn_perf_event_enable)lookup_sym("perf_event_enable");
    g_syms.perf_event_disable =
        (fn_perf_event_disable)lookup_sym("perf_event_disable");
    g_syms.perf_event_disable_inatomic =
        (fn_perf_event_disable_inatomic)lookup_sym("perf_event_disable_inatomic");
    secdebug_bind_runtime();

    if (!g_syms.rcu_read_lock || !g_syms.rcu_read_unlock)
        return -EOPNOTSUPP; /* control0 assumes exactly one host RCU nest */

    read_page_size();
    secdebug_task_init();

    g_cap_flags = 0;
    if (secdebug_mem_ops_ready())
        g_cap_flags |= SECDEBUG_CAP_MEM_READ | SECDEBUG_CAP_MEM_WRITE;
    if (secdebug_session_ready())
        g_cap_flags |= SECDEBUG_CAP_MEM_SESSION;
    /*
     * Symbol resolution is not a hit test. init_pid_ns is required so reap
     * does not use the caller's pid namespace. These are dependency flags,
     * NOT proof that a hardware breakpoint can be armed or hit on this PMU.
     */
    if (g_syms.perf_event_create_kernel_counter && g_syms.perf_event_release_kernel &&
        g_syms.perf_event_enable && g_syms.perf_event_disable &&
        g_syms.perf_event_disable_inatomic &&
        secdebug_task_ops_ready() && secdebug_caller_id_ready() &&
        g_init_pid_ns && secdebug_alloc_ready())
        g_cap_flags |= SECDEBUG_CAP_HW_BREAK | SECDEBUG_CAP_HW_WATCH;

    if (!(g_cap_flags & SECDEBUG_CAP_MEM_READ))
        printk("secdebug: memory operations disabled\n");
    if (!(g_cap_flags & SECDEBUG_CAP_HW_BREAK))
        printk("secdebug: breakpoint operations disabled\n");
    return 0;
}

static int secdebug_begin_call(void)
{
    unsigned int state = __atomic_load_n(&g_call_state, __ATOMIC_ACQUIRE);

    for (;;) {
        if ((state & SECDEBUG_CALLS_CLOSED) || state == SECDEBUG_CALLS_CLOSED - 1u)
            return 0;
        if (__atomic_compare_exchange_n(&g_call_state, &state, state + 1u, 0,
                                         __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            return 1;
    }
}

static void secdebug_end_call(void)
{
    __atomic_fetch_sub(&g_call_state, 1u, __ATOMIC_RELEASE);
}

static void wipe_load_token(const char *args);

static long secdebug_init(const char *args, const char *event, void *reserved)
{
    uint64_t token = 0;

    (void)event;
    (void)reserved;

    if (secdebug_host_contract_v1() != SECDEBUG_HOST_CONTRACT_V1)
        return -EOPNOTSUPP;
    __atomic_store_n(&g_call_state, 0u, __ATOMIC_RELEASE);
    secdebug_hwbp_init();
    secdebug_session_init();
    if (parse_auth_token(args, &token)) {
        printk("secdebug: load argument must be exactly 16 hex digits and not zero\n");
        return -EINVAL;
    }
    g_auth_token = token;
    /* Drop the host-visible copy as soon as the private token is stored. */
    wipe_load_token(args);
    {
        int rc = secdebug_resolve_symbols();
        if (rc) {
            g_auth_token = 0;
            return rc;
        }
    }
    if (!secdebug_alloc_ready()) {
        g_auth_token = 0;
        printk("secdebug: vmalloc/kvfree unavailable\n");
        return -EOPNOTSUPP;
    }
    g_initialized = 1;
    return 0;
}

/* Full-width XOR. The loop count does not depend on which bytes differ. */
static int auth_token_matches(uint64_t presented)
{
    uint64_t diff = presented ^ g_auth_token;
    uint32_t acc = 0;
    int i;

    for (i = 0; i < 8; i++)
        acc |= (uint32_t)((diff >> (i * 8)) & 0xffu);
    return acc == 0;
}

/* args is the writable host copy of the load token (mod->args). */
static void wipe_load_token(const char *args)
{
    volatile char *p;
    int i;

    if (!args)
        return;
    p = (volatile char *)args;
    for (i = 0; i < 16; i++)
        p[i] = 0;
}

static int secdebug_preflight_request(const struct secdebug_req_header *req_hdr,
                                      const void *req_payload, int outlen)
{
    uint32_t resp_payload_len = 0;

    if (!req_hdr || outlen < (int)sizeof(struct secdebug_resp_header))
        return -E2BIG;

    switch (req_hdr->cmd) {
    case SECDEBUG_CMD_PROBE_CAP:
        if (req_hdr->payload_len != 0)
            return -EINVAL;
        resp_payload_len = sizeof(struct secdebug_cap_resp);
        break;

    case SECDEBUG_CMD_MEM_READ: {
        const struct secdebug_mem_read_req *req;

        if (req_hdr->payload_len != sizeof(struct secdebug_mem_read_req))
            return -EINVAL;
        req = (const struct secdebug_mem_read_req *)req_payload;
        if (req->read_len == 0 || req->read_len > SECDEBUG_MAX_PAYLOAD)
            return -EINVAL;
        resp_payload_len = req->read_len;
        break;
    }

    case SECDEBUG_CMD_MEM_WRITE: {
        const struct secdebug_mem_write_req *req;

        if (req_hdr->payload_len < sizeof(struct secdebug_mem_write_req))
            return -EINVAL;
        req = (const struct secdebug_mem_write_req *)req_payload;
        if (req->write_len == 0 || req->write_len > SECDEBUG_MAX_PAYLOAD)
            return -EINVAL;
        if ((uint64_t)req_hdr->payload_len !=
            sizeof(struct secdebug_mem_write_req) + (uint64_t)req->write_len)
            return -EINVAL;
        resp_payload_len = sizeof(struct secdebug_mem_write_resp);
        break;
    }

    case SECDEBUG_CMD_MEM_SESSION_OPEN:
        if (req_hdr->payload_len != sizeof(struct secdebug_session_open_req))
            return -EINVAL;
        resp_payload_len = sizeof(struct secdebug_session_open_resp);
        break;

    case SECDEBUG_CMD_MEM_SESSION_READ: {
        const struct secdebug_session_read_req *req;
        if (req_hdr->payload_len != sizeof(struct secdebug_session_read_req))
            return -EINVAL;
        req = (const struct secdebug_session_read_req *)req_payload;
        if (req->read_len == 0 || req->read_len > SECDEBUG_MAX_PAYLOAD)
            return -EINVAL;
        resp_payload_len = req->read_len;
        break;
    }

    case SECDEBUG_CMD_MEM_SESSION_WRITE: {
        const struct secdebug_session_write_req *req;
        if (req_hdr->payload_len < sizeof(struct secdebug_session_write_req))
            return -EINVAL;
        req = (const struct secdebug_session_write_req *)req_payload;
        if (req->write_len == 0 || req->write_len > SECDEBUG_MAX_PAYLOAD ||
            (uint64_t)req_hdr->payload_len !=
                sizeof(struct secdebug_session_write_req) + (uint64_t)req->write_len)
            return -EINVAL;
        resp_payload_len = sizeof(struct secdebug_mem_write_resp);
        break;
    }

    case SECDEBUG_CMD_MEM_SESSION_CLOSE:
        if (req_hdr->payload_len != sizeof(struct secdebug_session_close_req))
            return -EINVAL;
        break;

    case SECDEBUG_CMD_HW_BP_REGISTER:
        if (req_hdr->payload_len != sizeof(struct secdebug_bp_reg_req))
            return -EINVAL;
        resp_payload_len = sizeof(struct secdebug_bp_reg_resp);
        break;

    case SECDEBUG_CMD_HW_BP_UNREGISTER:
        if (req_hdr->payload_len != sizeof(struct secdebug_bp_unreg_req))
            return -EINVAL;
        break;

    case SECDEBUG_CMD_HW_BP_GET_HIT: {
        const struct secdebug_bp_hit_req *req;

        if (req_hdr->payload_len != sizeof(struct secdebug_bp_hit_req))
            return -EINVAL;
        req = (const struct secdebug_bp_hit_req *)req_payload;
        if (req->clear_hit > 1)
            return -EINVAL;
        resp_payload_len = sizeof(struct secdebug_bp_hit_resp);
        break;
    }

    default:
        break;
    }

    if ((uint64_t)sizeof(struct secdebug_resp_header) + resp_payload_len > (uint64_t)outlen)
        return -E2BIG;
    return 0;
}

static long secdebug_control0(const char *ctl_args, char *__user out_msg, int outlen)
{
    unsigned char *req_buf = NULL;
    unsigned char *resp_buf = NULL;
    struct secdebug_req_header *req_hdr;
    struct secdebug_resp_header *resp_hdr;
    int arg_len;
    int decoded_len;
    int resp_total_len;
    int ret = 0;
    uid_t caller_uid;
    uint32_t registered_slot_id = 0;
    int registered_slot_pending = 0;
    struct secdebug_bp_hit_req hit_ack_req;
    uint64_t hit_snapshot_total = 0;
    int hit_lease_pending = 0;
    uint32_t opened_session_id = 0;
    int opened_session_pending = 0;
    int buffer_rcu_dropped = 0;

    if (!secdebug_begin_call())
        return -EBUSY;

    if (!ctl_args || !out_msg || outlen < (int)sizeof(struct secdebug_resp_header)) {
        ret = -EINVAL;
        goto out;
    }

    /* vmalloc may sleep. The loader's ctl_active reference, not RCU alone,
     * keeps module text and the private ctl_args alive while we drop RCU. */
    secdebug_rcu_drop(&buffer_rcu_dropped);
    req_buf = secdebug_alloc(SECDEBUG_ARGS_MAX);
    resp_buf = secdebug_alloc(SECDEBUG_RESP_MAX);
    secdebug_rcu_restore(&buffer_rcu_dropped);
    if (!req_buf || !resp_buf) {
        ret = -ENOMEM;
        goto out;
    }

    /* The loader must own a private, NUL-terminated buffer for this call. */
    arg_len = bounded_len(ctl_args, SECDEBUG_ARGS_MAX);
    if (arg_len <= 0) {
        ret = -EBADMSG;
        goto out;
    }

    decoded_len = b64_decode(ctl_args, arg_len, req_buf, SECDEBUG_ARGS_MAX);
    if (decoded_len < (int)sizeof(struct secdebug_req_header)) {
        ret = -EBADMSG;
        goto out;
    }

    req_hdr = (struct secdebug_req_header *)req_buf;
    if (req_hdr->magic != SECDEBUG_MAGIC || req_hdr->proto_ver != SECDEBUG_PROTO_VER) {
        ret = -EPROTONOSUPPORT;
        goto out;
    }

    if (req_hdr->payload_len > SECDEBUG_ARGS_MAX - sizeof(struct secdebug_req_header) ||
        decoded_len != (int)(sizeof(struct secdebug_req_header) + req_hdr->payload_len)) {
        ret = -EBADMSG;
        goto out;
    }

    caller_uid = current_uid();
    if (caller_uid != 0 && !is_su_allow_uid(caller_uid)) {
        ret = -EPERM;
        goto out;
    }

    if (!auth_token_matches(req_hdr->auth_token)) {
        ret = -EACCES;
        goto out;
    }

    resp_hdr = (struct secdebug_resp_header *)resp_buf;
    memset(resp_buf, 0, SECDEBUG_RESP_MAX);
    resp_hdr->magic = SECDEBUG_MAGIC;
    resp_hdr->proto_ver = SECDEBUG_PROTO_VER;
    resp_hdr->seq = req_hdr->seq;
    resp_hdr->status = 0;
    resp_hdr->payload_len = 0;

    {
        void *req_payload = req_buf + sizeof(struct secdebug_req_header);
        int preflight = secdebug_preflight_request(req_hdr, req_payload, outlen);

        if (preflight) {
            resp_hdr->status = preflight;
            goto copy_response;
        }

        void *resp_payload = resp_buf + sizeof(struct secdebug_resp_header);
        int max_resp_payload = SECDEBUG_RESP_MAX - (int)sizeof(struct secdebug_resp_header);

        switch (req_hdr->cmd) {
        case SECDEBUG_CMD_PROBE_CAP: {
            struct secdebug_cap_resp *cap = (struct secdebug_cap_resp *)resp_payload;

            cap->kpm_ver = SECDEBUG_PROTO_VER;
            cap->kp_core_ver = kpver;
            cap->linux_ver = kver;
            cap->page_size = g_page_size;
            cap->cap_flags = g_cap_flags;
            cap->max_bp_slots = SECDEBUG_MAX_BP_SLOTS;
            cap->active_bp_cnt = secdebug_hwbp_active_count();
            cap->reserved = 0;
            resp_hdr->payload_len = sizeof(struct secdebug_cap_resp);
            break;
        }

        case SECDEBUG_CMD_MEM_READ: {
            struct secdebug_mem_read_req *rreq;
            uint32_t bytes_read = 0;
            int status;

            if (req_hdr->payload_len != sizeof(struct secdebug_mem_read_req)) {
                resp_hdr->status = -EINVAL;
                break;
            }
            rreq = (struct secdebug_mem_read_req *)req_payload;
            if (rreq->read_len > (uint32_t)max_resp_payload) {
                resp_hdr->status = -E2BIG;
                break;
            }
            status = secdebug_mem_read(rreq, resp_payload, &bytes_read);
            resp_hdr->status = status;
            resp_hdr->payload_len = (status == 0) ? bytes_read : 0;
            break;
        }

        case SECDEBUG_CMD_MEM_WRITE: {
            struct secdebug_mem_write_req *wreq;
            struct secdebug_mem_write_resp *wresp;
            const void *write_data;
            uint32_t written = 0;
            int status;

            if (req_hdr->payload_len < sizeof(struct secdebug_mem_write_req)) {
                resp_hdr->status = -EINVAL;
                break;
            }
            wreq = (struct secdebug_mem_write_req *)req_payload;
            if ((uint64_t)req_hdr->payload_len !=
                sizeof(struct secdebug_mem_write_req) + (uint64_t)wreq->write_len) {
                resp_hdr->status = -EINVAL;
                break;
            }
            if (sizeof(struct secdebug_mem_write_resp) > (uint32_t)max_resp_payload) {
                resp_hdr->status = -E2BIG;
                break;
            }
            write_data = (const char *)req_payload + sizeof(struct secdebug_mem_write_req);
            status = secdebug_mem_write(wreq, write_data, &written);
            resp_hdr->status = status;
            if (status == 0) {
                wresp = (struct secdebug_mem_write_resp *)resp_payload;
                wresp->bytes_written = written;
                wresp->reserved = 0;
                resp_hdr->payload_len = sizeof(*wresp);
            }
            break;
        }

        case SECDEBUG_CMD_MEM_SESSION_OPEN: {
            struct secdebug_session_open_resp *sresp =
                (struct secdebug_session_open_resp *)resp_payload;
            int status = secdebug_session_open((struct secdebug_session_open_req *)req_payload,
                                               sresp);
            resp_hdr->status = status;
            if (status == 0) {
                resp_hdr->payload_len = sizeof(*sresp);
                opened_session_id = sresp->session_id;
                opened_session_pending = 1;
            }
            break;
        }

        case SECDEBUG_CMD_MEM_SESSION_READ: {
            struct secdebug_session_read_req *rreq =
                (struct secdebug_session_read_req *)req_payload;
            uint32_t bytes_read = 0;
            int status = secdebug_session_read(rreq, resp_payload, &bytes_read);
            resp_hdr->status = status;
            resp_hdr->payload_len = status == 0 ? bytes_read : 0;
            break;
        }

        case SECDEBUG_CMD_MEM_SESSION_WRITE: {
            struct secdebug_session_write_req *wreq =
                (struct secdebug_session_write_req *)req_payload;
            const void *write_data = (char *)req_payload + sizeof(*wreq);
            uint32_t written = 0;
            int status = secdebug_session_write(wreq, write_data, &written);
            resp_hdr->status = status;
            if (status == 0) {
                struct secdebug_mem_write_resp *wresp =
                    (struct secdebug_mem_write_resp *)resp_payload;
                wresp->bytes_written = written;
                wresp->reserved = 0;
                resp_hdr->payload_len = sizeof(*wresp);
            }
            break;
        }

        case SECDEBUG_CMD_MEM_SESSION_CLOSE: {
            struct secdebug_session_close_req *creq =
                (struct secdebug_session_close_req *)req_payload;
            resp_hdr->status = creq->reserved ? -EINVAL :
                               secdebug_session_close(creq->session_id);
            break;
        }

        case SECDEBUG_CMD_HW_BP_REGISTER: {
            struct secdebug_bp_reg_req *breq;
            struct secdebug_bp_reg_resp *bresp;
            int status;

            if (req_hdr->payload_len != sizeof(struct secdebug_bp_reg_req)) {
                resp_hdr->status = -EINVAL;
                break;
            }
            breq = (struct secdebug_bp_reg_req *)req_payload;
            bresp = (struct secdebug_bp_reg_resp *)resp_payload;
            status = secdebug_hwbp_register(breq, bresp);
            resp_hdr->status = status;
            resp_hdr->payload_len = (status == 0) ? sizeof(struct secdebug_bp_reg_resp) : 0;
            if (status == 0) {
                registered_slot_id = bresp->slot_id;
                registered_slot_pending = 1;
            }
            break;
        }

        case SECDEBUG_CMD_HW_BP_UNREGISTER: {
            struct secdebug_bp_unreg_req *ureq;
            int status;

            if (req_hdr->payload_len != sizeof(struct secdebug_bp_unreg_req)) {
                resp_hdr->status = -EINVAL;
                break;
            }
            ureq = (struct secdebug_bp_unreg_req *)req_payload;
            status = secdebug_hwbp_unregister(ureq);
            resp_hdr->status = status;
            resp_hdr->payload_len = 0;
            break;
        }

        case SECDEBUG_CMD_HW_BP_GET_HIT: {
            struct secdebug_bp_hit_req *hreq;
            struct secdebug_bp_hit_resp *hresp;
            int status;

            if (req_hdr->payload_len != sizeof(struct secdebug_bp_hit_req)) {
                resp_hdr->status = -EINVAL;
                break;
            }
            hreq = (struct secdebug_bp_hit_req *)req_payload;
            hresp = (struct secdebug_bp_hit_resp *)resp_payload;
            status = secdebug_hwbp_get_hit(hreq, hresp, &hit_snapshot_total);
            resp_hdr->status = status;
            resp_hdr->payload_len = (status == 0) ? sizeof(struct secdebug_bp_hit_resp) : 0;
            if (status == 0) {
                hit_ack_req = *hreq;
                hit_lease_pending = 1;
            }
            break;
        }

        default:
            resp_hdr->status = -EOPNOTSUPP;
            break;
        }
    }

copy_response:
    resp_total_len = (int)sizeof(struct secdebug_resp_header) + (int)resp_hdr->payload_len;
    if (resp_total_len > outlen) {
        /* Preflight should make this unreachable for commands with side effects. */
        resp_hdr->status = -E2BIG;
        resp_hdr->payload_len = 0;
        resp_total_len = (int)sizeof(struct secdebug_resp_header);
    }

    {
        int copied;
        int response_rcu_dropped = 0;

        /* copy_to_user may fault/sleep; do not hold the loader's RCU nest. */
        secdebug_rcu_drop(&response_rcu_dropped);
        copied = compat_copy_to_user(out_msg, resp_buf, resp_total_len);
        secdebug_rcu_restore(&response_rcu_dropped);
        if (hit_lease_pending) {
            /* BUSY lease prevents concurrent unregister between peek and ACK. */
            secdebug_hwbp_finish_hit(&hit_ack_req, hit_snapshot_total,
                                    copied == resp_total_len);
        }
        if (copied != resp_total_len) {
            if (registered_slot_pending) {
                struct secdebug_bp_unreg_req rollback = { registered_slot_id, 0 };
                int rollback_rc = secdebug_hwbp_unregister(&rollback);
                if (rollback_rc && rollback_rc != -ENOENT)
                    printk("secdebug: BP rollback failed: %d\n", rollback_rc);
            }
            if (opened_session_pending)
                (void)secdebug_session_close(opened_session_id);
            ret = -EFAULT; /* Side effects of writes/closes may already exist. */
            goto out;
        }
    }

out:
    /* Wiping/freeing can sleep too, including allocation-failure paths. */
    secdebug_rcu_drop(&buffer_rcu_dropped);
    secdebug_free(req_buf, SECDEBUG_ARGS_MAX);
    secdebug_free(resp_buf, SECDEBUG_RESP_MAX);
    secdebug_rcu_restore(&buffer_rcu_dropped);
    secdebug_end_call();
    return ret;
}

static long secdebug_exit(void *reserved)
{
    (void)reserved;

    /*
     * Host contract required for safe live unload:
     *   1. stop admitting new control callbacks before invoking KPM_EXIT;
     *   2. invoke KPM_EXIT outside a blocking-incompatible RCU read section;
     *   3. do not free module text/data until all in-flight callbacks and
     *      overflow handlers have completed.
     *
     * A loader that violates that contract cannot be made unload-safe from
     * inside the module itself. See README.md and SECURITY.md.
     */
    unsigned int expected = 0;

    /* No busy wait, scheduler dependency or priority-inversion loop. A failed
     * close has no side effects; the patched host MUST honor this refusal. */
    if (!__atomic_compare_exchange_n(&g_call_state, &expected,
                                      SECDEBUG_CALLS_CLOSED, 0,
                                      __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
        return -EBUSY;
    if (!g_initialized) {
        g_auth_token = 0;
        return 0; /* host may call EXIT after a failed INIT */
    }
    secdebug_hwbp_cleanup();
    secdebug_session_cleanup();
    g_initialized = 0;
    g_auth_token = 0;
    return 0;
}

KPM_INIT(secdebug_init);
KPM_CTL0(secdebug_control0);
KPM_EXIT(secdebug_exit);
