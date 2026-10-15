/* SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0 */
/*
 * secdebug_proto.h - Cross-ABI secure debug protocol definitions
 * Shared between KPM driver and userspace Client SDK
 */

#ifndef _SECDEBUG_PROTO_H_
#define _SECDEBUG_PROTO_H_

#ifdef __KERNEL__
#include <ktypes.h>
#else
#include <stdint.h>
#include <stddef.h>
#endif

#define SECDEBUG_MAGIC       0x53444247ULL /* "SDBG" in ASCII little-endian */
#define SECDEBUG_PROTO_VER   0x00010000UL  /* wire protocol v1.0, backwards compatible additions */

/* Module identification */
#define SECDEBUG_MOD_NAME    "secdebug"
#define SECDEBUG_MOD_VER     "1.0.0"

/* Maximum control arguments and buffer limits */
#define SECDEBUG_ARGS_MAX    1024
#define SECDEBUG_RESP_MAX    640
#define SECDEBUG_MAX_PAYLOAD 512

/* Command IDs */
enum secdebug_cmd_id {
    SECDEBUG_CMD_PROBE_CAP       = 0x01, /* Query capabilities, version & limits */
    SECDEBUG_CMD_MEM_READ        = 0x02, /* Safe cross-process memory read */
    SECDEBUG_CMD_MEM_WRITE       = 0x03, /* Safe cross-process memory write */
    SECDEBUG_CMD_MEM_SESSION_OPEN  = 0x04, /* Pin a process mm for multi-block I/O */
    SECDEBUG_CMD_MEM_SESSION_READ  = 0x05,
    SECDEBUG_CMD_MEM_SESSION_WRITE = 0x06,
    SECDEBUG_CMD_MEM_SESSION_CLOSE = 0x07,
    SECDEBUG_CMD_HW_BP_REGISTER  = 0x10, /* Register hardware breakpoint / watchpoint */
    SECDEBUG_CMD_HW_BP_UNREGISTER= 0x11, /* Unregister hardware breakpoint */
    SECDEBUG_CMD_HW_BP_GET_HIT   = 0x12, /* Retrieve breakpoint hit context */
    SECDEBUG_CMD_MAX,
};

/* Capability Flags returned in CMD_PROBE_CAP */
#define SECDEBUG_CAP_MEM_READ   (1U << 0)
#define SECDEBUG_CAP_MEM_WRITE  (1U << 1)
#define SECDEBUG_CAP_HW_BREAK   (1U << 2)
#define SECDEBUG_CAP_HW_WATCH   (1U << 3)
#define SECDEBUG_CAP_MEM_SESSION (1U << 4) /* Stable target across chunks */

/* Hardware breakpoint types */
#define SECDEBUG_BP_TYPE_EXEC   1 /* Instruction execution breakpoint */
#define SECDEBUG_BP_TYPE_READ   2 /* Data read watchpoint */
#define SECDEBUG_BP_TYPE_WRITE  3 /* Data write watchpoint */
#define SECDEBUG_BP_TYPE_RW     4 /* Data read/write watchpoint */

/*
 * Request Header (32 bytes, 8-byte aligned)
 */
struct secdebug_req_header {
    uint64_t magic;         /* Must be SECDEBUG_MAGIC */
    uint32_t proto_ver;     /* Must match SECDEBUG_PROTO_VER */
    uint32_t cmd;           /* enum secdebug_cmd_id */
    uint32_t seq;           /* Client-assigned sequence number */
    uint32_t payload_len;   /* Length of payload following header */
    uint64_t auth_token;    /* Shared session authentication token */
} __attribute__((packed, aligned(8)));

/*
 * Response Header (32 bytes, 8-byte aligned)
 */
struct secdebug_resp_header {
    uint64_t magic;         /* SECDEBUG_MAGIC */
    uint32_t proto_ver;     /* SECDEBUG_PROTO_VER */
    int32_t  status;        /* 0: success, <0: negative errno */
    uint32_t seq;           /* Echoed sequence number from request */
    uint32_t payload_len;   /* Length of response payload */
    uint32_t reserved;
    uint32_t pad;
} __attribute__((packed, aligned(8)));

/*
 * Payload for SECDEBUG_CMD_PROBE_CAP response
 */
struct secdebug_cap_resp {
    uint32_t kpm_ver;       /* KP module version */
    uint32_t kp_core_ver;   /* Host KernelPatch version */
    uint32_t linux_ver;     /* Linux kernel version code */
    uint32_t page_size;     /* 0=unknown, else 4096 / 16384 / 65536 */
    uint32_t cap_flags;     /* Bitmask of SECDEBUG_CAP_* */
    uint32_t max_bp_slots;  /* Max hardware breakpoint slots supported */
    uint32_t active_bp_cnt; /* Currently active breakpoint slots */
    uint32_t reserved;
} __attribute__((packed, aligned(8)));

/*
 * Payload for SECDEBUG_CMD_MEM_READ request
 */
struct secdebug_mem_read_req {
    int32_t  target_pid;    /* Target process PID (vpid) */
    uint32_t read_len;      /* Number of bytes to read (<= SECDEBUG_MAX_PAYLOAD) */
    uint64_t target_addr;   /* Virtual address in target process */
} __attribute__((packed, aligned(8)));

/*
 * Payload for SECDEBUG_CMD_MEM_WRITE request
 * Followed immediately by raw data to write of length write_len.
 * A successful response carries secdebug_mem_write_resp.
 */
struct secdebug_mem_write_req {
    int32_t  target_pid;    /* Target process PID (vpid) */
    uint32_t write_len;     /* Number of bytes to write (<= SECDEBUG_MAX_PAYLOAD) */
    uint64_t target_addr;   /* Virtual address in target process */
} __attribute__((packed, aligned(8)));

struct secdebug_mem_write_resp {
    uint32_t bytes_written; /* Bytes actually written; may be shorter than write_len */
    uint32_t reserved;
} __attribute__((packed, aligned(8)));

/* Stable-mm memory sessions are owned by their creating thread, bounded in
 * number, and keep an mm ref instead of relying on a PID for every chunk. */
struct secdebug_session_open_req {
    int32_t target_pid;
    uint32_t reserved;
} __attribute__((packed, aligned(8)));

struct secdebug_session_open_resp {
    uint32_t session_id;
    uint32_t reserved;
} __attribute__((packed, aligned(8)));

struct secdebug_session_read_req {
    uint32_t session_id;
    uint32_t read_len;
    uint64_t target_addr;
} __attribute__((packed, aligned(8)));

struct secdebug_session_write_req {
    uint32_t session_id;
    uint32_t write_len;
    uint64_t target_addr;
    /* Followed by write_len bytes of raw data. */
} __attribute__((packed, aligned(8)));

struct secdebug_session_close_req {
    uint32_t session_id;
    uint32_t reserved;
} __attribute__((packed, aligned(8)));

/*
 * Payload for SECDEBUG_CMD_HW_BP_REGISTER request
 */
struct secdebug_bp_reg_req {
    int32_t  target_tid;    /* Thread ID to monitor (vpid) */
    uint32_t bp_type;       /* SECDEBUG_BP_TYPE_* */
    uint64_t target_addr;   /* Address to break or watch */
    uint32_t bp_len;        /* 4 or 8 bytes for watchpoints, 4 for ARM64 breakpoint */
    uint32_t reserved;
} __attribute__((packed, aligned(8)));

/*
 * Payload for SECDEBUG_CMD_HW_BP_REGISTER response
 */
struct secdebug_bp_reg_resp {
    uint32_t slot_id;       /* Allocated breakpoint handle/slot */
    uint32_t reserved;
} __attribute__((packed, aligned(8)));

/*
 * Payload for SECDEBUG_CMD_HW_BP_UNREGISTER request
 */
struct secdebug_bp_unreg_req {
    uint32_t slot_id;       /* Slot ID previously allocated */
    uint32_t reserved;
} __attribute__((packed, aligned(8)));

/*
 * ARM64 pt_regs snapshot captured on breakpoint hit
 */
struct secdebug_regs_snapshot {
    uint64_t regs[31];      /* x0 - x30 */
    uint64_t sp;            /* stack pointer */
    uint64_t pc;            /* program counter */
    uint64_t pstate;        /* processor state */
} __attribute__((packed, aligned(8)));

/*
 * Payload for SECDEBUG_CMD_HW_BP_GET_HIT request
 */
struct secdebug_bp_hit_req {
    uint32_t slot_id;       /* Slot ID to query */
    uint32_t clear_hit;     /* 1: consume hit and reset, 0: peek */
} __attribute__((packed, aligned(8)));

/*
 * Payload for SECDEBUG_CMD_HW_BP_GET_HIT response
 */
struct secdebug_bp_hit_resp {
    uint32_t slot_id;
    uint32_t hit_count;     /* Unconsumed hits; clear re-arms the one-shot event */
    uint64_t trigger_addr;  /* Exec: PC. Watch: armed data address */
    struct secdebug_regs_snapshot regs;
} __attribute__((packed, aligned(8)));

#endif /* _SECDEBUG_PROTO_H_ */
