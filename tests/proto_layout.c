/* SPDX-License-Identifier: Apache-2.0 */
#include "secdebug_proto.h"

_Static_assert(sizeof(struct secdebug_req_header) == 32, "request header ABI");
_Static_assert(sizeof(struct secdebug_resp_header) == 32, "response header ABI");
_Static_assert(sizeof(struct secdebug_cap_resp) == 32, "capability response ABI");
_Static_assert(sizeof(struct secdebug_mem_read_req) == 16, "read request ABI");
_Static_assert(sizeof(struct secdebug_mem_write_req) == 16, "write request ABI");
_Static_assert(sizeof(struct secdebug_mem_write_resp) == 8, "write response ABI");
_Static_assert(sizeof(struct secdebug_session_open_req) == 8, "session open request ABI");
_Static_assert(sizeof(struct secdebug_session_open_resp) == 8, "session open response ABI");
_Static_assert(sizeof(struct secdebug_session_read_req) == 16, "session read request ABI");
_Static_assert(sizeof(struct secdebug_session_write_req) == 16, "session write request ABI");
_Static_assert(sizeof(struct secdebug_session_close_req) == 8, "session close ABI");
_Static_assert(sizeof(struct secdebug_bp_reg_req) == 24, "breakpoint register request ABI");
_Static_assert(sizeof(struct secdebug_bp_reg_resp) == 8, "breakpoint register response ABI");
_Static_assert(sizeof(struct secdebug_bp_unreg_req) == 8, "breakpoint unregister request ABI");
_Static_assert(sizeof(struct secdebug_bp_hit_req) == 8, "breakpoint hit request ABI");
_Static_assert(sizeof(struct secdebug_regs_snapshot) == 272, "register snapshot ABI");
_Static_assert(sizeof(struct secdebug_bp_hit_resp) == 288, "breakpoint hit response ABI");

int main(void)
{
    return 0;
}
