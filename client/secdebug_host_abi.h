/* SPDX-License-Identifier: Apache-2.0 */
/*
 * secdebug_host_abi.h - Minimal userspace interoperability constants.
 *
 * These numeric values describe the public SuperCall wire ABI used by
 * KernelPatch / KPatch-Next.  This file intentionally contains no copied
 * loader implementation code or upstream helper bodies.
 */

#ifndef _SECDEBUG_HOST_ABI_H_
#define _SECDEBUG_HOST_ABI_H_

#include <stdint.h>

/* ARM64 SuperCall entry used by the supported hosts. */
#define SECDEBUG_HOST_SYSCALL_NR 45L

/* Only the two host operations secdebug needs. */
#define SECDEBUG_HOST_CMD_HELLO       0x1000u
#define SECDEBUG_HOST_CMD_KPM_CONTROL 0x1022u

/* Public hello responses / command-family tags. */
#define SECDEBUG_HOST_KP_HELLO_RESPONSE     0x11581158L
#define SECDEBUG_HOST_KPN_HELLO_RESPONSE    0x20262026L
#define SECDEBUG_HOST_KP_FAMILY_TAG         0x1158u
#define SECDEBUG_HOST_KPN_FAMILY_TAG        0x2026u

/* Host ABI versions currently targeted by this SDK adapter. */
#define SECDEBUG_HOST_KP_ABI_VERSION   0x00000d09u /* 0.13.9 */
#define SECDEBUG_HOST_KPN_ABI_VERSION  0x00000d05u /* 0.13.5 */

static inline uint64_t secdebug_host_command_word(uint32_t version,
                                                  uint16_t family_tag,
                                                  uint16_t operation)
{
    uint64_t word = (uint64_t)version;

    word <<= 32;
    word |= (uint64_t)family_tag << 16;
    word |= (uint64_t)operation;
    return word;
}

#endif /* _SECDEBUG_HOST_ABI_H_ */
