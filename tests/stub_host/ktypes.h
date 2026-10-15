/* SPDX-License-Identifier: Apache-2.0 */
/* Compile-only stubs. NEVER use these to build/load a production KPM. */
#ifndef TEST_STUB_KTYPES_H
#define TEST_STUB_KTYPES_H
#define __KERNEL__ 1
#ifndef NULL
#define NULL ((void *)0)
#endif
typedef __UINT8_TYPE__ uint8_t;
typedef __UINT16_TYPE__ uint16_t;
typedef __UINT32_TYPE__ uint32_t;
typedef __UINT64_TYPE__ uint64_t;
typedef __INT32_TYPE__ int32_t;
typedef __UINTPTR_TYPE__ uintptr_t;
typedef __SIZE_TYPE__ size_t;
typedef int pid_t;
typedef unsigned int uid_t;
#endif
