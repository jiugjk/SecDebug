/* SPDX-License-Identifier: Apache-2.0 */
#ifndef TEST_STUB_ERR_H
#define TEST_STUB_ERR_H
#include <ktypes.h>
#define IS_ERR(p) ((uintptr_t)(p) >= (uintptr_t)-4095)
#define PTR_ERR(p) ((long)(p))
#endif
