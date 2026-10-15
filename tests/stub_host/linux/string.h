/* SPDX-License-Identifier: Apache-2.0 */
#ifndef TEST_STUB_STRING_H
#define TEST_STUB_STRING_H
#include <ktypes.h>
extern size_t strlen(const char *);
extern void *memset(void *, int, size_t);
extern void *memcpy(void *, const void *, size_t);
#endif
