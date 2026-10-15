/* SPDX-License-Identifier: Apache-2.0 */
#ifndef TEST_STUB_KPUTILS_H
#define TEST_STUB_KPUTILS_H
#include <ktypes.h>
#include <compiler.h>
extern int compat_copy_to_user(void __user *, const void *, int);
extern uid_t current_uid(void);
#endif
