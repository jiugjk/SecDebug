/* SPDX-License-Identifier: Apache-2.0 */
#ifndef TEST_STUB_KPMODULE_H
#define TEST_STUB_KPMODULE_H
extern unsigned long kallsyms_lookup_name(const char *);
extern unsigned int kver, kpver;
#define VERSION(a,b,c) (((a) << 16) | ((b) << 8) | (c))
/* Match the strictest supported host, including the terminating NUL. */
#define KPM_NAME_LEN 32
#define KPM_VERSION_LEN 12
#define KPM_LICENSE_LEN 32
#define KPM_AUTHOR_LEN 32
#define KPM_DESCRIPTION_LEN 512
#define STUB_KPM_INFO(field, value, limit) \
    _Static_assert(sizeof(value) <= (limit), "KPM info string too long"); \
    static const char *const __attribute__((used)) stub_##field = (value)
#define KPM_NAME(s) STUB_KPM_INFO(name, s, KPM_NAME_LEN)
#define KPM_VERSION(s) STUB_KPM_INFO(version, s, KPM_VERSION_LEN)
#define KPM_AUTHOR(s) STUB_KPM_INFO(author, s, KPM_AUTHOR_LEN)
#define KPM_DESCRIPTION(s) STUB_KPM_INFO(description, s, KPM_DESCRIPTION_LEN)
#define KPM_LICENSE(s) STUB_KPM_INFO(license, s, KPM_LICENSE_LEN)
#define KPM_INIT(fn) static __typeof__(&(fn)) __attribute__((used)) stub_init = &(fn)
#define KPM_CTL0(fn) static __typeof__(&(fn)) __attribute__((used)) stub_ctl0 = &(fn)
#define KPM_EXIT(fn) static __typeof__(&(fn)) __attribute__((used)) stub_exit = &(fn)
#endif
