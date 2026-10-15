<!-- SPDX-License-Identifier: Apache-2.0 -->
# Security policy

**免责声明：** 详见 [DISCLAIMER.md](DISCLAIMER.md)。通过本地检查不等于
真实设备安全，任何部署及对设备或第三方的操作均须获得明确授权。

## Supported version

当前交付 `1.0.0` 源码；共享线协议头版本为 1.0。**未经过目标设备认证，禁止将测试通过等同于生产可用。**

## Threat model

`secdebug` 是高权限调试模块，不是面向不受信任用户的隔离沙箱。模块控制接口要求：

- 调用者 UID 为 root，或通过宿主的 `is_su_allow_uid()`；并且
- 请求携带加载时配置的非零 64 位认证 token。

通过认证的调用者可以对其他进程执行强力调试操作，因此 token 与宿主 su allow-list 都必须按高权限凭据保护。

## Required host profile

The approved host patches and the KPM must be deployed together. The required
host export is absent from the pinned unpatched hosts and the independent LKM
backend; unresolved imports reject loading before module initialization.
A runtime primitive check can refuse initialization with `-EOPNOTSUPP`.
Neither this marker nor the source hash is cryptographic attestation of the
running kernel: the host remains trusted and needs target-device validation.

`lkm/` and KernelPatch event-driven KPMs are explicitly unsupported by this
profile. `notify_modules_event` does not dispatch events. A busy unload returns
`-EBUSY` without teardown; stop callers before retrying. A hit event stays
one-shot after clear; raw perf offsets cannot be enabled.

## Deployment requirements

安全部署还依赖 KernelPatch / KPatch-Next loader 的参数生命周期、并发序列化和卸载/RCU 契约。请先阅读 `README.md` 中的 host 约束和 `host_patches/README.md`，并完成以下核查：

- 固定并记录真实 loader fork/commit、目标内核构建号、设备型号、page shift 与 perf/SELinux 策略。
- 验证每次控制调用都有私有且不可变的参数缓冲，loader 传入的外层 RCU 可按约定暂时退出/恢复；检查 `compat_copy_to_user()` 的返回值语义。
- 验证 loader 的模块列表并发修改、控制调用/overflow 回调与卸载等待顺序；模块代码与数据必须在回调结束及 RCU 宽限期后才释放。
- 使用目标内核头文件核对 `FOLL_FORCE`、perf ABI 布局和必需符号；缺失功能必须 fail-closed。
- 在隔离的 ARM64 测试设备上使用 KASAN/KCSAN 验证多核并发、异常协议、目标退出/PID 复用、写入回执丢失、硬件断点清除/重建与卸载竞争。
- 核对 kmsg/pstore/loader 日志不含 token、superkey 或控制 payload，泄露过的凭据应轮换。

源码包附带针对指定公开提交的参考 host patch，但**没有**自动集成到实际 loader，也不能证明设备安全。未完成上述验证时，不要 live unload，更不能将本源码包视为已通过生产部署验收。

## Secret handling

不要把以下内容提交到 GitHub 或公开日志：

- 模块 auth token；
- KernelPatch superkey；
- Base64 控制请求；
- 目标进程内存内容或写入 payload；
- 设备专用内核/loader 私密凭据。

示例程序只从环境变量读取凭据，不从 argv 读取，初始化后清理该进程继承的变量；仍应视环境变量为可被高权限人员读取的不安全传递渠道。SDK `secdebug_client_destroy()` 成功时主动清零上下文；如果会话清理失败，它会返回错误并保留句柄和凭据，必须由创建会话的线程重试清理。模块在解析加载 token 后会清掉宿主传入的参数缓冲。`-EINPROGRESS` 表示写、注册、注销、打开或关闭会话、带 clear 的命中查询丢失或收到不完整回执；`-EACCES`、`-EPERM`、`-EBUSY`、`-ENOMEM` 等要按原错误处理，不能当成结果未知。数据操作结果与 `secdebug_client_cleanup_error()` 分开判断，不要因为关闭失败重放已经完成的写入。

## Reporting a vulnerability

如果仓库启用了 GitHub **Private vulnerability reporting / Security Advisories**，优先通过该渠道私下报告。报告应尽量包含：受影响 commit、loader fork/commit、内核版本、最小复现步骤、预期/实际行为和必要的日志（先移除 token、superkey 与用户数据）。

在修复发布前，不建议在公开 issue 中粘贴可直接利用的漏洞细节或真实凭据。
