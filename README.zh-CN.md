<!-- SPDX-License-Identifier: Apache-2.0 -->
# SecDebug — ARM64 KPM 调试器（加固源码）

[English](README.md) | **简体中文**

**源码版本：1.0.0**（模块版本字符串为 `1.0.0`）；
**线协议头/协议版本：1.0**（`0x00010000`）。本源码包包含可编辑的 C 源码、
客户端 SDK、协议测试、隔离的编译测试桩，以及宿主（host）的**参考补丁**。
**它不是可直接部署的二进制程序，也不是经过目标设备认证的发行版。**

**免责声明：** 仅供获得明确授权的安全调试与研究。内核内存操作与断点可能导致崩溃
或数据损坏。不保证运行时/设备兼容性——详见 [DISCLAIMER.md](DISCLAIMER.md)、
[SECURITY.md](SECURITY.md) 与 [LICENSE](LICENSE)。

SecDebug 是面向 KernelPatch/KPatch-Next 的高权限内核补丁模块（Kernel Patch Module，
KPM），用于在获得授权的情况下，对其他进程的**用户态虚拟地址**进行内存读取、写入，
以及使用 ARM64 perf 硬件执行断点/数据监视点并采集寄存器快照。通过加载器鉴权的
调用者（root/su 允许列表**且**持有模块配置的非零 64 位 token）将获得强大的调试权限。
**只能针对自己拥有或已获得明确授权的目标进程，并在可用于测试的设备上使用。**

## 宿主兼容性与运行限制

**本源码包未经过设备认证。** KPM 依赖 `secdebug_host_contract_v1` 导入符号：
未打补丁的加载器，以及独立的 KernelPatch LKM 后端，都无法满足该契约。
必须应用匹配的补丁、重新构建并启动**宿主加载器**，同时重新构建 SecDebug。
只修改本地源码目录，不会更新设备上已经运行的加载器。

该宿主配置具有以下运行限制：

- 如果仍有控制调用正在执行，卸载将返回 `-EBUSY`，不会改变模块状态。
  请停止发起新的调用，等待已有调用结束后再重试；不要忙循环重试。
- 硬件断点是**一次性**的。清除命中状态只会确认/清除快照，**不会重新启用**该事件。
  需要先注销再重新注册事件才能再次布防。禁止使用任何
  `SECDEBUG_PERF_PENDING_OFFSET` 值。
- 不支持 KernelPatch 的 `lkm/`。该宿主配置禁用 KernelPatch 的 `.kpm.event`
  事件分发（返回 `-EOPNOTSUPP`）；不要在依赖其他事件驱动型 KPM 的系统中应用此配置。
  KPatch-Next 不提供这样的事件分发 API。

## 不可妥协的宿主约束

针对两个固定公开提交的宿主修复位于
[`host_patches/`](host_patches/README.md)。`apply_checked.sh` 会在对应的准确源码树上运行
`git apply --check`；`--verify` 还会将完整且获批准的已打补丁内核源码与 Git blob
进行比对，而不是只检查 HEAD 或标记字符串。这**不能证明设备或 KASAN 层面的安全性**。
部署核查要求见 [SECURITY.md](SECURITY.md)。

1. `module_control0` 必须为每个执行中的控制调用提供**私有且不可变**的参数缓冲区，
   绝不能覆盖模块级全局 `ctl_args`。
2. 加载器在进入模块调用时必须持有定义明确的外层 RCU 读临界区；KPM 在可能休眠的
   操作前后必须能够按契约暂时退出、再恢复该临界区。
3. 宿主必须停止接收新的模块调用，在不受不兼容 RCU 限制的上下文中执行退出函数，
   并等待执行中的控制调用、溢出回调及 RCU 宽限期**全部结束后**才能释放模块可执行代码。
   同时还要审计模块列表修改和并发卸载。
4. 加载、控制调用、模块信息相关路径不得记录 token 或解码后的/Base64 载荷。
   如果密钥可能已进入 kmsg/pstore，应立即轮换。

**切勿在未经验证的加载器上热卸载。** 与进行不受支持的 KPM 卸载相比，重启测试设备
通常更安全。

## 目录结构与测试

```text
src/                  KPM 核心、内存、固定 mm 会话、perf 硬件断点
include/              协议及 KPM ABI 头文件
client/               C 语言 SDK 与示例冒烟测试客户端
tests/                ABI/布局、SDK 协议、模拟 mm 状态机测试
scripts/              KPM 未定义符号检查、桩编译、Sanitizer 工具
host_patches/         宿主源码参考补丁及受检查的应用工具
.github/workflows/    用户态/桩编译及 Sanitizer CI
```

无需加载器或真实设备，即可在普通 Linux 主机上执行：

```bash
make check        # SDK/模块故障注入、构建/宿主回归、ABI 测试
make check-stub   # 使用模拟头文件编译 AArch64 对象并部分链接
make sanitize     # 对可在主机运行的测试执行 ASan + UBSan（需要 clang）
make ubsan CC=gcc # 仅执行 UBSan；不能替代 ASan
make client       # 构建 CLI 示例
make package      # 生成干净的源码 ZIP，并保留 Shell 脚本可执行权限
```

`make package` 排除 `.git`/`build`/`dist` 并保留脚本可执行位（桩构建也会用
`sh` 调用脚本）。**AArch64 桩只验语法/代码生成**；真实 `.kpm` 需要经审计的
KernelPatch 树，perf/RCU 行为只能在 ARM64 设备上验证。

### 构建 KPM（仅在核实宿主契约后）

工具要求：GNU make >= 4.3、`clang`、`ld.lld`、Python >= 3.10、
`readelf` 或 `llvm-readelf`，以及与目标加载器准确匹配、已完成宿主修复审查的
固定提交源码目录。

```bash
make KP_DIR=/absolute/path/to/audited/KernelPatch \
     HOST_COMMIT=<full-40-character-git-commit> \
     TARGET_PAGE_SHIFT=12 \
     SECDEBUG_FOLL_FORCE=0x10 \
     HOST_CONTRACT_ACK=I_ACKNOWLEDGE_VERIFIED_HOST
```

`SECDEBUG_FOLL_FORCE` 必须是**目标内核实际使用的** `FOLL_FORCE` 值；如果未核对
目标内核头文件，应设为 `0`，不能仅凭 `kver` 推断。**禁止设置**
`SECDEBUG_PERF_PENDING_OFFSET`，即使设为零或看似对齐的偏移也不允许；构建检查
和 C 预处理器都会拒绝它。上面示例中的 page shift 与 flag **只是示例，不代表
任何特定设备的真实配置**。KPM 编译参数包含 `-mgeneral-regs-only`，避免 Clang
在 `-O2` 下为模块生成 NEON 指令。

**可选 CPU 调优：** 默认 `KPM_TUNE=generic`（`-mcpu=generic -O2`）。确认 CPU
并完成基准后可传如 `KPM_TUNE=cortex-a78`（仅 `-mtune`，安全参数不变）。大小核
可能互相拖累；未启用 `-O3`/LTO/`-mcpu=native`。可用
`make check-stub KPM_TUNE=cortex-a78` 探测；调优写入配置指纹，变更会强制完整重编。

如果缺少宿主契约确认、受支持的 Git 提交、完整的已批准宿主补丁、目标页大小或
`FOLL_FORCE` 设置，此命令会**主动失败**。仅支持 `host_patches/hosts.json`
指定的两个固定提交。额外修改过的内核源码或头文件同样会被拒绝。宿主头文件、链接
和符号验证全部通过后，才会生成 `build/secdebug.kpm` 与
`build/BUILD-METADATA.txt`。**构建期检查不等于运行时兼容性认证。**
安装前必须阅读 [SECURITY.md](SECURITY.md)。

`build/build-config.json` 记录编译器/链接器、参数、宿主提交、补丁哈希与已验证
内核源码哈希。改变已接受参数会使 KPM 目标失效；配置不变则保留对象 mtime。链接/
符号检查走临时文件，失败会移除最终产物。**不要多个 make 共用同一 `BUILD_DIR`。**

## 加载与 SDK 使用

模块加载参数应使用随机生成的、**恰好 16 位十六进制且非零**的 token；SDK 上下文
中使用相同的 `uint64_t` 值。不得将 token、密钥、Base64 请求或目标数据写入公共
日志或 CI 产物。

示例 CLI 通过环境变量而不是命令行参数（argv）接收认证值，以降低一种常见的
Shell 历史泄露风险。**环境变量不是强安全保护**，有足够权限的程序仍可能读取：

```bash
export SECDEBUG_AUTH_TOKEN=0123456789abcdef
# 默认安全模式：要求 KPatch-Next，使用 root hello（不使用 superkey 路径）
./build/client/test_secdebug
```

正常构建的 SDK **禁用旧版 KernelPatch 模式**。如果已审查的加载器分支仍需该模式，
应用构建时必须显式定义 `SECDEBUG_ALLOW_LEGACY_TRUNCATE_SYSCALL=1`；
调用前的 `stat()` 检查**不能解决 TOCTOU 竞态**。应优先采用宿主提供的安全入口。

### SDK 返回值与会话语义

- `secdebug_read_mem` 在没有操作报告错误时返回读取的字节数；如果目标读取不足，
  可以返回较短的正值。后续分块发生错误时返回对应的负 errno。传入非 NULL 的
  `bytes_done` 可获得已经确认完成的前缀长度。**将返回字节数与请求长度比较后，
  才能认为缓冲区已完整读取。**
- `secdebug_write_mem` 在写操作或会话 OPEN 的回执丢失时（系统调用返回
  `-EFAULT`，或响应内容损坏）返回 `-EINPROGRESS`。确定性错误，例如
  `-EACCES`、`-EPERM`、`-EBUSY`、`-ENOMEM`，在尚无分块完成时仍返回负值；
  如果此前已有确认完成的分块，后续确定性错误会返回对应的正数部分字节数。
  **切勿盲目重试 `-EINPROGRESS`、已完成的前缀，或整次已成功写入的操作。**
- 每条原始命令最多传输 **512 字节**。较大数据操作由 SDK 自动打开一个固定的
  `mm` 会话。会话属于**发起调用的线程**；操作及清理都必须在同一线程进行。
  对不支持会话命令的旧模块，大数据传输将以拒绝方式安全失败。
- 如果 CLOSE 失败，SDK 会保留句柄并最多重试三次；在清理成功前阻止新的内存
  传输。数据操作的返回值与清理错误相互独立：读写后应检查
  `secdebug_client_cleanup_error()`；若其非零，应在打开会话的线程调用
  `secdebug_client_cleanup()` 进行重试。**不能因为清理失败就重复已完成的写入。**
  CLOSE 回执丢失可以安全重试，之后收到 `-ENOENT` 表示清理已完成。
- SDK 使用者必须针对随包头文件编译：`struct secdebug_client` 带有私有清理
  状态，`secdebug_client_destroy()` 会返回错误码。尽可能每线程使用独立上下文。
  同一个上下文上并发或重入执行内存/清理操作会返回 `-EBUSY`。
  清理仍未解决时，不要复制、重新初始化或释放仍然存活的上下文。
- 固定 `mm_struct` 后，目标进程可能退出；此后数据分块仍引用**旧的 mm**，
  绝不会因为 PID 被重用就切换到另一个进程。
- `SECDEBUG_CAP_HW_BREAK` / `SECDEBUG_CAP_HW_WATCH` 表示 perf 辅助函数及
  `init_pid_ns` 已解析，**不表示断点已成功布防或已检测到命中**。如果事件创建
  返回 `-ENODEV`、`-ENOSYS`、`-EOPNOTSUPP` 或 `-ENOENT`，对应能力位会
  被清除。清除命中状态不会重新布防：必须注销并重新注册。会话与断点资源回收使用
  初始 PID 命名空间（init pid namespace），而不是调用者的命名空间。
  **可选硬件命中检查（只允许真实 ARM64 测试设备）：** 设置
  `SECDEBUG_HWBP_SMOKE=1`，然后在可用于测试且已获授权的设备上运行示例 CLI。
  它会在自身栈变量上注册写监视点、写入该变量、轮询非零 PC 的命中记录，然后注销
  事件。`make check` 不会运行此测试；它也无法证明并发卸载、所有 PMU 或重新布防
  场景都安全。
- 使用结束后调用 `secdebug_client_destroy(&client)` 并检查返回值是否为零。
  清理失败时，该函数会保留句柄和凭据，供打开会话的线程重新尝试；只有成功才会
  清零上下文。初始化/销毁时不得有其他 SDK 操作正在执行；不要在日志或内存转储中
  暴露凭据。

协议与 ABI 详见 `include/secdebug_proto.h` 和 `include/secdebug_perf_abi.h`。
源码许可证：KPM 为 **GPL-2.0-only**；用户态代码为 **Apache-2.0**；
共享协议头文件为 **GPL-2.0-only OR Apache-2.0**。
更多信息见 [`LICENSES/`](LICENSES/) 和 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
