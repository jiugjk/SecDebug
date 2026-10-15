<!-- SPDX-License-Identifier: Apache-2.0 -->
# 免责声明 / Disclaimer

本源码包仅供设备所有者或得到明确授权的人员进行安全研究、调试、兼容性测试和教育。
跨进程内存读写、内核模块加载/卸载以及硬件断点会改变设备高权限状态，
可能造成内核崩溃、设备无法启动、数据丢失、隐私泄露或其他安全问题。
使用者应先备份数据，仅在隔离的、可恢复的测试设备上操作，遵守适用法律、
设备与目标进程的授权边界，并自行验证目标内核 ABI、loader 并发/RCU 合约及卸载安全。
不得因为主机测试通过或源码补丁可应用就认为它已通过真机验证。

This source is provided solely for lawful, explicitly authorized debugging,
security research and interoperability testing. It is a high-privilege kernel
component that may crash a device, corrupt data, leak sensitive information,
or compromise system security. Only use it on isolated, recoverable systems
that you own or have permission to test. Verify loader, kernel and perf ABI
compatibility independently before loading. Host tests and patch-application
checks are not evidence of safe operation on a physical Android device.

To the extent permitted by the applicable licenses and law, the source is
provided **AS IS, WITHOUT WARRANTY**; no fitness for a particular purpose,
production readiness, device compatibility, stability or security is claimed.
This notice does not override the licenses in `LICENSE` and `LICENSES/`,
or limit any rights that cannot legally be excluded. See `SECURITY.md`.
