<!-- SPDX-License-Identifier: Apache-2.0 -->
# Third-party notices and interoperability notes

This repository is designed to interoperate with external kernel/loader
projects, but it does not vendor their complete source trees. The host reference patches
contain upstream context and modifications for their stated GPL-2.0 baselines;
upstream copyright and licensing continue to apply to those host files.

## KernelPatch and KPatch-Next

`secdebug` supports the public SuperCall/KPM control ABI exposed by:

- KernelPatch: https://github.com/bmax121/KernelPatch
- KPatch-Next: https://github.com/KernelSU-Next/KPatch-Next

Those upstream projects are distributed under GNU GPL version 2 terms. The
userspace file `client/secdebug_host_abi.h` contains only the small set of
numeric interoperability values needed to address the public ABI (SuperCall
entry, hello/control operation numbers, family tags, and hello responses) plus
an independently written command-word packer. It does not copy upstream loader
helper implementations.

The KPM is compiled against the selected host SDK/header tree. Kernel-side
sources in this repository are therefore kept under `GPL-2.0-only`. In
particular, `src/secdebug_mem.c` uses the host-provided ARM64 `asm/current.h`
helper rather than carrying a local copy of the host's `current` implementation.

`secdebug` is an independent project and is not an official KernelPatch or
KPatch-Next component. Upstream project names are used only to describe
compatibility.

## Linux kernel ABI definitions

The hardware-breakpoint implementation interoperates with Linux perf/hardware
breakpoint ABI values and the ARM64 register layout. Linux UAPI headers such as
`include/uapi/linux/perf_event.h`, `include/uapi/linux/hw_breakpoint.h`, and
`arch/arm64/include/uapi/asm/ptrace.h` document those interface values and use
the Linux syscall-note exception. This repository does not vendor those Linux
headers; the KPM-side implementation is GPL-2.0-only.

Linux source: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/

## Base64 / RFC 4648

The Base64 codec in this repository implements the behavior specified by RFC
4648 using project-owned block-oriented code. During pre-publication review an
earlier AI-generated encoder was found to resemble a widely circulated public
implementation, so that encoder was removed rather than relicensed or lightly
edited. The current implementation was rewritten from the RFC behavior and is
covered by the SPDX identifier of its containing source file.

RFC 4648: https://www.rfc-editor.org/rfc/rfc4648
