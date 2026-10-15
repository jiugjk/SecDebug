<!-- SPDX-License-Identifier: Apache-2.0 -->
# SecDebug — ARM64 KPM debugger (hardened source)

**Languages:** English | [简体中文](README.zh-CN.md)

**Source version: 1.0.0** (module string `1.0.0`);
**wire header/protocol: 1.0** (`0x00010000`). The ZIP contains editable C source, SDK,
protocol tests, isolated compile-test stubs and host **reference** patches.
It is **not** a ready-to-deploy binary or a device-certified release.

**Disclaimer:** Authorized security research only. Kernel memory ops and breakpoints
can crash devices or corrupt data. No runtime/device guarantees — see
[DISCLAIMER.md](DISCLAIMER.md), [SECURITY.md](SECURITY.md), and [LICENSE](LICENSE).

SecDebug is a high-privilege KernelPatch/KPatch-Next Kernel Patch Module for
authorized cross-process *user-virtual-address* memory inspection, writing
and ARM64 perf-based hardware break/watchpoints with register snapshots. Any
caller authorized by the loader (root/su allow-list **and** the nonzero 64-bit
module token) receives powerful debugger-level capabilities. Use only on
owned or explicitly authorized target processes and disposable test devices.

## Host compatibility and runtime limits

**This source package is not device-certified.** The KPM requires the
`secdebug_host_contract_v1` import: an unpatched loader or the independent
KernelPatch LKM backend cannot satisfy it. Apply the matching patch and rebuild
and boot the **host loader** as well as rebuilding SecDebug. Editing a source
checkout does not update the loader already running on a device.

The host profile enforces the following operational restrictions:

- An unload with in-flight control calls returns `-EBUSY`, without changing the
  module. Stop issuing calls, let them finish, and retry; do not busy-loop.
- Hardware breakpoints are one-shot. Clearing a hit acknowledges its snapshot
  but never re-arms that event. Unregister and register a fresh event to arm
  again. All `SECDEBUG_PERF_PENDING_OFFSET` values are forbidden.
- KernelPatch `lkm/` is unsupported. KernelPatch `.kpm.event` dispatch is disabled
  by this host profile (`-EOPNOTSUPP`); do not apply it to an installation which
  relies on other event-driven KPMs. KPatch-Next has no such dispatch API.

## Non-negotiable host constraints

Host fixes for the two pinned public commits live in
[`host_patches/`](host_patches/README.md). `apply_checked.sh` runs
`git apply --check` against those exact trees. `--verify` additionally checks
the complete approved patched kernel source against Git blobs, not just HEAD
or a marker string. That is not a device or KASAN proof. See [`SECURITY.md`](SECURITY.md) for deployment checks.

1. `module_control0` must pass a **private immutable** argument buffer for
   every in-flight control call, never overwrite a module-global `ctl_args`.
2. Loader must hold one well-defined outer RCU read section on entry; KPM
   must be permitted to drop/restore it around sleeping operations.
3. Host must stop new module calls, invoke exit outside blocking-incompatible
   RCU, wait in-flight control/overflow callbacks and RCU grace periods **before
   freeing executable text**. Audit list mutation and concurrent unload too.
4. Loading/control/module-info paths must never log tokens or decoded/Base64
   payloads. Rotate any key which may already appear in kmsg/pstore.

**Never hot-unload from an unverified loader.** Restarting a test device is
safer than attempting unsupported KPM teardown.

## Files / tests

```text
src/                  KPM core, memory, pinned-mm sessions, perf HWBP
include/              protocol + KPM ABI header
client/               C SDK and example smoke-test client
tests/                ABI/layout, SDK protocol + fake-mm state-machine tests
scripts/              KPM undefined-symbol check, stub compilation, sanitizers
host_patches/         host source REFERENCE patches and checked installer
.github/workflows/     userspace+stub and sanitizer CI
```

On a normal Linux host, **without any loader or device**, run:

```bash
make check        # SDK/module failure injection + build/host regressions + ABI
make check-stub   # AArch64 object compilation and partial link, FAKE headers
make sanitize     # ASan + UBSan on host-executable tests (needs clang)
make ubsan CC=gcc # UBSan-only alternative; does not replace ASan
make client       # build CLI example
make package      # create clean source ZIP, keeping executable shell permissions
```

`make package` excludes `.git`/`build`/`dist` and keeps script execute bits
(stubs also call scripts via `sh`). The AArch64 stub checks **C syntax/codegen
only** — a real audited KernelPatch tree is required for `.kpm`, and only an
ARM64 device can exercise perf/RCU.

### KPM build (only after verifying host contract)

Tools: GNU make >= 4.3, `clang`, `ld.lld`, Python >= 3.10,
binutils `readelf` or `llvm-readelf`, and a pinned source checkout with the
reviewed host fixes applied, matching your exact target loader.

```bash
make KP_DIR=/absolute/path/to/audited/KernelPatch \
     HOST_COMMIT=<full-40-character-git-commit> \
     TARGET_PAGE_SHIFT=12 \
     SECDEBUG_FOLL_FORCE=0x10 \
     HOST_CONTRACT_ACK=I_ACKNOWLEDGE_VERIFIED_HOST
```

`SECDEBUG_FOLL_FORCE` must be the target kernel's `FOLL_FORCE` value, or `0`
when that header was not checked. Do not infer it from `kver`.
`SECDEBUG_PERF_PENDING_OFFSET` is prohibited, including zero or an apparently
aligned offset; the build gate AND a C preprocessor error reject it. The page
shift and flag above are **examples, not a claim** about your device. KPM C flags include
`-mgeneral-regs-only` so Clang `-O2` does not emit NEON in the module.

**Optional CPU tune:** default `KPM_TUNE=generic` (`-mcpu=generic -O2`).
For a benchmarked CPU you may pass e.g. `KPM_TUNE=cortex-a78` (`-mtune=…` only;
safety flags stay). Big/little phones may regress on the other cluster; `-O3`/LTO/
`-mcpu=native` are off. Probe with `make check-stub KPM_TUNE=cortex-a78` — the
tune is in the config fingerprint and forces a full KPM rebuild when changed.

This command intentionally **fails** when the contract acknowledgement,
supported git commit, complete approved host patch, page size, or `FOLL_FORCE`
setting is missing. Only the two pinned commits in `host_patches/hosts.json`
are supported. Modified or additional kernel source/header files are refused. Build
generates `build/secdebug.kpm` and `build/BUILD-METADATA.txt` if host headers,
linking and symbol validation all succeed. Build-time checks do NOT certify
runtime compatibility. Review `SECURITY.md` before installing.

`build/build-config.json` records compiler/linker, flags, host commit, patch
hash and verified kernel-source hash. Changing an accepted parameter invalidates
KPM objects; unchanged configs keep object mtimes. Link/symbol checks use a temp
file; failures remove final outputs. Do not share one `BUILD_DIR` across make
processes.

## Load and SDK usage

Supply a randomly generated 16-hex-digit nonzero token as module load args;
use the same `uint64_t` in the SDK context. No token, key, base64 request or
target data should enter public logs or CI artifacts.

The sample CLI uses environment variables rather than argv to avoid a common
shell-history leak. This is **not** a strong protection for process secrets;
environment variables can still be inspected by sufficiently privileged code:

```bash
export SECDEBUG_AUTH_TOKEN=0123456789abcdef
# Default safe mode: requires KPatch-Next, root hello (no superkey pathname).
./build/client/test_secdebug
```

KernelPatch legacy mode is **disabled** in normal SDK builds. If a reviewed
loader fork still needs it, an application build must explicitly define
`SECDEBUG_ALLOW_LEGACY_TRUNCATE_SYSCALL=1`; the pre-call `stat()` check is
**not** a TOCTOU fix. Prefer a host-provided safe entry instead.

### SDK results and sessions

- `secdebug_read_mem` returns a byte count when no operation reports an
  error; a short target read may return a short count. A later chunk error
  returns that negative errno. Pass a
  non-NULL `bytes_done` to learn the confirmed prefix. Compare the return
  value with the requested length before treating the buffer as complete.
- `secdebug_write_mem` returns `-EINPROGRESS` when a write or session OPEN
  receipt was lost (`-EFAULT` from the syscall, or a corrupt response).
  Definite errors such as `-EACCES`, `-EPERM`, `-EBUSY` and `-ENOMEM` remain
  negative if no chunk completed; after earlier confirmed chunks, a definite
  error returns that positive partial byte count. Never blindly retry
  `-EINPROGRESS`, a completed prefix, or an entire successful write.
- Each raw command transfers up to 512 bytes. SDK automatically opens one
  stable-mm session for larger operations. Sessions belong to the *calling
  thread*; operation and cleanup happen in that same thread. Older modules
  without session commands fail closed for large transfers.
- The SDK retains a handle if CLOSE fails, retries at most three times, and
  blocks new memory transfers until cleanup succeeds. The data return value
  remains separate: after read/write check `secdebug_client_cleanup_error()`;
  retry `secdebug_client_cleanup()` on the opening thread if it is nonzero.
  Never repeat a completed write merely because cleanup failed. A lost CLOSE
  receipt is safely retried; a subsequent `-ENOENT` confirms cleanup.
- SDK consumers must compile against the supplied header: `struct
  secdebug_client` contains private cleanup state and
  `secdebug_client_destroy()` returns an error code. Use one
  context per thread where possible. Concurrent/reentrant memory and cleanup
  operations on a shared context return `-EBUSY`. Do not copy, reinitialize,
  or free a live context with unresolved cleanup.
- A target might exit while its old `mm_struct` is pinned. Subsequent chunks
  continue to refer to **that old mm**, never a new process with the same PID.
- `SECDEBUG_CAP_HW_BREAK` / `SECDEBUG_CAP_HW_WATCH` mean the perf helpers and
  `init_pid_ns` resolved. They do **not** mean a breakpoint was armed or that
  a hit was observed. If creating an event fails with `-ENODEV`, `-ENOSYS`,
  `-EOPNOTSUPP` or `-ENOENT`, those bits are cleared. Clearing never re-arms
  a hit event; unregister and register anew. Session and breakpoint reclaim
  uses the init pid namespace, not the caller's.
  **Opt-in hardware-hit check (real ARM64 device only):** set
  `SECDEBUG_HWBP_SMOKE=1` and run the sample CLI on a disposable, authorized
  device. It registers a write watchpoint on its own stack value, writes it,
  polls for a hit with a nonzero PC, and unregisters. This is not run by
  `make check`, and does not certify concurrent unload, every PMU, or re-arm.
- After use, call `secdebug_client_destroy(&client)` and check for zero. On
  cleanup failure it preserves the handle and credentials so the opening
  thread can retry. Only success scrubs the context. Init/destroy require that
  no other SDK operation is in flight; do not put credentials in logs/dumps.

Protocol and ABI details are in `include/secdebug_proto.h` and
`include/secdebug_perf_abi.h`. Source licensing: KPM GPL-2.0-only, userspace
Apache-2.0, shared protocol headers GPL-2.0-only OR Apache-2.0; see `LICENSES/`
and `THIRD_PARTY_NOTICES.md`.
