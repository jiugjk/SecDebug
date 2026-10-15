<!-- SPDX-License-Identifier: Apache-2.0 -->
# SecDebug host safety profile

These are source patches, **not a complete host distribution or a device image**.
They apply only to these fixed public baselines:

| Host | Commit | Original module.c Git blob |
|---|---|---|
| bmax121/KernelPatch | f36f3d1377004871f8c964f7cd3276712eeba943 | d6f5f99143e70bca0be57fdf42afffb7ed28e6ab |
| KernelSU-Next/KPatch-Next | 456744b29efb9989445463ab29e368fa59a103c4 | 087cd4bf5f43cc53216a46db409f6ee8fc7576fe |

## Important compatibility restrictions

This is a **SecDebug-focused profile**, not a drop-in generic KPM loader update.
KernelPatch `lkm/` is unsupported. The patches do NOT repair that separate LKM
loader. Instead, SecDebug requires a new host export absent from that backend,
so its normal symbol resolution fails before INIT. Do not bypass this import.

The KernelPatch patch disables `notify_modules_event`, returning `-EOPNOTSUPP`
without taking locks, allocating or calling a KPM. SecDebug has no `.kpm.event`
callback. Other KPMs that need event dispatch are unsupported by this profile;
evaluate this compatibility change BEFORE replacing a shared system's host.
No new event dispatcher or claim of IRQ-safe arbitrary callbacks is provided.

## Apply, verify, rebuild

Use a clean, exact Git checkout. The installer requires Python >= 3.10 and Git.
It never resets or discards a user's changes. Run it with `sh` so a ZIP extractor
which drops executable bits does not prevent its use.

```sh
# Choose ONE matching host. --check makes no source changes.
sh host_patches/apply_checked.sh /path/to/KernelPatch KernelPatch --check
sh host_patches/apply_checked.sh /path/to/KernelPatch KernelPatch --apply
sh host_patches/apply_checked.sh /path/to/KernelPatch KernelPatch --verify

# Alternative host:
sh host_patches/apply_checked.sh /path/to/KPatch-Next KPatch-Next --check
sh host_patches/apply_checked.sh /path/to/KPatch-Next KPatch-Next --apply
sh host_patches/apply_checked.sh /path/to/KPatch-Next KPatch-Next --verify
```

`--check` requires clean baseline bytes, validates all tracked `kernel/` files,
rejects additional source/headers, and runs `git apply --check`. `--apply` does
that check, applies the patch to the working tree, and verifies the result.
`--verify` compares expected patched bytes constructed from Git HEAD against
the actual kernel-source tree; it accepts only the full approved patch, not a
keyword or any nonempty diff. It does not change the caller's Git index.
Tracked symlinks must match their blobs and stay within the checkout. Added
headers/source/linker scripts, including ignored ones, are rejected. Ordinary
object build products are not considered source files.

`hosts.json` contains reviewed patch SHA256s and the baseline identifiers. Keep
HEAD at the baseline while applying this profile in the working tree. A new
commit or another host fork needs an explicit new review/manifest entry; do
not weaken the verifier to accept it. The build tests alter only a temporary
project COPY to test synthetic commits, not the production allow-list.

After verification, rebuild and boot the patched host according to that host's
own build instructions. Then build the KPM using the same verified checkout and
target-specific page size/FOLL_FORCE inputs. Merely building `secdebug.kpm`
against changed headers does **not** update the running host. No ready-to-load
binary or reboot/install command is provided in this source package.

## Lifecycle and copy contract

Each control request owns its argument buffer. Metadata/log output redacts
payloads. Loader list mutation, admission and reference counts use the host's
one-argument `spin_lock_irqsave()` API, paired with irqrestore.

Unload rejects in-flight control callbacks with `-EBUSY`. Otherwise it marks the
module unloading while leaving its name reserved, waits a real RCU grace
period, and calls EXIT outside RCU and locks. Nonzero EXIT is honored without
unlinking or freeing; EXIT must refuse BEFORE destructive teardown. On success
it unlinks under the lock, waits another real grace period, then frees memory.
There is no `schedule()`/`yield` callback-wait loop. Async resources owned by a
module must still be synchronously quiesced by its EXIT implementation.

Both patches fix `rcupdate.h` to call `kf_synchronize_rcu`, not the unbound rude
barrier. `secdebug_host_contract_v1()` advertises `0x53440101` only when the
required RCU and irqsave primitives are available. Missing imports or a zero
runtime contract refuse SecDebug initialization. These checks do not validate
private kernel layout or prove the identity of a running kernel.

The outer list/info wrappers validate actual source lengths and normalize zero,
short or negative copy results to `-EFAULT`. Empty list returns zero while
copying one NUL byte; nonempty list returns copied length. Info returns copied
length including a final NUL; callers need that additional byte. Oversized or
truncated sizes never become stack source lengths.

## Evidence limits

`tests/host_patch_apply.py` uses synthetic preimages constructed from patch
context. `tests/host_lifecycle.py` compiles actual patched helper/control/unload
function bodies against mocks and tests controlled interleavings, refusal and
RCU-call ordering. `tests/host_patch_bounds.py` tests actual list/wrapper bodies.
These do not replace a real checkout application check, full host compilation,
real RCU/IRQ behavior, KASAN/KCSAN or device tests. The CI job is
configured to run real checkout application/verification on the pinned hosts. These checks still cannot establish device runtime safety.
