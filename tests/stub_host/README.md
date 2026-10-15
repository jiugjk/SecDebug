# Compile-only stubs (not a host SDK)

These headers replace host identifiers just enough to catch source syntax,
AArch64 code generation and compiler diagnostics in CI. They DO NOT verify
actual KernelPatch symbol exports, true target ABI, runtime RCU ownership,
perf_event behavior or safe KPM loading. Never build a deployable .kpm with
them; production Makefile requires a real, pinned host checkout.
