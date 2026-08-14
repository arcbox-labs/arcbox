# arcbox-vz Agent Guidance

The VZ (Virtualization.framework) backend. All framework interaction happens
in **ArcBoxVZShim**, a SwiftPM static library under `shim/` compiled and
linked by `build.rs`. There is no ObjC runtime interop in Rust — no
`msg_send`, no hand-rolled blocks, no `objc2` dependency. VZ is the oracle
backend (`virt/AGENTS.md`): keep it boring and correct.

## The C ABI boundary (the one contract that must never drift)

- `shim/Sources/ArcBoxVZShim/Exports.swift` (`@_cdecl`) and `src/shim_ffi.rs`
  (extern declarations) mirror each other in a **normative symbol order** —
  review side by side. A symbol lands in the same PR as its Rust caller.
- The shim is statically linked from this same source tree in the same build,
  so version skew is impossible and there is **no runtime ABI-version
  handshake**. The drift defense is `link_coverage` (a `SYMBOLS` address
  table + `EXPECTED_SYMBOL_COUNT`): a renamed or dropped `@_cdecl` export
  fails `cargo test -p arcbox-vz` at **link time**. Adding a symbol updates
  that table and the count; the C ABI does no signature checking across the
  boundary, so keep the two files' declarations literally aligned.
- Conventions (headers of Errors.swift / shim_ffi.rs are authoritative):
  strings crossing out of Swift are strdup'd and freed by Rust
  (`abx_string_free` / `take_string` / `take_error_string`); handles are
  `Unmanaged` object pointers at +1 released via `abx_object_release`;
  borrows never consume the +1. Callbacks are C fn pointers + ctx, invoked
  **exactly once** from the VM's dispatch queue; the Rust trampoline consumes
  the boxed sender and must clean up undeliverable resources (see
  `vsock_trampoline`'s fd close and `object_trampoline`'s handle release).
- ObjC exceptions are **not caught anywhere**: every throwing VZ call site is
  precondition-guarded (`validate` before build, `can_stop` before stop, fd
  pre-checks). An NSException is a programmer error and must crash loudly
  rather than unwind into Rust frames. Do not add a catch helper.

## Queue affinity lives in Swift

`VZVirtualMachine` and its device objects are queue-affine
(`dispatch_assert_queue` aborts on violation — the historical idle-balloon
crash class). The shim owns the per-VM serial queue inside `ABXVMBox` and
queue-syncs every access; the box types (`ABXVMBox`, `ABXSocketDeviceBox`,
`ABXBalloonBox`, `ABXInstallerBox`) pair object + queue precisely so no raw
VZ object can escape without its queue. Never return a bare VZ object across
the ABI.

## build.rs landmines (each was hit once; comments at the sites)

- Swift invocations go through absolute `/usr/bin/xcrun` with
  `SDKROOT`/`DEVELOPER_DIR` scrubbed: the devenv nix SDK is
  SwiftPM-incompatible and devenv's PATH shadows `xcrun` with xcbuild's fake.
- rustc-driven links ignore static-archive autolink hints: build.rs parses
  `otool -l` and forwards `-lswift*`/`-lobjc` explicitly
  (`swiftCompatibility*` skipped — toolchain-static, irrelevant at the
  macOS 13 floor).
- The Swift runtime stub search path must match the SDK the **final linker**
  uses (SDKROOT when set, toolchain default otherwise); Swift ABI stability
  makes the compiler/linker SDK mix sound.
- The published crate ships `shim/**` (Cargo.toml `include`); verify packaging
  with `cargo package -p arcbox-vz --no-verify` after touching the file set.

## Validation

1. `cargo test -p arcbox-vz` — boundary tests run **unsigned** (entitlement is
   enforced at VM init, not config alloc); keep new smoke tests
   entitlement-free or they break CI.
2. `xcrun swift-format lint --strict --parallel --recursive virt/arcbox-vz/shim`
   (CI-enforced; `swift-format format --in-place` fixes).
3. e2e: `cargo test -p arcbox-e2e --test boot_assets -- --ignored` with
   `ARCBOX_VM_BACKEND=vz`; `backend_matrix` for the VZ↔HV oracle split
   (see `virt/AGENTS.md`).

## Known non-obvious semantics

- Lifecycle ops resolve on VZ completion handlers — there is no state
  polling; do not reintroduce it.
- **Balloon inflation is a host-side no-op** (measured 2026-07-29, macOS
  26.4): Apple neither deallocates nor `madvise`s pages the guest gives up
  — host `phys_footprint` stays at the configured memory size from boot,
  and under host memory pressure the kernel compresses ballooned pages as
  live data. `set_target_memory_size` only resizes what the *guest* may
  use. This is one half of why the idle balloon never engages on macOS
  (the other is HV's Darwin-inert `MADV_DONTNEED` — see `app/AGENTS.md`).
- `VZLinuxRosettaAvailability` raw values are notSupported=0, notInstalled=1,
  installed=2 (a hand-written mapping once had 1 and 2 swapped; the shim now
  returns raw values and Rust maps them — keep them aligned with the SDK).
- `MacAuxiliaryStorage::open` does not verify the file; VZ checks at
  configuration-validate time.
- Installer progress is a Rust-side 2s poll of `fractionCompleted`; the
  installer is constructed on the VM queue (its initializer asserts).
