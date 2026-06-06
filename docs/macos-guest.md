# macOS Guest VMs

> Status: implemented on branch `feat/macos-guest-vz` (PLAN.md slices 1–6). The macOS
> VM stack (install → clone → boot) is verified on real Apple Silicon via the
> `arcbox-vz` examples — see "Verification status" below.

ArcBox can run **disposable macOS guests** on Apple Silicon: install macOS once from an
IPSW into a reusable base image, then copy-on-write clone that image to boot clean,
throwaway macOS VMs in seconds — the same "clone, use, discard" model ArcBox provides
for Linux, extended to macOS.

macOS guests run through `arcbox-vz` (Virtualization.framework) **only** — Apple permits
booting macOS solely through Virtualization.framework, never through the custom HV VMM —
and they are a **Machine-tier** capability (no Container or Sandbox tier).

## Requirements

- Apple Silicon (M1+). Intel/T2 is unsupported.
- Host macOS 13+ (save/restore "instant start" needs 14+).
- The guest macOS version is constrained by the host macOS version.
- Data directory on an **APFS** volume (copy-on-write clone needs `clonefile`).
- Developer ID signing for the daemon (`com.apple.security.virtualization`; see
  `CLAUDE.md` → macOS Development). No additional entitlement is needed for install.
- **At most 2 macOS guests per host** (Apple license cap) — enforced with a clear error.

## Startup Path Shape

The CLI → gRPC → daemon "upper half" is shared with Linux machines. At the machine
service it forks on `MachineKind`; the macOS lower half is an independent chain through
`arcbox-vz` into Apple's framework, and never touches `arcbox-vmm` / HV / the vsock
guest agent.

```text
arcbox machine ...                         (CLI, shared)
        │  gRPC
        ▼
app/arcbox-api/src/grpc/machine.rs         (machine service, shared)
        ▼
Runtime.machine_manager()                  (built in daemon init_runtime, shared)
        ▼
   ┌────────── route by guest_os / owning manager ───────────┐
   │ Linux: machine_manager()               │ macOS: mac_machine_manager() │
   ▼                                        ▼
VmManager::start                          macos::MacVm
  → Vmm::new (arcbox-vmm, VmBackend::Hv)     → arcbox-vz: VirtualMachineConfiguration
  → custom HV VMM (darwin_hv/vcpu_loop)         .set_boot_loader(MacOSBootLoader)
  → custom virtio + Linux kernel                .set_platform(MacPlatform{hw,id,aux})
  → ready = vsock guest-agent ping              .add_storage/network/serial/... (reused)
                                                .build() → VirtualMachine
                                              → vm.start() → Virtualization.framework
                                              → ready = VZ state==Running (+ opt. SSH)
```

### macOS sub-paths

1. **One-time install (slow, per base image).** Unlike Linux (direct kernel boot, no
   install), macOS must be restored from an IPSW first:

   ```text
   arcbox macos image pull --ipsw <path|latest>
     → arcbox-vz restore.rs: MacOSRestoreImage → most-featureful requirements
     → temp VM + MacOSInstaller.install (~10-20 min, NSProgress percentage)
     → base template: data_dir/macos/images/<name>/
          { disk.img, aux.img, hwmodel.bin, machine-id.bin, meta.json }
   ```

2. **Per-VM create (fast, CoW).**

   ```text
   arcbox machine create <n> --os macos --image <base>
     → MacImageManager.clone_base: clonefile(disk.img) CoW + copy aux.img  (APFS, seconds)
     → MacMachineManager persists a machine record + the base hardware model
       (a fresh machine identifier is minted at boot, so concurrent clones differ)
   ```

3. **Per-VM start (hot path).**

   ```text
   arcbox machine start <n>
     → MacVm.build → arcbox-vz VirtualMachineConfiguration
          boot_loader = MacOSBootLoader
          platform    = MacPlatform{ hardware_model, machine_id, aux_storage }
          storage     = cloned disk.img        (reused StorageDeviceConfiguration)
          + network / serial / entropy / balloon (reused)
          + VirtioFS directory share for per-VM config injection (reused)
     → vm.start().await  (serial dispatch queue + ObjC completion block -> Rust oneshot)
     → ready = VZ state == Running (+ optional SSH probe); no in-guest ArcBox agent
   ```

Teardown for the disposable loop: `request_stop` (graceful) -> delete the per-VM clone.
`save_state`/`restore_state` (macOS 14+) enable Anka-style instant start later.

### How it differs from the Linux path

- **Driver model.** Linux runs ArcBox's own vcpu loop; macOS hands the
  `VZVirtualMachine` to Apple's framework and drives it via a serial dispatch queue +
  completion blocks (`virt/arcbox-vz/src/vm.rs`).
- **Readiness.** Linux waits on the vsock guest agent; macOS has no in-guest agent —
  readiness is the VZ `Running` state, plus an optional SSH probe for interaction.
- **Provisioning.** Linux boots a kernel directly; macOS adds the one-time IPSW install
  step, after which per-VM provisioning is the fast CoW clone.
- **Recovery.** On daemon restart, persisted macOS machines are reloaded and a stale
  `Running` is corrected to `Stopped`, the same hook as Linux.

## Module Map

| Concern | Location |
| --- | --- |
| macOS boot loader | `virt/arcbox-vz/src/configuration/boot_loader.rs` (`MacOSBootLoader`) |
| macOS platform | `virt/arcbox-vz/src/configuration/platform.rs` (`MacPlatform`) |
| hardware model / machine id / aux storage | `virt/arcbox-vz/src/configuration/mac.rs` |
| restore image + installer | `virt/arcbox-vz/src/restore.rs` |
| VM lifecycle (stop/save/restore) | `virt/arcbox-vz/src/vm.rs` |
| base-image registry + CoW clone | `app/arcbox-core/src/macos/image.rs` (`MacImageManager`) |
| base-image install | `app/arcbox-core/src/macos/install.rs` (`install_from_ipsw`) |
| macOS machine lifecycle | `app/arcbox-core/src/macos/{vm.rs,machine.rs}` (`MacVm`, `MacMachineManager`) |
| daemon wiring | `app/arcbox-core/src/runtime.rs` (`mac_machine_manager()`) |
| daemon gRPC + CLI | `app/arcbox-api/src/grpc/machine.rs`, `app/arcbox-cli/src/commands/{machine,macos}.rs` |

The machine gRPC service routes by `guest_os` (on create) or by which manager owns the
name (start/stop/remove) to `mac_machine_manager()`; there is no shared `MachineKind`
enum — the Linux `MachineManager` and `MacMachineManager` are separate, unified only at
the CLI/gRPC surface. macOS VM operations are `!Send` (ObjC handles + the VM dispatch
queue across await) while tonic requires `Send` handler futures, so the daemon drives
them on a transient current-thread runtime inside `spawn_blocking`.

## Usage

```sh
# 1. Install a base image once from a local IPSW (long-running, ~10–20 min):
arcbox macos image pull sequoia --ipsw /path/to/UniversalMac_xx.ipsw
arcbox macos image ls

# 2. Create a disposable machine by copy-on-write cloning the base (instant):
arcbox machine create ci-1 --os macos --image sequoia --cpus 4 --memory 8192

# 3. Start / list / stop / remove:
arcbox machine start ci-1
arcbox machine ls            # an OS column shows linux | macos
arcbox machine stop ci-1
arcbox machine rm ci-1
arcbox macos image rm sequoia
```

## Verification status

- The macOS VM stack — restore-image load, install from IPSW, copy-on-write clone, and
  boot — is verified end to end on real Apple Silicon via the `arcbox-vz` examples:
  `macos_validate` (Gate A: config validates), `macos_install` (Gate B: install →
  Running), and `macos_clone_boot` (CoW clone of a 64 GiB disk in ~90 µs → boot). Build
  and Developer-ID-sign an example, then run the binary directly (not `cargo run`, which
  re-strips the signature):

  ```sh
  direnv exec . cargo build -p arcbox-vz --example macos_install
  codesign --force --entitlements bundle/arcbox.entitlements \
    -s "Developer ID Application: …" target/debug/examples/macos_install
  ./target/debug/examples/macos_install /path/to/UniversalMac_xx.ipsw
  ```

  Do **not** pass `--options runtime`: devenv/nix-built binaries link a nix-store
  `libiconv` whose Team ID trips hardened-runtime library validation (exit 134).

- The CLI → daemon → manager surface is implemented and clippy-clean, but the daemon
  binary does not link under the devenv/nix toolchain (its SDK lacks the macOS 15+
  `hv_gic_*` Hypervisor.framework symbols `arcbox-hv`'s GIC backend needs — a
  pre-existing limitation unrelated to this feature). A real `arcbox macos image pull`
  → `arcbox machine create --os macos` → `arcbox machine start` run uses the project's
  normal (system-SDK) build path, with the daemon Developer-ID-signed.

## Security model (zero-trust): what's achievable

macOS guests are well suited to untrusted CI (e.g. GitHub Actions runners): the microVM
gives VM-level isolation and the disposable clone is destroyed after each job. There is a
hard ceiling, verified against Apple/Arm primary sources:

- **(A) Don't trust the job / Runner — ACHIEVABLE.** A one-shot clone + a short-lived
  scoped identity + destroy-after-use caps a compromised job's blast radius to one
  throwaway VM. This is the target, and the clone → boot → teardown loop here delivers it.
- **(B) Don't trust the host / platform (in-use confidentiality from the host) — NOT
  ACHIEVABLE on Apple Silicon.** The host VMM owns guest RAM by design (`hv_vm_map`);
  Virtualization.framework exposes no confidential-VM / encrypted-memory /
  guest-attestation API; no Apple chip implements Arm CCA/RME, and there is no
  TDX/SEV-SNP equivalent; the Secure Enclave's memory encryption protects only the SEP;
  and Private Cloud Compute is Apple-internal and relies on attestation + statelessness,
  not in-use memory encryption. Integrity attestation ≠ confidentiality-from-host.

So macOS CI on Apple Silicon can offer (A) but never (B). Builds that genuinely require
confidentiality from the host must run in a TEE on x86 (TDX/SEV-SNP) or Arm (CCA)
hardware — not on a Mac — so **do not advertise "complete zero trust" for macOS CI**.
The complementary building blocks to add at the runner layer are OIDC short-lived
identity (replacing long-lived secrets) and Secure Enclave-held signing keys.

See `PLAN.md` for the full slice-by-slice plan, decision gates, and non-goals.
