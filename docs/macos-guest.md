# macOS Guest VMs

> Status: implemented on branch `feat/macos-guest-vz` (PLAN.md slices 1–6). The macOS
> VM stack (install → clone → boot) is verified on real Apple Silicon via the
> `arcbox-vz` examples — see "Verification status" below.

ArcBox can run **disposable macOS guests** on Apple Silicon: pull a pre-baked base
image once from ArcBox's distribution bucket, then copy-on-write clone that image to
boot clean, throwaway macOS VMs in seconds — the same "clone, use, discard" model
ArcBox provides for Linux, extended to macOS. Images are baked and published by the
`macos-runner-image-builder` repo (which also owns the artifact format spec).

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

macOS guests are a separate noun end to end: the `arcbox macos` CLI talks to a dedicated
`MacosService`, distinct from the Linux `arcbox machine` / `MachineService`. The two share
no request types and no routing — only the daemon process, the gRPC socket, and the reused
`arcbox-vz` device configuration. The macOS lower half is an independent chain through
`arcbox-vz` into Apple's framework, and never touches `arcbox-vmm` / HV / the vsock
guest agent.

```text
arcbox machine ...               arcbox macos ...            (CLI, separate nouns)
        │  gRPC                          │  gRPC
        ▼                               ▼
MachineService (machine.rs)      MacosService (macos.rs, macOS-only)
        ▼                               ▼
Runtime.machine_manager()        Runtime.mac_machine_manager()
        ▼                               ▼
VmManager::start                 macos::MacVm
  → Vmm::new (arcbox-vmm, Hv)       → arcbox-vz: VirtualMachineConfiguration
  → custom HV VMM (vcpu_loop)          .set_boot_loader(MacOSBootLoader)
  → custom virtio + Linux kernel       .set_platform(MacPlatform{hw,id,aux})
  → ready = vsock guest-agent ping     .add_storage/network/serial/... (reused)
                                       .build() → VirtualMachine
                                     → vm.start() → Virtualization.framework
                                     → ready = VZ state==Running (+ opt. SSH)
```

### macOS sub-paths

1. **One-time image pull (per base image).** The published artifact is a JSON
   manifest + zstd-compressed disk/aux on ArcBox's `darwin` bucket (see the
   `macos-runner-image-builder` repo for the format spec):

   ```text
   arcbox macos image pull tahoe-base[@version]   (or --manifest <url|path>)
     → resolve via index.json → fetch manifest
     → validate hardware model support BEFORE the multi-GB download
     → stream disk.img.zst: socket → zstd decode → zero-skipping sparse writes
       (compressed bytes never touch disk; SHA-256 verified in flight)
     → staging dir renamed live only after every check passes:
       data_dir/macos/images/<name>/
          { disk.img, aux.img, hwmodel.bin, machine-id.bin, meta.json }
   ```

   The legacy IPSW installer (`install_from_ipsw`, ~15 min `VZMacOSInstaller`
   restore) is retained but unshipped behind the `macos-ipsw-install` feature of
   `arcbox-core`; it is not reachable from the proto/CLI surface.

2. **Per-VM create (fast, CoW).**

   ```text
   arcbox macos create <n> --image <base>
     → MacImageManager.clone_base: clonefile(disk.img) CoW + copy aux.img  (APFS, seconds)
     → MacMachineManager persists a machine record + the base hardware model
       and machine identifier (clones share the base identifier — the one its
       NVRAM was created with; same practice as Tart, proven fine in CI fleets)
   ```

3. **Per-VM start (hot path).**

   ```text
   arcbox macos start <n>
     → MacVm.build → arcbox-vz VirtualMachineConfiguration
          boot_loader = MacOSBootLoader
          platform    = MacPlatform{ hardware_model, machine_id, aux_storage }
          storage     = cloned disk.img        (StorageDeviceConfiguration)
          network     = NAT (vmnet shared)     (DHCP + outbound internet, no host setup)
          graphics    = MacGraphicsDeviceConfiguration
     → vm.start().await  (serial dispatch queue + ObjC completion block -> Rust oneshot)
     → ready = VZ state == Running (+ optional SSH probe); no in-guest ArcBox agent

   Not yet wired: a VirtioFS config share for per-VM provisioning (the channel a
   CI-runner token would arrive through) and serial/entropy/balloon devices.
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
| published index/manifest schema | `app/arcbox-core/src/macos/remote.rs` |
| base-image pull (streaming, sparse) | `app/arcbox-core/src/macos/pull.rs` (`pull_remote`) |
| IPSW install (feature `macos-ipsw-install`, unshipped) | `app/arcbox-core/src/macos/install.rs` (`install_from_ipsw`) |
| macOS machine lifecycle | `app/arcbox-core/src/macos/{vm.rs,machine.rs}` (`MacVm`, `MacMachineManager`) |
| daemon wiring | `app/arcbox-core/src/runtime.rs` (`mac_machine_manager()`) |
| daemon gRPC (macOS-only) | `app/arcbox-api/src/grpc/macos.rs` (`MacosServiceImpl`) |
| CLI | `app/arcbox-cli/src/commands/macos.rs` (`arcbox macos`) |

`MacosService` is a wholly separate gRPC service from the Linux `MachineService`: its own
request types (macOS-shaped, in MiB/GiB, no Linux fields), its own `arcbox macos` CLI noun,
and it delegates straight to `mac_machine_manager()` — no `guest_os` discriminator and no
ownership-probe routing. The service is registered and the CLI noun exists only on Apple
Silicon hosts. macOS VM operations are `!Send` (ObjC handles + the VM dispatch queue across
await) while tonic requires `Send` handler futures, so the daemon drives them on a transient
current-thread runtime inside `spawn_blocking` (`grpc::run_macos_blocking`).

## Usage

```sh
# 1. Pull a published base image (multi-GB download; progress streams to the CLI):
arcbox macos image pull tahoe-base            # latest per the published index
arcbox macos image pull tahoe-base@2026.07.02 # pinned version
arcbox macos image pull --manifest <url|path> # dev: bypass the index
arcbox macos image ls

# 2. Create a disposable guest by copy-on-write cloning the base (instant):
arcbox macos create ci-1 --image tahoe-base --cpus 4 --memory 8192

# 3. Start / list / stop / remove:
arcbox macos start ci-1
arcbox macos ls
arcbox macos stop ci-1
arcbox macos rm ci-1
arcbox macos image rm tahoe-base
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
  → `arcbox macos create` → `arcbox macos start` run uses the project's
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
