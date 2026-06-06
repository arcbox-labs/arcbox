# macOS Guest VMs

> Status: in progress (see `PLAN.md`, branch `feat/macos-guest-vz`). This document is
> the implementation navigation map; the end-user walkthrough is filled in by the
> final slice.

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
   ┌──────────────── fork: match MachineKind ────────────────┐
   │ Linux (existing, untouched)            │ macOS (this work)         │
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
     → MacImageManager.clone_base: libc::clonefile(disk.img)  (APFS CoW, seconds)
     → fresh per-VM aux storage + machine-id (reuse base hwmodel)
     → persist a kind=MacOs machine (Created)
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
| base-image install + CoW clone | `app/arcbox-core/src/macos/image.rs` |
| macOS machine lifecycle | `app/arcbox-core/src/macos/vm.rs` + `MachineKind` |
| daemon/CLI surface | `app/arcbox-api/src/grpc/machine.rs`, `app/arcbox-cli` |

See `PLAN.md` for the full slice-by-slice plan, decision gates, and non-goals.
