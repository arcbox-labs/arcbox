# arcbox-fc-driver

The Firecracker adapter for the [`arcbox-vm-driver`](../arcbox-vm-driver)
port. It turns a `VmSpec` into Firecracker API payloads and (under the
jailer) chroot-relative paths, owns the `firecracker`/`jailer` process,
and serves the port's capabilities over it: `Vsock` and `VsockListen`
through the hybrid-vsock Unix socket, `Checkpoint` through
pause → snapshot → resume, `Prepare` for warm pools that spawn ahead of a
boot, `Staging` for bringing that boot's files into the jail before it — and for
taking one back out afterwards, from the prepared VM or from a handle —
`Adopt`/`Detach` for VMs that outlive the process that booted them, and
`Adopt::discard_area` for the jail of one that did not.

Nothing above this crate names Firecracker except the composition root
that picks it. The sandbox manager (`arcbox-computer-runtime`) reaches
every VM through `dyn VmDriver`, jail layout included; the only other
things this crate depends on are the port and `fc-sdk`: no snapshot
catalog, no engine, no orchestrator.

## Layout

| Module | Owns |
|--------|------|
| `config` | `FcDriverConfig` — binaries, seccomp, log level, API-socket wait, jailer resource limits |
| `error` | `FcError`, folded into the port's `Error::Driver { driver: "firecracker", .. }` |
| `render` | `VmLayout` (every path Firecracker sees, and the jailer's relativity), `VmSpec` → `FcPlan`, `RestoreSpec` → `FcRestorePlan` |
| `jail` | chroot layout, the id budget the longest jail socket leaves, and staging (link-or-copy, copy, block-device node, move-in), `apply` for a rendered plan, `move_file` out of a jail |
| `spawn` | `firecracker` / `jailer` process spawn from a `SpawnPlan` |
| `vsock` | the `CONNECT <port>` handshake and the `{uds}_{port}` listener |
| `process` | the process guard: waiter task, exit watch + event, kill / wait, detach |
| `api` | pause, resume, snapshot, ctrl-alt-del, describe, vm-config over the raw client |
| `listener` | the port's `VsockListener` over a `{uds}_{port}` socket |
| `discover` | finding a Firecracker that outlived its booter: the recorded pid and any `/proc` candidate, held to the same `--id` / `--api-sock` / jail-root test |
| `adopt` | rebuilding a handle over what `discover` found: a bounded API reconnect for the full `FcHandle`, else `FcProcessHandle` over the process alone |
| `staging` | `JailStaging: Staging` — one VM's jail as its staging area, built from a `VmLayout` so both grips on the VM reach the same one |
| `prepared` | `FcPrepared: PreparedVm + VsockListen` — a spawned VMM waiting for a spec, and the jail its files are staged into |
| `handle` | `FcHandle: VmHandle + Vsock + VsockListen + Checkpoint + Detach`; `FcProcessHandle: VmHandle + Detach`, over a VMM whose API is unreachable. Both offer `Staging`: the area is named by the layout, and asks the VMM nothing |
| `driver` | `FcDriver: VmDriver + Prepare + Adopt` |

## Usage

```rust
use std::sync::Arc;
use arcbox_fc_driver::{FcDriver, FcDriverConfig};
use arcbox_vm_driver::VmDriver;

let mut config = FcDriverConfig::new("/usr/bin/firecracker");
config.jailer_binary = Some("/usr/bin/jailer".into());
let driver: Arc<dyn VmDriver> = Arc::new(FcDriver::new(config));
let vm = driver.boot(spec, &runtime_dir).await?;   // Box<dyn VmHandle>
```

The checkpoint format is `firecracker/v1`: a directory holding `vmstate`
and `mem`. Restoring anything else fails with `Error::ForeignCheckpoint`.

**Checkpoints are a jailer-mode capability.** `PUT /snapshot/load` reopens
every drive at the path the checkpoint recorded, with no override, so a
restored VM can be given other disks only where that path is private to
it — inside a per-VM chroot, where the driver stages this restore's disks
under the recorded names. Without a jail the recorded paths are the source
VM's own host paths, shared with it (the sandbox manager refuses direct-mode
restores for the same reason). So `capabilities().checkpoint` is `true`
only with a jailer binary configured, `FcHandle::checkpoint()` is `Some`
only for a VM under `IsolationSpec::Jailer`, and a `RestoreSpec` without
jailer isolation is refused with `Error::InvalidSpec` — direct mode
advertises `checkpoint: false`. A restore loads the image with the guest
frozen, points every drive at the path *this* restore gives it
(`PATCH /drives/{id}`, skipped where the image already names it — a
snapshot records the disk paths of the VM it was taken from, never the fresh
copy-on-write device a restore runs on), and only then resumes. The load
must find every recorded name first: a staged disk lands at `/{id}.ext4`,
the name a checkpoint of this driver records, and a disk that already sits
in the jail under another name is given that name too for the load (a hard
link, or a device node or copy) and loses it once the drive points at the
disk itself.

**Adopt never fails on the API.** `Adopt::adopt` finds the VMM by its
process — the recorded pid when it is still a Firecracker the record
names, else a `/proc` scan by `--id`, `--api-sock`, or jail root
(`discover`) — and `Ok(None)` means nothing survived. A found process is
always adopted: the exit prober goes over the verified pid first, then the
API is reconnected best-effort with a short bound (`adopt::API_TIMEOUT`,
2 s for `GET /` and `GET /vm/config`). A VMM that answers yields the full
`FcHandle` — vsock at the path Firecracker reports, checkpoint under a
jail, `Quiesced` if it was paused. One whose socket is missing, wedged, or
closes yields an `FcProcessHandle`: `id`/`record`/`state`/`events`,
`shutdown` (`Kill` is SIGKILL plus the bounded reap; `Graceful` degrades to
it, since the ctrl-alt-del that would ask the guest is an API call), and
`detach`; every API-backed accessor is `None`. The record either handle
reports names the process that was verified, not the one the caller
recorded. This is what lets the sandbox manager's restart sweep
`shutdown(Kill)` an orphan whose control socket died with its booter — the
blind SIGKILL by pid it replaced had no API dependency, and neither does
this.

## Path rules

- **No isolation**: every spec path is passed to Firecracker verbatim; the
  API socket is `{runtime_dir}/firecracker.sock`, the log and metrics files
  `{runtime_dir}/firecracker.{log,metrics}` (pre-created), the vsock socket
  `{runtime_dir}/firecracker.vsock`.
- **Jailer**: the jail is `{chroot_base}/{firecracker binary name}/{id}/root`
  and Firecracker sees only paths inside it. A host path already under the
  jail is passed as `/` + its relative part; anything else is staged first:
  the kernel to `/vmlinux` (hard link when the jail runs as root, a chowned
  copy otherwise), a disk `id` to `/{id}.ext4` (a device node for a block
  device, a copy for a writable file, link-or-copy for a read-only one), a
  checkpoint to `/snapshots/{image dir name}/{vmstate,mem}`. The API socket
  is `{jail}/run/firecracker.socket`, the vsock socket
  `/run/firecracker.vsock` inside and `{jail}/run/firecracker.vsock` outside.

  `Staging` stages the same files under the same names ahead of the boot
  that renders them, which is how a warm pool pays for a checkpoint's
  memory file before a restore asks for it; `unstage_disk` takes a disk
  back out of the jail, so it survives the VM. It is reached from either
  grip on a VM — the prepared VM, and the handle, which is all a VM this
  driver adopted has. Without a jail every staging verb is the identity.

  The jail itself goes with whichever grip owns the VMM: `FcPrepared::discard`
  for a VM this process spawned, `shutdown` for one it adopted, and
  `Adopt::discard_area` for one that is gone and left neither.

  Those sockets are also what bounds a VM id: each must fit AF_UNIX's 107
  bytes, so `id_budget` answers with what the chroot base and binary name
  leave for the longest of them — the guest dial-out listener,
  `{jail}/run/firecracker.vsock_{port}`, not the API socket — and `0` for
  a base that spends it all, since the alternative is ids that look fine
  and never connect.

A VM `id` and a disk `id` must each be a plain name: the first is the jail's
directory, the second a device id in the API URL and the file the disk is
staged as. Anything that could name a path outside the jail — `.`, `..`, a
separator — is refused. The VM id is held to less than that, and by the
port rather than here: it is also Firecracker's `--id`, which takes
`[A-Za-z0-9-]` and panics on anything else, so a `.` or a `_` never
reaches this layout at all. A disk id keeps the wider path-safe alphabet,
never being handed to the VMM as an identity.

Console files and sockets, virtiofs shares, and the balloon are refused
with `Error::InvalidSpec` — the driver claims none of those capabilities.

## Running the contract

`tests/contract.rs` runs every check of the port's `driver_contract!`
against a real Firecracker, directly and — when `FC_JAILER` is set —
under the jailer as uid/gid 0 (production's shape). The tests are
`#[ignore]`d and skip themselves without their assets; they need
`/dev/kvm`, and the jailer needs root:

```bash
FC_BINARY=/tmp/fc-assets/firecracker FC_JAILER=/tmp/fc-assets/jailer \
FC_KERNEL=/tmp/fc-assets/vmlinux FC_ROOTFS=/tmp/fc-assets/rootfs.ext4 \
sudo -E cargo test --test contract -p arcbox-fc-driver -- --include-ignored --test-threads=1
```

`FC_ROOTFS` must carry `vm-agent` at `/sbin/vm-agent` (the harness boots
`init=/sbin/vm-agent`, dial-polls its exec port to know the guest is up,
and relies on its READY dial-out for the prepared-listener check). The
`e2e` job of `.github/workflows/test-vm-linux.yml` runs exactly this after
the sandbox manager's own e2e suite, on the assets `firecracker.sh
install` and the S3 CI bucket put under `/tmp/fc-assets`.

Design: company repo `engineering/arcbox/architecture/vm-stack-redesign.md`
(Adapters → `virt/arcbox-fc-driver`; D-VM1, D-VM9).
