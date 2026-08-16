# arcbox-fc-driver

The Firecracker adapter for the [`arcbox-vm-driver`](../arcbox-vm-driver)
port. It turns a `VmSpec` into Firecracker API payloads and (under the
jailer) chroot-relative paths, owns the `firecracker`/`jailer` process,
and serves the port's capabilities over it: `Vsock` and `VsockListen`
through the hybrid-vsock Unix socket, `Checkpoint` through
pause → snapshot → resume, `Prepare` for warm pools that spawn ahead of a
boot, `Adopt`/`Detach` for VMs that outlive the process that booted them.

Nothing above this crate names Firecracker. The sandbox manager
(`arcbox-vm`) reaches it through `dyn VmDriver` — during the R1 migration
it also calls the moved staging helpers directly, an edge R3 removes — and
the only other things it depends on are the port and `fc-sdk`: no snapshot
catalog, no engine, no orchestrator.

## Layout

| Module | Owns |
|--------|------|
| `config` | `FcDriverConfig` — binaries, seccomp, log level, API-socket wait, jailer resource limits |
| `error` | `FcError`, folded into the port's `Error::Driver { driver: "firecracker", .. }` |
| `render` | `VmLayout` (every path Firecracker sees, and the jailer's relativity), `VmSpec` → `FcPlan`, `RestoreSpec` → `FcRestorePlan` |
| `jail` | chroot layout and staging (link-or-copy, copy, block-device node), `apply` for a rendered plan, `move_file` out of a jail |
| `spawn` | `firecracker` / `jailer` process spawn from a `SpawnPlan` |
| `vsock` | the `CONNECT <port>` handshake and the `{uds}_{port}` listener |
| `process` | the process guard: waiter task, exit watch + event, kill / wait, detach |
| `api` | pause, resume, snapshot, ctrl-alt-del, describe, vm-config over the raw client |
| `listener` | the port's `VsockListener` over a `{uds}_{port}` socket |
| `discover` | finding a Firecracker that outlived its booter (recorded pid, `/proc` scan) |
| `prepared` | `FcPrepared: PreparedVm` — a spawned VMM waiting for a spec |
| `handle` | `FcHandle: VmHandle + Vsock + VsockListen + Checkpoint + Detach` |
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
