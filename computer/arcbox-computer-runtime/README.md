# arcbox-computer-runtime

Guest-side sandbox orchestration: runs **inside** the ArcBox System VM and
manages nested microVMs — one per sandbox — through a `VmDriver`
([`arcbox-vm-driver`](../../virt/arcbox-vm-driver)); the reference driver is
[`arcbox-fc-driver`](../../virt/arcbox-fc-driver), Firecracker.

Do not confuse it with `arcbox-vmm`, which is the **host** VMM that boots
the System VM itself on Virtualization.framework or KVM. Different layer,
different machine.

```
host (macOS)         System VM (Linux)              sandbox (microVM)
arcbox-daemon  ──vsock──►  arcbox-agent        ──vsock──►  vm-agent (PID 1)
  arcbox-vmm             arcbox-computer-runtime             workload
                         arcbox-vm-driver                (arcbox-vm-agent)
                         (arcbox-fc-driver)
                                    └── arcbox-vm-proto ──┘
```

`arcbox-agent` is this crate's only consumer: it owns the `sandbox.v1`
surface and the vsock transport, and calls `SandboxManager` underneath.
There are no service implementations, no tonic, and no daemon here.

The **`vm-agent`** binary that becomes PID 1 *inside* each sandbox is a
separate crate, [`arcbox-vm-agent`](../../virt/arcbox-vm-agent); the wire
vocabulary both sides share — boot parameters, exec-channel and
file-channel frames — is [`arcbox-vm-proto`](../../virt/arcbox-vm-proto). This
crate and the agent each depend on the proto crate and never on each
other, so the agent stays a small static musl binary no matter what the
manager pulls in. `boot_proto` and `file_proto` stay reachable here as
re-exports. `RootfsBuilder` (this crate) stages the binary into every
sandbox rootfs at `/sbin/vm-agent` — OCI/overlay2 → ext4 conversion plus
the default busybox image, with the agent binary source, the cache
directory, and the busybox supplied by the composer as `RootfsPaths`. The
rootfs convention the boot protocol relies on is therefore implemented
once, here.

## Usage

```rust
use std::sync::Arc;
use arcbox_computer_runtime::{NodeEnvironment, RuntimeConfig, SandboxManager, SandboxSpec};

// `environment` is the composer's; see below.
let manager = Arc::new(SandboxManager::new(RuntimeConfig::default(), environment)?);

let (id, ip) = manager
    .create_sandbox(SandboxSpec {
        vcpus: 1,
        memory_mib: 512,
        ..Default::default()
    })
    .await?;
```

`RuntimeConfig` loads from TOML (`RuntimeConfig::from_file`) or is built
programmatically; `[firecracker]`, `[network]`, and `[defaults]` are the
sections that matter, and `[firecracker.jailer]` opts into jailer mode.
See `config/runtime.rs` for the fields.

`[firecracker]` is named for the VMM a deployed `vmm.toml` has always run,
not for anything this crate knows: the keys that configure a VMM adapter
live in the same section and are read by whoever builds it (for the System
VM, `arcbox_agent::config::AdapterConfig`). serde ignores unknown fields,
so one section serves both halves.

What the stack needs from its *environment* — the pieces that differ
between the System VM's busybox userland and a stock distro — is a
separate input, `NodeEnvironment`, and all four members are required.
This crate builds none of them and names no VMM: whoever composes the node
does. For the System VM that is `arcbox_agent::sandbox::node_environment`.

- `driver` — the VMM behind `arcbox_vm_driver::VmDriver`. It must claim
  `Prepare` and `Staging` and offer `vsock`, or `SandboxManager::new`
  refuses it.
- `network` — what the NICs attach to, behind
  `arcbox_vm_driver::net::GuestNetwork`. It must offer `NetworkReconcile`.
- `agent` — how the guest agent is reached, behind
  `agent::GuestAgentFactory`. The reference is the `arcbox-vm-proto`
  client over the driver's vsock, which also decides what the readiness
  gate needs from the driver.
- `cow_manager` — the copy-on-write rootfs manager
  (`arcbox_snapshot::snapshot_cow::CowManager`), built over the composer's
  own loop-device tooling: `BusyboxBlockTools` in the System VM,
  `UtilLinuxBlockTools` on a stock distro, or a consumer's own few dozen
  lines of ioctls.

`testkit::fake_environment` (feature `testkit`) is those four over the
port's fakes, for tests that must not need a VMM.

The sandbox network itself — the IPv4 pool, the per-sandbox TAP, the
invariant NAT (eBPF TCX or netfilter), and the quarantine ledger — is
[`arcbox-tap-net`](../../virt/arcbox-tap-net), the Linux adapter of the
`arcbox-vm-driver` `GuestNetwork` port; the composer builds it, and this
crate does not depend on it at all. Rendering the invariant translation
in the host's netfilter framework is that adapter's own seam
(`arcbox_tap_net::PacketFilter`: `IptablesLegacy` in the System VM,
`Nftables` on a stock distro — legacy and nft rulesets are mutually
invisible), so it is an argument to the network, not a member here.

## Build and test

```bash
cargo test -p arcbox-computer-runtime    # unit + integration, no Firecracker needed
cargo clippy -p arcbox-computer-runtime -- -D warnings
cargo test -p arcbox-tap-net             # the TAP network (root-only TAP tests skip)

# vm-agent, as the release ships it (aarch64 musl; brew install FiloSottile/musl-cross/musl-cross)
cargo build -p arcbox-vm-agent --bin vm-agent --target aarch64-unknown-linux-musl --release
```

`tests/manager_over_fakes.rs` drives the manager's own flows — create,
boot, exec, files, pause, resume, checkpoint, restore, expiry, remove,
adoption — over the driver port's `FakeDriver`/`FakeNetwork` and this
crate's `FakeAgent`, so the whole lifecycle is testable with no KVM, no
root and no Firecracker.

Everything real — TAP creation (`arcbox-tap-net`), boot, checkpoint —
needs Linux with `CAP_NET_ADMIN`, a `firecracker` binary, and (for jailer
mode) root, and so belongs to whoever composes the driver and the network.
That is `arcbox-agent`: its `tests/sandbox_manager_e2e.rs` and
`examples/sandbox-manager-smoke.rs` boot real Firecracker through the
environment its `SandboxService` composes.
`.github/workflows/test-vm-linux.yml` runs the whole ladder on real KVM.

## Jailer mode: every path the FC API sees is chroot-relative

Firecracker `pivot_root`s before it processes any API request, so a
host-absolute path handed to the API resolves inside the chroot and
returns `ENOENT`. Kernel and rootfs are therefore *staged into* the
chroot before boot (`{chroot}/vmlinux`, `{chroot}/rootfs.ext4`) and the
API is given `/vmlinux` and `/rootfs.ext4`. Checkpoints write to
`{chroot}/snapshots/{id}/` and are moved out to the catalog afterwards;
restore copies them back into the *new* sandbox's chroot first.

The same rule is what keeps vsock sockets from colliding: the vmstate
records the UDS as `/run/firecracker.vsock`, which is a different host
path in every sandbox's chroot.

## Data layout

```
{data_dir}/                       # default /var/lib/firecracker-vmm
├── kernels/vmlinux
├── images/*.ext4
├── sandboxes/{id}/               # firecracker.sock, .vsock, .log, .metrics
├── sandbox-network-quarantine/   # arcbox-tap-net's ledger: {id}.json per quarantined address
└── snapshots/{sandbox-id}/{snapshot-id}/
                                  # vmstate, mem, meta.json
```

Under jailer mode the live files instead sit beneath
`{chroot_base_dir}/firecracker/{sandbox-id}/root/` (default
`/srv/jailer`), and the snapshot catalog above is still the durable home.

## License

MIT OR Apache-2.0, inherited from the workspace root.
