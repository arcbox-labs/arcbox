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
use arcbox_computer_runtime::{SandboxManager, SandboxSpec, VmmConfig};

let manager = Arc::new(SandboxManager::new(VmmConfig::default())?);

let (id, ip) = manager
    .create_sandbox(SandboxSpec {
        vcpus: 1,
        memory_mib: 512,
        ..Default::default()
    })
    .await?;
```

`VmmConfig` loads from TOML (`VmmConfig::from_file`) or is built
programmatically; `[firecracker]`, `[network]`, and `[defaults]` are the
sections that matter, and `[firecracker.jailer]` opts into jailer mode.
See `config.rs` for the fields.

What the stack needs from its *environment* — the pieces that differ
between the System VM's busybox userland and a stock distro — is a
separate input, `SandboxEnvironment`. `SandboxManager::new(config)` uses
the reference environment (the System VM's); a composer on another host
overrides the members it owns and calls
`SandboxManager::with_environment(config, env)`. Today that is the VM
driver behind `arcbox_vm_driver::VmDriver` (`None` = the Firecracker
driver built from `[firecracker]`; whatever is supplied must claim the
`Prepare` capability, which the boot and pool flows need), what its NICs
attach to behind `arcbox_vm_driver::net::GuestNetwork` (`None` = the TAP
network from `[network]`), how its guest agent is reached behind
`agent::GuestAgentFactory` (`None` = the `arcbox-vm-proto` client over
the driver's vsock, which also decides what the readiness gate needs from
the driver), the loop-device tooling behind
`arcbox_snapshot::snapshot_cow::BlockTools`
(`BusyboxBlockTools` is the reference, `UtilLinuxBlockTools` the
stock-distro one; an ioctl implementation is a consumer's few dozen
lines) and the netfilter
rendering of the identity-invariant translation behind
`arcbox_tap_net::PacketFilter` (`IptablesLegacy` is the reference,
`Nftables` the stock-distro one — legacy and nft rulesets are mutually
invisible, so this is a seam, not a path); the path seams follow.

The sandbox network itself — the IPv4 pool, the per-sandbox TAP, the
invariant NAT (eBPF TCX or netfilter), and the quarantine ledger — is
[`arcbox-tap-net`](../../virt/arcbox-tap-net), the Linux adapter of the
`arcbox-vm-driver` `GuestNetwork` port; `arcbox_computer_runtime::network`
re-exports it and `NetworkManager` is an alias of its `TapNetwork` until
the manager moves onto the port.

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
