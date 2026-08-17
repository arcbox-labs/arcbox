# arcbox-tap-net

The Linux TAP guest network of the sandbox stack — the adapter of
[`arcbox-vm-driver`](../arcbox-vm-driver)'s `GuestNetwork` port that runs
inside the ArcBox System VM (and on a bare Linux node). One `TapNetwork`
owns:

- an IPv4 pool (`cidr` + `gateway`; addresses `.2` onwards, deterministic
  TAP name `vmtap<c>-<d>` and MAC per VM id);
- per VM, a persistent TAP on an isolated point-to-point link, created
  over `/dev/net/tun` and addressed through `ioctl`;
- the identity-invariant translation (CORE-81): every guest boots on the
  fixed `169.254.100.2/30` behind `169.254.100.1` (`invariant`), and the
  pool address is applied host-side per TAP — as two eBPF TCX programs
  (`bpf/sandbox_nat.bpf.o`, the default) or as the iptables rule set
  behind the `PacketFilter` seam (`IptablesLegacy` is the reference; a
  stock distro on the nft backend supplies its own);
- the hand-encoded rtnetlink requests the invariant scheme needs (fwmark
  fib rule, per-sandbox table route, onlink gateway route) — pure
  encoders, unit-tested;
- the durable quarantine ledger and the startup-cleanup token protocol
  that keep a released address out of the pool until the host confirms
  its forwarding state is gone. VM ids are the port's `VmId`
  (`[A-Za-z0-9._-]`, at most 64 bytes, not `.`/`..`), checked at `reserve`
  and on every ledger write and load, so whatever is reserved can be
  quarantined and every entry is one `NetworkReconcile` can list and
  finalize.

It moved here from `arcbox-vm/src/network` (vm-stack-redesign R2a,
D-VM6). `arcbox_vm::network` re-exports the crate and `NetworkManager` is
an alias of `TapNetwork` until R2b moves the sandbox manager onto the
port; `invariant::GUEST_IP` and friends stay exported for the guest
agent's port-forward and init code.

## The `GuestNetwork` mapping

| port | inherent method |
|------|-----------------|
| `reserve(vm, policy)` | `reserve(vm)` — `Isolated` and `Nat` are the same TAP shape (egress policy is the composer's netfilter business); `Bridged` is refused |
| `activate(lease, mode)` | `activate(alloc, mode)` — returns `NicSpec { id: "eth0", mac, Tap { name } }` |
| `quarantine(lease)` | `quarantine_checked(vm, alloc)` |
| `release(lease)` | `release_checked(alloc)` |
| `identity(lease)` | the invariant link for every fresh boot and invariant restore; the pool address once the TAP was activated as `LegacySnapshot` — the resolver is the gateway either way |
| `reconcile()` | `Some(self)` while a quarantine ledger is kept |
| `NetworkReconcile::*` | `pending_quarantines`, `validate_quarantine` / `finalize_quarantine`, and the `*_startup_cleanup` set |

The `NetworkLease` carries VM, address, prefix, gateway, MAC and cleanup
token; the allocation is rebuilt from it (TAP name from the address,
resolvers from the network), so there is no side table to keep. Errors:
`TapNetError` maps variant for variant into `arcbox_vm::VmmError`
(`WrongState` / `Unavailable` keep their 412 / 503 meaning) and into the
port's `Error` (`Io` kept, the rest `Network` with the classification in
the text).

## Usage

```rust
use std::sync::Arc;
use arcbox_tap_net::{AttachMode, Datapath, IptablesLegacy, TapNetwork};

let network = TapNetwork::with_quarantine_dir(
    "172.20.0.0/16", "172.20.0.1", vec![],
    data_dir.join("sandbox-network-quarantine"),
    Datapath::default(),                 // eBPF, iptables fallback
    Arc::new(IptablesLegacy::default()),
)?;
let allocation = network.reserve("box-1")?;          // journal it, then:
network.activate(&allocation, AttachMode::Invariant)?;
// ... boot the VM on `allocation.tap_name` ...
network.quarantine_checked("box-1", &allocation)?;   // address held until the host finalizes
```

Through the port the same lifecycle is `reserve(&vm, policy)` →
`activate(&lease, mode)` → `quarantine(lease)`, and the ledger's protocol
is `network.reconcile()`.

## Requirements and tests

Everything that touches the kernel is Linux-only and needs `CAP_NET_ADMIN`
(root in practice): TAP creation, netlink, `/sbin/iptables`, and the TCX
attach (`BPF_SYSCALL`, `BPF_JIT_ALWAYS_ON`, `NET_XGRESS`; the loader
attaches only through TCX links and never falls back to netlink tc). The
pool, the encoders, the ledger, and the port mapping compile and are
unit-tested on every host.

```bash
cargo test -p arcbox-tap-net                     # unit + bpf-object guards, no root
sudo -E cargo test -p arcbox-tap-net --test integration   # real TAPs (skips unless root)
```

`.github/workflows/test-vm-linux.yml` runs both.

## The eBPF object

`bpf/sandbox_nat.bpf.o` is compiled offline from `bpf/sandbox_nat.bpf.c`
by `cargo xtask dev bpf` (clang with the BPF backend) and committed
together with two sha256 sidecars, one for the source and one for the
object. `tests/bpf_object.rs` pins the pairing — a source edit without a
rebuild, or a rebuilt-but-not-recommitted object, fails there — and the
ELF shape the loader depends on (little-endian 64-bit `EM_BPF`, the
`sandbox_nat_ingress` / `sandbox_nat_egress` programs, the `SANDBOX_NAT` /
`SANDBOX_NAT_POOL` maps, a GPL-compatible license string). The object is
`include_bytes!`-embedded, loaded once per process on the first invariant
activation; TCX links are file descriptors, so a crashed process leaves no
kernel state behind beyond the TAP itself.

Design: company repo `engineering/arcbox/architecture/vm-stack-redesign.md`
("`GuestNetwork` and `arcbox-tap-net`", D-VM6, R2).
