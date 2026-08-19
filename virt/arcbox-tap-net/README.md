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
  (`bpf/sandbox_nat.bpf.o`, the default) or as the netfilter rule set
  behind the `PacketFilter` seam (`IptablesLegacy` for the System VM's
  userland, `Nftables` for a stock distro; legacy and nft rulesets are
  mutually invisible, so that is a seam rather than a binary path);
- the hand-encoded rtnetlink requests the invariant scheme needs (fwmark
  fib rule, per-sandbox table route, onlink gateway route) — pure
  encoders, unit-tested;
- the durable quarantine ledger and the startup-cleanup token protocol
  that keep a released address out of the pool until the host confirms
  its forwarding state is gone. VM ids are the port's `VmId`
  (`[A-Za-z0-9._-]`, at most 64 bytes, not `.`/`..`), checked at `reserve`
  and on every ledger write and load, so whatever is reserved can be
  quarantined and every entry is one `NetworkReconcile` can list and
  finalize. A marker that fails those checks is skipped rather than
  fatal — the load runs inside the constructor, and a host that cannot
  build its network reaps nothing — but its address is still withheld
  from the pool for the manager's lifetime, because a guest this build
  cannot name may still be on it.

It moved here from `arcbox-vm/src/network` (vm-stack-redesign R2a,
D-VM6). The sandbox runtime reaches it only through the `GuestNetwork`
port and no longer re-exports it; consumers that need this crate's own
vocabulary — the guest agent's port-forward and init code, for
`invariant::GUEST_IP` and `ExposeTarget` — depend on it directly.
`NetworkManager` is an alias of `TapNetwork`, kept for this crate's own
integration tests.

## The `GuestNetwork` mapping

| port | inherent method |
|------|-----------------|
| `reserve(vm, policy)` | `reserve(vm)` — `Isolated` and `Nat` are the same TAP shape (egress policy is the composer's netfilter business); `Bridged` is refused |
| `activate(lease, mode)` | `activate(alloc, mode)` — returns `NicSpec { id: "eth0", mac, Tap { name } }` |
| `adopt(lease, mode)` | `adopt(vm, alloc, mode)` — the guest is still running: the TAP is left alone, the address goes back out of the pool, and the translation the previous process's exit took with it is re-established (its eBPF TCX links died with that process) |
| `quarantine(lease)` | `quarantine_checked(vm, alloc)` |
| `release(lease)` | `release_checked(alloc)` |
| `identity(lease, mode)` | the invariant link under `Invariant` (every fresh boot and invariant restore), the pool address under `LegacySnapshot` — the resolver is the gateway either way |
| `reconcile()` | `Some(self)` while a quarantine ledger is kept |
| `NetworkReconcile::*` | `pending_quarantines` (an id the port cannot name is an error, not a dropped entry), `validate_quarantine` / `finalize_quarantine`, and the `*_startup_cleanup` set |

The `NetworkLease` carries VM, address, prefix, gateway, MAC and cleanup
token; the allocation is rebuilt from it (TAP name from the address,
resolvers from the network), so there is no side table to keep. Errors:
`TapNetError` maps variant for variant into
`arcbox_computer_runtime::VmmError` (`WrongState` / `Unavailable` keep
their 412 / 503 meaning) and into the port's `Error` (`Unavailable` and
`PreconditionFailed` carry the same two answers; `Io` keeps its shape, the
faults land on `Network`).

## Usage

```rust
use std::sync::Arc;
use arcbox_tap_net::{AttachMode, Datapath, IptablesLegacy, TapNetwork};

let network = TapNetwork::with_quarantine_dir(
    "172.20.0.0/16", "172.20.0.1", vec![],
    data_dir.join("sandbox-network-quarantine"),
    Datapath::default(),                 // eBPF, packet-filter fallback
    Arc::new(IptablesLegacy::default()), // or `Nftables::discover()?`
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
(root in practice): TAP creation, netlink, `/sbin/iptables` or
`/usr/sbin/nft`, and the TCX attach (`BPF_SYSCALL`, `BPF_JIT_ALWAYS_ON`,
`NET_XGRESS`; the loader attaches only through TCX links and never falls
back to netlink tc). The pool, the encoders, the ledger, the rule
renderings, and the port mapping compile and are unit-tested on every
host.

```bash
cargo test -p arcbox-tap-net                     # unit + bpf-object guards, no root
sudo -E cargo test -p arcbox-tap-net --test integration   # real TAPs (skips unless root)
```

The nftables tests move their own thread into a private network namespace
before touching a ruleset, so they never mutate the host's. That also
makes them runnable without a root shell:

```bash
cargo test -p arcbox-tap-net --test integration --no-run   # then, on the built binary:
ARCBOX_REQUIRE_NFT=1 unshare -rn ./target/debug/deps/integration-* nftables
```

`ARCBOX_REQUIRE_NFT=1` turns "nft is missing, skipping" into a failure —
set it wherever nft is known to be installed, so the coverage cannot
evaporate silently.

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
