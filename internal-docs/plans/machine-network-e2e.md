# Machine networking E2E

`tests/e2e/tests/machine_network.rs` — the first exercise of a **Machine's
actual network plane**. The lifecycle test (`machine.rs`) only asserts an
agent-reported IP over vsock; it never drives a packet. This runs real
traffic from inside a Machine over the `machines.exec` vsock channel (the
Machine's `docker exec`).

```
cargo test -p arcbox-e2e --test machine_network -- --ignored --nocapture
```

Needs internet (create pulls alpine from the live `image.arcboxcdn.com`
mirror) and a guest `arcbox-agent` (musl cross-build, or the installed
app's agent staged by newest-mtime).

## Datapath (source-verified 2026-07-21)

A Machine's **primary NIC is the same socketpair userspace netstack +
TcpBridge as the System VM's** (`virt/arcbox-vmm/src/vmm/darwin.rs` —
`gateway=10.0.2.1, guest=10.0.2.2`, DHCP + `DnsForwarder` at the gateway).
Egress is pure in-process host-socket proxying
(`common/arcbox-proxy/src/egress/mod.rs`) — **no privileged helper, no host
route, no `/etc/resolver`**. The System VM's helper-installed `172.16/12`
route (`route_reconciler`) is System-VM-only and was never wired to
Machines (`app/arcbox-core/src/machine.rs` never calls it). So Machine
networking runs fully in the isolated e2e daemon.

The agent channel is vsock, independent of the network plane
(`MachineManager::connect_agent`), which is why `exec` drives in-Machine
commands even while testing the network.

## Scenarios (one Machine, one boot)

| # | What | Assertion |
|---|---|---|
| M1 | egress TCP | `wget` a host-local origin at `10.0.2.1:<port>`; `wc -c` byte-exact — first proof a Machine reaches the network *(implemented)* |
| M2 | DNS | `nslookup host.docker.internal` / `gateway.docker.internal` resolve to `10.0.2.1` via the in-VMM `DnsForwarder` *(implemented)* |
| M3 | egress volume | 16 MiB download, byte-exact and bounded *(implemented)* |
| M4 | metadata | `inspect` reports gateway `10.0.2.1` and it as a DNS server; IP is a valid routable IPv4 *(implemented)* |
| M5 | SSH contract | `ssh_info` is still `Unimplemented` — pins the gap so a future SSH feature trips this test *(implemented)* |

## Not covered — by architecture, not omission

Documented here because the architecture, not the harness, is the reason;
no active test (would be flaky/meaningless today):

- **Machine ↔ Machine, Machine → container, Machine → System VM**: each VM
  gets its own private per-process socketpair netstack; the second (vmnet
  bridge) NIC is never brought up guest-side for Machines
  (`guest/arcbox-agent/src/init.rs` `machine_init()` does DHCP on the
  primary NIC only). Two Machines can even both be `10.0.2.2` — there is no
  shared segment and no cross-VM route. When cross-machine networking is
  added, M5's pattern (assert-the-gap-then-grow) is the template.
- **host → Machine inbound / SSH**: `ssh_info` is unimplemented and
  `InboundListenerManager` is only ever wired to the System VM
  (`app/arcbox-docker/src/handlers/container/mod.rs`), never to a Machine.
  M5 pins this.

## Finding (2026-07-21): reported IP ≠ datapath IP on a fake-IP host

The datapath logs `gateway=10.0.2.1, guest=10.0.2.2`, and egress/DNS work
through it (M1–M3 pass), but `inspect().network.ip_address` came back as
`198.18.11.51` — the Surge/Clash fake-IP range this host runs, not the
datapath's `10.0.2.2`. `select_routable_ip`
(`app/arcbox-core/src/machine.rs`) picks from the agent's enumerated
addresses and chose a non-datapath address here. The desktop UI shows this
field as "the machine's IP", so a user on such a host sees a bogus address.
M4 asserts the robust facts (gateway, DNS, valid IPv4) and WARN-logs the
mismatch rather than gating on it (host-environment-tangled). Worth
reproducing on a clean, non-fake-IP host to decide whether
`select_routable_ip` should prefer the datapath subnet.
