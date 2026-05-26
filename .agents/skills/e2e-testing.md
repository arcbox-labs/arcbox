---
name: e2e-testing
description: "ArcBox end-to-end testing procedures. Covers VM boot, Docker containers, port forwarding, L3 direct routing, DNS resolution, and common debugging patterns. Trigger on: e2e, end-to-end test, docker run, curl container, integration test, smoke test."
---

# ArcBox E2E Testing

## Quick smoke test

```bash
export DOCKER_HOST=unix://$HOME/.arcbox/run/docker.sock
docker run --rm alpine echo hello           # basic: VM + agent + dockerd
docker run -d -p 8080:80 nginx && curl localhost:8080  # port forwarding
docker run -d --name n nginx && curl http://$(docker inspect n --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')/  # L3 direct
curl http://n.arcbox.local/                 # DNS resolution
```

## Build and deploy

### Always build BOTH binaries

`abctl daemon start` exec()s a separate `arcbox-daemon` binary. Building only
`arcbox-cli` leaves the daemon unchanged — your code edits won't take effect.

```bash
cargo build -p arcbox-cli -p arcbox-daemon
```

### Sign with Developer ID (ad-hoc will NOT work)

```bash
codesign --force --options runtime \
  --entitlements bundle/arcbox.entitlements \
  -s "Developer ID Application: ArcBox, Inc. (422ACSY6Y5)" \
  target/debug/arcbox-daemon

# Ad-hoc (-s -) is killed on launch — restricted entitlements
# require Developer ID + provisioning profile.
# See CONTRIBUTING.md "Code Signing" for setup.
```

### Cross-compile agent (if modified)

```bash
cargo build -p arcbox-agent --target aarch64-unknown-linux-musl --release
cp target/aarch64-unknown-linux-musl/release/arcbox-agent ~/.arcbox/bin/arcbox-agent
```

### Build helper (if modified)

```bash
make build-helper
```

## Clean start procedure

```bash
# 1. Kill everything
pkill -9 -f "arcbox-daemon" 2>/dev/null
pkill -9 -f "com.arcboxlabs.desktop.daemon" 2>/dev/null
sleep 2
rm -f ~/.arcbox/run/*.sock

# 2. Verify port 5553 is free (DNS)
lsof -i :5553  # must be empty — desktop daemon steals this port

# 3. Start helper (separate terminal, needs root)
make run-helper   # listens on /tmp/arcbox-helper.sock

# 4. Start daemon (auto-connects to /tmp/arcbox-helper.sock)
make run-daemon
```

## Expected startup log sequence

```
INFO  Creating VMM: vcpus=4, memory=4096MB
INFO  Added bridge NIC (VZNATNetworkDeviceAttachment) for L3 routing
INFO  Network datapath started (TCP shim + socket proxy mode)
INFO  VMM started
INFO  Learned guest MAC: xx:xx:xx:xx:xx:xx
INFO  DHCP lease acquired  interface="eth0"
INFO  bridge NIC DHCP lease acquired  interface="eth1"
INFO  guest DNS server listening on 0.0.0.0:53
INFO  Agent is ready
INFO  Bridge routing: discovered guest bridge NIC  guest_ip=192.168.65.x
INFO  route installed  subnet="172.16.0.0/12"  gateway=192.168.65.x
INFO  route installed  subnet="10.88.0.0/16"  gateway=192.168.65.x
INFO  DNS service bound  addr=127.0.0.1:5553
INFO  ArcBox daemon started
```

If the sequence stops before "ArcBox daemon started", check the failure
table below.

## L3 direct routing architecture

```
curl http://172.17.0.2/
  → route 172.16/12 via 192.168.65.x → bridge100 → vmnet
  → guest eth1 (192.168.65.x) → ip_forward → docker0 → container
  → reply: container → docker0 → guest eth1 → vmnet → bridge100 → host
```

Two NICs on the VM:
- eth0: socketpair (outbound proxy, DHCP, DNS, port forwarding)
- eth1: VZNATNetworkDeviceAttachment (inbound L3 routing via bridge100)

## Failure diagnosis

### Daemon exits immediately after "Runtime initialized"

| Cause | Check | Fix |
|-------|-------|-----|
| DNS port 5553 occupied | `lsof -i :5553` | `pkill -f com.arcboxlabs.desktop.daemon` |
| Wrong entitlements | `codesign -d --entitlements :- target/debug/arcbox-daemon` | Use `bundle/arcbox.entitlements` |
| docker.img missing/corrupt | Log: "storage device attachment is invalid" | `rm ~/.arcbox/data/docker.img` (auto-recreated) |

### L3 direct curl times out

| Cause | Check | Fix |
|-------|-------|-----|
| Route points to utun (stale) | `route -n get 172.17.0.2` → check interface | `sudo route -n delete -net 172.16.0.0/12 -interface utunN` |
| No route installed | `netstat -rn \| grep 172.16` empty | Restart daemon, check helper logs |
| Helper not running | Log: "is arcbox-helper running?" | `make run-helper` |
| bridge100 doesn't exist | `ifconfig bridge100` fails | VM may not have started, check VMM logs |
| Guest eth1 no IP | Log missing "bridge NIC DHCP lease" | Check VM has second NIC in darwin.rs |

### DNS resolution fails

| Cause | Check | Fix |
|-------|-------|-----|
| No resolver file | `cat /etc/resolver/arcbox.local` | Create with `nameserver 127.0.0.1\nport 5553` |
| DnsService not bound | Log missing "DNS service bound" | Fix port 5553 conflict |
| Container not registered | `dig @127.0.0.1 -p 5553 name.arcbox.local` | Wait for docker_events reconcile |

### Port forwarding curl timeout

| Cause | Check | Fix |
|-------|-------|-----|
| Listener not bound | `lsof -i :8080` | Check `setup_port_forwarding` in container handler |
| Wrong port connected | Log: RST-ACK (flags=0x14) | Confirm `initiate_inbound` uses host_port |
| SYN not reaching guest | No TCP frame in log | Check classifier `take_gated_syns` and TcpBridge handshake path |

### Code changes not taking effect

```bash
# Verify all binaries are freshly built
ls -la target/debug/arcbox-daemon    # should be recent
ls -la ~/.arcbox/bin/arcbox-agent    # should match cross-compile time
file ~/.arcbox/bin/arcbox-agent      # must be "ELF 64-bit LSB ... ARM aarch64"
```

## Network debugging

### Bridge and routing

```bash
ifconfig bridge100                   # host bridge interface
arp -a -i bridge100                  # find guest IP
cat /var/db/dhcpd_leases             # vmnet DHCP leases
route -n get 172.17.0.2              # verify route goes via bridge100
netstat -rn | grep -E "172.16|10.88" # all container routes
ping 192.168.65.x                    # direct bridge connectivity
```

### Helper communication

The helper uses tarpc (bincode over Unix socket), not plain JSON. To verify
the helper is reachable, use the Rust client:

```bash
# Quick connectivity check via the daemon — if helper is up, self-setup
# tasks (DNS, docker socket) will succeed in daemon logs.
make run-helper   # terminal 1
make run-daemon   # terminal 2 — look for "configured" in logs

# Or check via `arcbox doctor`:
./target/debug/abctl doctor   # "ArcBoxHelper" check
```

### TCP frame inspection

```bash
grep "TCP frame:" /tmp/arcbox-*.log
# Format: TCP frame: src_ip:port → dst_ip:port flags=0xNN len=NN
# Flags: 0x02=SYN  0x12=SYN-ACK  0x10=ACK  0x14=RST-ACK  0x18=PSH-ACK
```

### Guest DNS verification

```bash
dig @127.0.0.1 -p 5553 container-name.arcbox.local +short
```

## macOS-specific gotchas

### utun write() is output-only on macOS

macOS utun `write()` goes through the kernel output path (as if sending
to a peer), NOT the input path (delivering to local sockets). tcpdump
shows both directions because BPF captures on output, but the local TCP
stack never receives written packets. Verified by measuring IP input
counters before/after writing 100 packets — zero increment.

This is why L3 routing uses vmnet bridge instead of utun.

### Surge VPN compatibility

Surge's Enhanced Mode (TUN) uses 198.18.0.0/15 on utun4. Our routes
(172.16.0.0/12 via bridge100) don't conflict because they use different
subnets and a gateway-based route (not interface-based). Both can coexist.

### check_interface sysctl

`net.inet.ip.check_interface=1` (macOS default) means the kernel only
accepts packets where dst IP matches the receiving interface's IP. This
is another reason utun-based return path fails — packets with dst=en0_ip
arriving on utun get dropped.

## Key file paths

| Path | Description |
|------|-------------|
| `bundle/arcbox.entitlements` | Correct entitlements for daemon signing |
| `~/.arcbox/run/docker.sock` | Docker API socket |
| `~/.arcbox/run/arcbox.sock` | gRPC API socket |
| `~/.arcbox/bin/arcbox-agent` | Guest agent binary (Linux aarch64) |
| `~/.arcbox/data/docker.img` | VM data disk (auto-created) |
| `/var/run/arcbox-helper.sock` | Privileged helper socket (production) |
| `/tmp/arcbox-helper.sock` | Privileged helper socket (dev, via `make run-helper`) |
| `/var/db/dhcpd_leases` | vmnet DHCP lease database |
| `/etc/resolver/arcbox.local` | DNS resolver configuration |

## Key source files

| File | Purpose |
|------|---------|
| `virt/arcbox-vmm/src/vmm/darwin.rs` | VM init: two NICs (socketpair + NAT bridge) |
| `guest/arcbox-agent/src/init.rs` | Guest init: eth0 + eth1 DHCP |
| `guest/arcbox-agent/src/dns_server.rs` | Guest DNS server |
| `guest/arcbox-agent/src/docker_events.rs` | Docker event → DNS auto-registration |
| `virt/arcbox-net/src/darwin/bridge_discovery.rs` | Discover guest bridge IP |
| `virt/arcbox-net/src/darwin/datapath_loop.rs` | Network datapath event loop |
| `virt/arcbox-net/src/darwin/helper_client.rs` | Helper client (route ops) |
| `app/arcbox-helper/src/server/handler.rs` | Helper tarpc service implementation |
| `app/arcbox-helper/src/server/mutations/` | Helper privileged operations (route, dns, socket, cli) |
| `app/arcbox-daemon/src/main.rs` | Daemon: auto route installation |
