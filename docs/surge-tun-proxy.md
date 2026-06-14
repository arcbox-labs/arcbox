# Host tunnel proof: `tun_proxy`

`tun_proxy` proves that the data plane extracted into `arcbox-packet` /
`arcbox-datapath` / `arcbox-conntrack` / `arcbox-fakeip` / `arcbox-proxy` /
`arcbox-tcpstack` can power a **Surge-class host proxy**, not just the VM
datapath. It opens a macOS `utun`, runs host egress traffic through the *same*
`FrameClassifier` + `TcpBridge` + `SocketProxy` the VM uses, and forwards TCP to
an upstream SOCKS5 proxy by hostname (recovered from Fake-IP via the DNS log).

It is a **proof harness, not a product**: best-effort writes (no backpressure
queue), no Fake-IP DNS server of its own, root-only, macOS-only. The signed
`NEPacketTunnelProvider` packaging and encrypted remote protocols are explicit
non-goals (see `PLAN.md`).

## Requirements

- Apple Silicon / macOS, **root** (utun addressing + routes).
- An upstream SOCKS5 listener — e.g. `ssh -D 1080 …`, `sing-box`, or Surge in
  SOCKS mode. (Without one, TCP connects fail at the proxy hop.)

## Run

```sh
# Terminal 1: an upstream SOCKS5 (example: ssh dynamic forward)
ssh -N -D 1080 somehost

# Terminal 2: the harness (creates utunN, assigns 198.18.0.1, raises MTU)
sudo cargo run -p arcbox-net --example tun_proxy -- --socks 127.0.0.1:1080
```

It logs the assigned interface (e.g. `utun7`). Two ways to send traffic through it:

- **Scoped interface (safest — no routing table change):**

  ```sh
  curl --interface utun7 https://example.com
  ```

- **Scoped route (opt-in):** pass `--route` and the harness installs the route
  via `arcbox-route` and removes it on normal exit and on Ctrl-C. Run in the
  default dev profile (as below) so a panic still unwinds and tears the route
  down. A hard kill (`SIGKILL`) or a `--release` build (`panic = "abort"`) skips
  the cleanup and can leave the route pointed at a dead `utun` — remove it
  manually with `sudo route -n delete -net 198.18.0.0/15` if that happens:

  ```sh
  sudo cargo run -p arcbox-net --example tun_proxy -- \
      --socks 127.0.0.1:1080 --route 198.18.0.0/15
  ```

For destination **domains** to be recovered (and tunnelled by name), the DNS
query must also traverse the utun so the harness can record `domain → IP`; pass
`--dns <resolver:53>` (default `1.1.1.1:53`). Traffic to the Fake-IP range
(`198.18.0.0/15`) is tunnelled by IP string even without a recorded domain.

## Manual verification (Gate C)

This gate is functional, not a throughput target. With the upstream SOCKS5
running and traffic routed through `utunN`:

1. A host TCP flow reaches its destination **through the upstream proxy** (verify
   on the proxy side — e.g. the `ssh -D` connection log, or `sing-box` access log).
2. The harness logs `recorded DNS resolution` for the domain and the `TcpBridge`
   `SOCKS5 tunnel established` line naming `host:port` — i.e. the destination was
   tunnelled **by hostname**, not by raw Fake-IP.
3. A UDP flow (e.g. `dig @<addr-on-utun>`) round-trips via `SocketProxy`.

If TCP termination or domain recovery fails on the L3 path, the L3↔L2 shim or the
synthetic-MAC assumptions are wrong — diagnose against the working VM datapath
(`virt/arcbox-net/tests/datapath_test.rs`, which exercises the same stack over a
socketpair).

## How it maps to the VM datapath

`tun_proxy`'s loop is a focused transcription of
`arcbox_net::darwin::datapath_loop::NetworkDatapath::run`, differing only at the
endpoint and in the VM-only concerns it omits:

| VM datapath (`NetworkDatapath`) | `tun_proxy` |
| --- | --- |
| socketpair + `FdFrameSource` | `utun` + `UtunFrameSource` → `L3ToL2Source` |
| learned guest MAC, DHCP server | synthetic `HOST_MAC`/`GATEWAY_MAC`, no DHCP |
| zero-copy inject thread (`ConnSink`) | direct `UtunSink` writes |
| inbound port-forward listeners | none |
| `FrameClassifier` · `TcpBridge` · `SocketProxy` | **shared, unchanged** |

Everything below the `FrameSource` / `FrameSink` line is the same code.
