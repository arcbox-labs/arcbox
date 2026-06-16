# Host tunnel proof: `tun_proxy`

`tun_proxy` proves that the data plane extracted into `arcbox-packet` /
`arcbox-datapath` / `arcbox-conntrack` / `arcbox-fakeip` / `arcbox-proxy` /
`arcbox-tcpstack` can power a **Surge-class host proxy**, not just the VM
datapath. It opens a macOS `utun`, runs host egress traffic through the *same*
`FrameClassifier` + `TcpBridge` + `SocketProxy` the VM uses, and forwards TCP to
an upstream SOCKS5 proxy by hostname (recovered from a Fake-IP via the DNS log).

This has been **verified end-to-end** (Gate C): a host HTTP flow over a `utun`
was classified, TCP-terminated by `TcpBridge`, promoted to the fast path, and
tunnelled **by domain** to an upstream SOCKS5 — response and clean teardown
included.

It is a **proof harness, not a product**: best-effort writes (no backpressure
queue), host sockets are polled rather than async, root-only, macOS-only. The
signed `NEPacketTunnelProvider` packaging and encrypted remote protocols are
explicit non-goals (see `PLAN.md`).

## Requirements

- Apple Silicon / macOS, **root** (utun creation, addressing, and routes all
  require root on macOS 15+).
- An upstream SOCKS5 listener — e.g. `ssh -N -D 1080 <host>`, `sing-box`, or
  Surge in SOCKS mode.
- If a Fake-IP proxy (Surge/ClashX) is already running, it owns `198.18.0.0/15`
  and the conventional gateway `198.18.0.1`. Give the harness a **private** utun
  address (`--addr 10.99.0.1 --peer 10.99.0.2`) so it cannot collide.

## Options

| flag | meaning |
| --- | --- |
| `--socks host:port` | upstream SOCKS5 authority (required) |
| `--addr` / `--peer` | utun local / peer address (default `198.18.0.1` / `.2`) |
| `--route CIDR` | route `CIDR` onto the utun; removed on exit |
| `--dns resolver:53` | upstream resolver for DNS queries that traverse the utun |
| `--map IP=DOMAIN` | pre-seed an IP→domain mapping (repeatable) so a routed IP is tunnelled by name without a live DNS round-trip |

## Reproducible self-contained proof

This is the verified Gate C run. It needs no internet: a local SOCKS5 proxy maps
the destination to a local HTTP server, and a seeded `--map` supplies the domain.

```sh
# 1) a local SOCKS5 proxy + HTTP test server, and 2) the harness:
#    private utun address (no Fake-IP collision), seeded IP->domain mapping.
sudo cargo run -p arcbox-net --example tun_proxy -- \
    --socks 127.0.0.1:1080 --addr 10.99.0.1 --peer 10.99.0.2 \
    --map 198.51.100.7=example.test &

# 3) route the (TEST-NET-2) destination onto the harness's utunN, then drive a flow:
sudo route add -host 198.51.100.7 -interface utunN
curl --resolve example.test:80:198.51.100.7 http://example.test/
```

Expected: the body comes back, and the harness logs the full lifecycle —
`SYN gated` → `passive-open registered` → `SOCKS5 tunnel established
target=example.test` → fast-path promotion → response → FIN. The SOCKS5 proxy
logs `CONNECT example.test:80`, i.e. the destination was tunnelled **by name**.

(A ready-to-run script that wires the local proxy/test-server, picks the utun,
adds and removes the route, and prints a `PASS`/`FAIL` verdict is the simplest
way to reproduce this.)

## Real-world usage

Point it at a real upstream SOCKS5 and route real traffic through the utun:

```sh
ssh -N -D 1080 <host>                                   # upstream SOCKS5
sudo cargo run -p arcbox-net --example tun_proxy -- \
    --socks 127.0.0.1:1080 --addr 10.99.0.1 --peer 10.99.0.2 &
# force a flow onto the utun (scoped to the interface; no routing-table change):
curl --interface utunN https://example.com
```

For a destination domain to be tunnelled **by name** (instead of by raw IP), its
DNS query must traverse the utun so the harness records `domain → IP`: send it to
the utun's gateway (`--peer`) address, e.g. `dig example.com @10.99.0.2`. A
destination in the Fake-IP range (`198.18.0.0/15`) is tunnelled by IP string even
without a recorded domain.

> Routes are removed on normal exit and on Ctrl-C (dev profile / unwind). A hard
> kill (`SIGKILL`) or a `--release` build (`panic = "abort"`) skips Drop and can
> leave a `--route` pointed at a dead `utun`; remove it with `sudo route delete`.

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
