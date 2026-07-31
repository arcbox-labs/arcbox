//! `tun_proxy` — host-tunnel proof harness for the extracted ArcBox data plane.
//!
//! Opens a macOS `utun` and drives real host egress traffic through the SAME
//! stack the VM datapath uses — [`FrameClassifier`], [`TcpBridge`], and
//! [`HostEgress`] — forwarding TCP to an upstream SOCKS5 proxy by hostname
//! (recovered from Fake-IP via the DNS log). It is the concrete proof that the
//! ArcBox data plane can power a Surge-class host proxy.
//!
//! This is a proof harness, not a product: it requires root (utun addressing +
//! routes), best-effort writes (no backpressure queue), and is macOS-only. See
//! `docs/surge-tun-proxy.md` for the run recipe and the manual verification.
//!
//! Run: `sudo cargo run -p arcbox-net --example tun_proxy -- --socks 127.0.0.1:1080`

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("tun_proxy requires macOS (utun)");
    std::process::exit(1);
}

#[cfg(target_os = "macos")]
fn main() -> anyhow::Result<()> {
    macos::run()
}

#[cfg(target_os = "macos")]
mod macos {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::os::fd::{AsRawFd, RawFd};
    use std::time::Duration;

    use anyhow::{Context, Result};
    use clap::Parser;
    use tokio::io::unix::AsyncFd;
    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;

    use arcbox_fakeip::dns_log::{DnsResolutionLog, parse_dns_response_a_records};
    use arcbox_fakeip::proxy_detect::{ProxyConfig, ProxyEnvironment};
    use arcbox_proxy::egress::HostEgress;
    use arcbox_route::Ipv4Net;
    use splicetcp::FrameSource;
    use splicetcp::classifier::{FrameClassifier, InterceptedKind};
    use splicetcp::shim::{GATEWAY_MAC, HOST_MAC, L3ToL2Source};
    use splicetcp::tcp_bridge::TcpBridge;
    use splicetcp::utun::{UtunFrameSource, UtunSink};

    use arcbox_net::darwin::DarwinTun;

    /// utun MTU. The shim's TCP frames toward the host can reach
    /// `FAST_PATH_GUEST_MSS` (~2000 B), so the device MTU is raised above the
    /// 1500 default to avoid fragmentation on the loopback-class path.
    const UTUN_MTU: u32 = 4000;

    #[derive(Parser)]
    #[command(
        name = "tun_proxy",
        about = "Host-tunnel proof: utun -> ArcBox stack -> upstream SOCKS5"
    )]
    struct Args {
        /// Upstream SOCKS5 proxy authority, e.g. `127.0.0.1:1080`.
        #[arg(long)]
        socks: String,
        /// utun local (host-side) address.
        #[arg(long, default_value = "198.18.0.1")]
        addr: Ipv4Addr,
        /// utun peer address (the synthetic gateway).
        #[arg(long, default_value = "198.18.0.2")]
        peer: Ipv4Addr,
        /// Optional CIDR to route through the utun (e.g. `198.18.0.0/15`).
        /// Removed on exit. Omit and use `curl --interface utunN` instead.
        #[arg(long)]
        route: Option<String>,
        /// Upstream DNS resolver for queries routed through the utun.
        #[arg(long, default_value = "1.1.1.1:53")]
        dns: SocketAddr,
        /// Pre-seed an IP -> domain mapping into the resolution log (repeatable),
        /// e.g. `--map 198.51.100.7=example.test`. Lets a routed destination be
        /// tunnelled by name without a live DNS round-trip through the utun.
        #[arg(long = "map", value_name = "IP=DOMAIN")]
        maps: Vec<String>,
    }

    pub fn run() -> Result<()> {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "info,tun_proxy=debug".into()),
            )
            .init();

        let args = Args::parse();
        let (socks_host, socks_port) = parse_authority(&args.socks)
            .with_context(|| format!("invalid --socks authority: {}", args.socks))?;

        // Open + configure the utun. Creating it needs no root; addressing does.
        let tun = DarwinTun::new().context("open utun (try sudo)")?;
        tun.configure(args.addr, args.peer, Ipv4Addr::new(255, 255, 255, 252))
            .context("configure utun address (needs root)")?;
        set_mtu(tun.name(), UTUN_MTU).context("set utun mtu")?;
        tun.set_nonblocking(true).context("set utun nonblocking")?;
        tracing::info!(iface = %tun.name(), addr = %args.addr, peer = %args.peer, "utun up");

        // Optional scoped route, removed on exit so a crash cannot strand the host.
        let route_guard = match args.route.as_deref() {
            Some(cidr) => Some(RouteGuard::install(cidr, tun.name())?),
            None => None,
        };

        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .context("build tokio runtime")?;

        let result = rt.block_on(event_loop(&tun, &args, socks_host, socks_port));

        drop(route_guard); // restore routing before returning
        result
    }

    /// The surge-datapath event loop: a focused transcription of the VM
    /// `NetworkDatapath::run` for the host/utun case (no DHCP, no inbound, no
    /// zero-copy inject; synthetic MACs; best-effort egress).
    async fn event_loop(
        tun: &DarwinTun,
        args: &Args,
        socks_host: String,
        socks_port: u16,
    ) -> Result<()> {
        let fd = tun.as_raw_fd();
        let gateway_ip = args.peer;
        let guest_ip = args.addr;

        // Ingest: utun IP packets -> synthetic Ethernet -> classifier.
        let mut source = L3ToL2Source::new(UtunFrameSource::new(fd));
        let sink = UtunSink::new(fd);

        let mut classifier = FrameClassifier::new(gateway_ip, UTUN_MTU as usize);
        classifier.set_gateway_mac(GATEWAY_MAC);
        // On a utun there is no real guest MAC; the shim's source MAC is fixed.
        let mut guest_mac: Option<[u8; 6]> = Some(HOST_MAC);

        let mut tcp_bridge = TcpBridge::new(gateway_ip);
        tcp_bridge.set_fast_path_macs(GATEWAY_MAC, HOST_MAC);

        // Proxy awareness: a Fake-IP-active environment whose SOCKS5 upstream is
        // the one we were given. resolve_proxy_target then routes Fake-IP / named
        // destinations through it (by hostname, recovered via the DNS log).
        let dns_log = DnsResolutionLog::new();
        for m in &args.maps {
            if let Some((ip, domain)) = m.split_once('=')
                && let Ok(ip) = ip.parse::<Ipv4Addr>()
            {
                dns_log.record(domain, &[ip]);
                tracing::info!(%ip, domain, "seeded IP->domain mapping");
            }
        }
        let proxy_env = ProxyEnvironment {
            fake_ip_active: true,
            socks_proxy: Some(ProxyConfig {
                host: socks_host,
                port: socks_port,
            }),
            ..Default::default()
        };
        tcp_bridge.set_proxy_awareness(dns_log.clone(), proxy_env);

        let cancel = CancellationToken::new();
        let (reply_tx, mut reply_rx) = mpsc::channel::<Vec<u8>>(256);
        let mut egress = HostEgress::new(
            gateway_ip,
            GATEWAY_MAC,
            guest_ip,
            reply_tx.clone(),
            cancel.clone(),
            UTUN_MTU as usize,
        );

        let async_fd = AsyncFd::new(RawFdWrapper(fd)).context("register utun with reactor")?;
        let dns_upstream = args.dns;
        let mut maintenance = tokio::time::interval(Duration::from_secs(30));
        // Drive the common tail (handshake completion + fast-path reads)
        // continuously. Unlike the VM datapath there is no inject thread and no
        // steady guest traffic to keep the loop spinning, so a host SOCKS5
        // connect resolving — or response data arriving on a host socket —
        // would otherwise wait for the next utun packet. A short tick keeps the
        // proof harness responsive (a productized version would make the host
        // sockets async instead of polling).
        let mut poll = tokio::time::interval(Duration::from_millis(2));
        poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        tracing::info!("tun_proxy datapath running; Ctrl-C to stop");

        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    tracing::info!("shutting down");
                    cancel.cancel();
                    break;
                }
                readable = async_fd.readable() => {
                    let mut guard = readable.context("utun readiness")?;
                    source.drain(|frame| classifier.classify_frame(frame, &mut guest_mac));
                    guard.clear_ready();

                    for ack in classifier.drain_fast_path(|f| tcp_bridge.try_fast_path_intercept(f)) {
                        write_frame(&sink, &ack);
                    }
                    for reply in classifier.drain_handshake(|f| tcp_bridge.try_complete_handshake(f)) {
                        write_frame(&sink, &reply);
                    }
                    classifier.clear_unmatched_rx();

                    for intercepted in classifier.take_intercepted() {
                        match intercepted.kind {
                            InterceptedKind::Dns => handle_dns(
                                &intercepted.frame,
                                dns_upstream,
                                &dns_log,
                                &reply_tx,
                                gateway_ip,
                                guest_mac.unwrap_or(HOST_MAC),
                            ),
                            // No DHCP server on a host tunnel; treat as plain UDP.
                            InterceptedKind::Udp | InterceptedKind::Dhcp | InterceptedKind::Icmp => {
                                egress.handle_outbound(&intercepted.frame, guest_mac.unwrap_or(HOST_MAC));
                            }
                        }
                    }

                    for syn in classifier.take_gated_syns() {
                        if let Some(rst) =
                            tcp_bridge.handle_outbound_syn(&syn.frame, GATEWAY_MAC, HOST_MAC)
                        {
                            write_frame(&sink, &rst);
                        }
                    }
                }
                Some(reply) = reply_rx.recv() => {
                    write_frame(&sink, &reply);
                }
                _ = poll.tick() => {}
                _ = maintenance.tick() => {
                    egress.maintenance();
                }
            }

            // Common tail (every iteration): drive handshakes + fast-path reads.
            for frame in tcp_bridge.poll_handshakes() {
                write_frame(&sink, &frame);
            }
            for frame in tcp_bridge.poll_fast_path() {
                write_frame(&sink, &frame);
            }
            tokio::task::yield_now().await;
        }

        Ok(())
    }

    /// Writes one L2 frame to the utun (best-effort: ARP/non-IP is dropped by
    /// the sink, WouldBlock/errors are logged — this harness has no write queue).
    fn write_frame(sink: &UtunSink, frame: &[u8]) {
        match sink.send_l2_frame(frame) {
            Ok(true) => tracing::debug!("utun TX {} bytes", frame.len()),
            Ok(false) => tracing::debug!("utun TX SKIPPED (non-IP/ARP) {} bytes", frame.len()),
            Err(e) => tracing::debug!("utun TX error: {e}"),
        }
    }

    /// Forwards a DNS query routed through the utun to the upstream resolver,
    /// records the A records in the log (so a later TCP connect to one of those
    /// IPs recovers the hostname for the SOCKS5 tunnel), and replies to the host.
    fn handle_dns(
        frame: &[u8],
        upstream: SocketAddr,
        dns_log: &DnsResolutionLog,
        reply_tx: &mpsc::Sender<Vec<u8>>,
        gateway_ip: Ipv4Addr,
        guest_mac: [u8; 6],
    ) {
        use arcbox_packet::ethernet::{ETH_HEADER_LEN, build_udp_ip_ethernet};

        let ip_start = ETH_HEADER_LEN;
        let ihl = ((frame[ip_start] & 0x0F) as usize) * 4;
        let l4_start = ip_start + ihl;
        let dns_start = l4_start + 8;
        if dns_start >= frame.len() {
            return;
        }
        let src_ip = Ipv4Addr::new(
            frame[ip_start + 12],
            frame[ip_start + 13],
            frame[ip_start + 14],
            frame[ip_start + 15],
        );
        let src_port = u16::from_be_bytes([frame[l4_start], frame[l4_start + 1]]);
        let query = frame[dns_start..].to_vec();
        let log = dns_log.clone();
        let reply_tx = reply_tx.clone();

        tokio::spawn(async move {
            let Ok(socket) = tokio::net::UdpSocket::bind("0.0.0.0:0").await else {
                return;
            };
            if socket.send_to(&query, upstream).await.is_err() {
                return;
            }
            let mut buf = [0u8; 4096];
            let n = match tokio::time::timeout(Duration::from_secs(2), socket.recv(&mut buf)).await
            {
                Ok(Ok(n)) if n >= 2 => n,
                _ => return,
            };
            let response = &buf[..n];
            if let Some((domain, ips)) = parse_dns_response_a_records(response) {
                tracing::debug!(%domain, ?ips, "recorded DNS resolution");
                log.record(&domain, &ips);
            }
            let reply_frames = build_udp_ip_ethernet(
                gateway_ip,
                src_ip,
                53,
                src_port,
                response,
                GATEWAY_MAC,
                guest_mac,
                UTUN_MTU as usize,
            );
            for reply_frame in reply_frames {
                if reply_tx.send(reply_frame).await.is_err() {
                    return;
                }
            }
        });
    }

    /// Wraps a raw fd so it can be registered with `AsyncFd` (the fd is owned by
    /// the `DarwinTun`, which outlives this wrapper).
    struct RawFdWrapper(RawFd);
    impl AsRawFd for RawFdWrapper {
        fn as_raw_fd(&self) -> RawFd {
            self.0
        }
    }

    /// Installs a scoped route through the utun and removes it on drop.
    struct RouteGuard {
        net: Ipv4Net,
    }
    impl RouteGuard {
        fn install(cidr: &str, iface: &str) -> Result<Self> {
            let net = parse_cidr(cidr).with_context(|| format!("invalid --route CIDR: {cidr}"))?;
            let outcome = arcbox_route::add(net, iface)
                .map_err(|e| anyhow::anyhow!("add route {cidr} via {iface}: {e}"))?;
            anyhow::ensure!(
                outcome == arcbox_route::AddOutcome::Added,
                "route {cidr} already exists and was left untouched"
            );
            tracing::info!(%cidr, iface, "installed scoped route");
            Ok(Self { net })
        }
    }
    impl Drop for RouteGuard {
        fn drop(&mut self) {
            if let Err(e) = arcbox_route::remove(self.net) {
                tracing::warn!("failed to remove route on exit: {e}");
            } else {
                tracing::info!("removed scoped route");
            }
        }
    }

    fn parse_authority(s: &str) -> Option<(String, u16)> {
        let (host, port) = s.rsplit_once(':')?;
        Some((host.to_string(), port.parse().ok()?))
    }

    fn parse_cidr(s: &str) -> Result<Ipv4Net> {
        let (addr, prefix) = s.split_once('/').context("CIDR must be addr/prefix")?;
        let addr: Ipv4Addr = addr.parse().context("CIDR address")?;
        let prefix: u8 = prefix.parse().context("CIDR prefix")?;
        Ipv4Net::new(addr, prefix).map_err(|e| anyhow::anyhow!("invalid CIDR: {e:?}"))
    }

    /// Sets the interface MTU via `ifconfig` (no stable libc ioctl wrapper).
    fn set_mtu(iface: &str, mtu: u32) -> Result<()> {
        let status = std::process::Command::new("ifconfig")
            .args([iface, "mtu", &mtu.to_string()])
            .status()
            .context("spawn ifconfig")?;
        anyhow::ensure!(status.success(), "ifconfig {iface} mtu {mtu} failed");
        Ok(())
    }
}
