//! UDP egress: per-flow host sockets, optionally routed through a SOCKS5 proxy.
//!
//! Each guest UDP flow gets a spawned task owning a [`UdpTransport`] — a direct
//! host `UdpSocket`, or a SOCKS5 UDP association when the proxy environment
//! applies. Replies are reframed as guest-bound L2 frames and pushed back over
//! the shared `reply_tx`.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Instant;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use arcbox_fakeip::dns_log::DnsResolutionLog;
use arcbox_fakeip::proxy_detect::ProxyEnvironment;
use arcbox_packet::ethernet::{ETH_HEADER_LEN, build_udp_ip_ethernet};

use crate::socks5::Socks5UdpAssociation;

/// The egress transport for one UDP flow: a direct host socket, or a SOCKS5 UDP
/// association. Unifies the per-flow pump so the reply path is identical.
enum UdpTransport {
    Direct(UdpSocket),
    Socks {
        assoc: Socks5UdpAssociation,
        host: String,
        port: u16,
    },
}

impl UdpTransport {
    async fn send(&self, data: &[u8]) -> std::io::Result<()> {
        match self {
            Self::Direct(s) => s.send(data).await.map(|_| ()),
            Self::Socks { assoc, host, port } => assoc.send_to(data, host, *port).await.map(|_| ()),
        }
    }

    /// `Ok(Some(n))` = a deliverable payload of `n` bytes in `buf`; `Ok(None)` =
    /// a datagram that was received but isn't deliverable (fragmented / malformed)
    /// and should be skipped without tearing the flow down; `Err` = fatal.
    async fn recv(&self, buf: &mut [u8]) -> std::io::Result<Option<usize>> {
        match self {
            Self::Direct(s) => s.recv(buf).await.map(Some),
            Self::Socks { assoc, .. } => assoc.recv_from(buf).await.map(|o| o.map(|(n, _, _)| n)),
        }
    }
}

/// Builds a flow's egress transport. `socks` = `Some((authority, target_host))`
/// routes via SOCKS5 UDP ASSOCIATE (the proxy resolves `target_host`); `None` is
/// a direct host socket connected to `connect_ip:dst_port`. Returns `None` (after
/// logging) on setup failure.
async fn build_udp_transport(
    socks: Option<(String, String)>,
    connect_ip: Ipv4Addr,
    dst_port: u16,
) -> Option<UdpTransport> {
    match socks {
        Some((authority, host)) => match Socks5UdpAssociation::associate(&authority).await {
            Ok(assoc) => Some(UdpTransport::Socks {
                assoc,
                host,
                port: dst_port,
            }),
            Err(e) => {
                tracing::warn!("UDP proxy: SOCKS5 UDP associate failed: {e}");
                None
            }
        },
        None => {
            let socket = match UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("UDP proxy: failed to bind socket: {e}");
                    return None;
                }
            };
            if let Err(e) = socket
                .connect(SocketAddr::V4(SocketAddrV4::new(connect_ip, dst_port)))
                .await
            {
                tracing::warn!("UDP proxy: failed to connect: {e}");
                return None;
            }
            Some(UdpTransport::Direct(socket))
        }
    }
}

/// Per-flow UDP state.
struct UdpFlow {
    /// Last time traffic was seen on this flow.
    last_active: Instant,
    /// Channel to send subsequent payloads to the flow's host socket task.
    payload_tx: mpsc::Sender<Vec<u8>>,
}

/// UDP proxy: per-flow host sockets.
pub(super) struct UdpProxy {
    /// Active flows keyed by (src_ip, src_port, dst_ip, dst_port).
    flows: HashMap<(Ipv4Addr, u16, Ipv4Addr, u16), UdpFlow>,
    reply_tx: mpsc::Sender<Vec<u8>>,
    gateway_mac: [u8; 6],
    /// Gateway IP — connections to this IP are translated to loopback
    /// so they reach host services (host.docker.internal support).
    gateway_ip: Ipv4Addr,
    /// Shared fake-IP → domain log; reverses a fake-IP destination before the
    /// proxy decision so UDP routes by domain like TCP. `None` = no reversal.
    pub(super) dns_log: Option<DnsResolutionLog>,
    /// Detected host proxy environment; a configured SOCKS proxy routes
    /// non-gateway, non-bypassed flows through it. `None` = always direct.
    pub(super) proxy_env: Option<ProxyEnvironment>,
}

impl UdpProxy {
    pub(super) fn new(
        reply_tx: mpsc::Sender<Vec<u8>>,
        gateway_mac: [u8; 6],
        gateway_ip: Ipv4Addr,
    ) -> Self {
        Self {
            flows: HashMap::new(),
            reply_tx,
            gateway_mac,
            gateway_ip,
            dns_log: None,
            proxy_env: None,
        }
    }

    /// Proxies a UDP packet from the guest to the host network.
    pub(super) fn proxy_udp(
        &mut self,
        frame: &[u8],
        guest_mac: [u8; 6],
        cancel: CancellationToken,
    ) {
        // Parse IP + UDP headers from the frame.
        if frame.len() < ETH_HEADER_LEN + 28 {
            return;
        }

        let ip_start = ETH_HEADER_LEN;
        let ihl = ((frame[ip_start] & 0x0F) as usize) * 4;
        let l4_start = ip_start + ihl;

        if frame.len() < l4_start + 8 {
            return;
        }

        let src_ip = Ipv4Addr::new(
            frame[ip_start + 12],
            frame[ip_start + 13],
            frame[ip_start + 14],
            frame[ip_start + 15],
        );
        let dst_ip = Ipv4Addr::new(
            frame[ip_start + 16],
            frame[ip_start + 17],
            frame[ip_start + 18],
            frame[ip_start + 19],
        );
        let src_port = u16::from_be_bytes([frame[l4_start], frame[l4_start + 1]]);
        let dst_port = u16::from_be_bytes([frame[l4_start + 2], frame[l4_start + 3]]);
        let udp_len = u16::from_be_bytes([frame[l4_start + 4], frame[l4_start + 5]]) as usize;

        if udp_len < 8 || l4_start + udp_len > frame.len() {
            return;
        }

        let payload = frame[l4_start + 8..l4_start + udp_len].to_vec();
        let flow_key = (src_ip, src_port, dst_ip, dst_port);

        // Existing flow: send payload through its channel.
        if let Some(flow) = self.flows.get_mut(&flow_key) {
            flow.last_active = Instant::now();
            if flow.payload_tx.try_send(payload).is_err() {
                // Task exited or channel full — remove stale flow so it
                // gets recreated on the next packet.
                self.flows.remove(&flow_key);
            }
            return;
        }

        // New flow: create a channel and spawn a task that owns the socket.
        let (payload_tx, mut payload_rx) = mpsc::channel::<Vec<u8>>(64);

        self.flows.insert(
            flow_key,
            UdpFlow {
                last_active: Instant::now(),
                payload_tx,
            },
        );

        let reply_tx = self.reply_tx.clone();
        let gateway_mac = self.gateway_mac;
        // Translate gateway IP to loopback so host services are reachable.
        let connect_ip = if dst_ip == self.gateway_ip {
            Ipv4Addr::LOCALHOST
        } else {
            dst_ip
        };

        // Domain-preferred (like the TCP path): reverse a fake-IP destination to
        // its domain so the proxy can resolve it and domain bypass rules apply.
        let host = self
            .dns_log
            .as_ref()
            .and_then(|log| log.lookup(dst_ip))
            .unwrap_or_else(|| dst_ip.to_string());
        // Route via the SOCKS5 proxy when one applies: a usable SOCKS proxy is
        // configured (HTTP can't carry UDP), the destination isn't gateway-local
        // (host services stay direct), and it isn't on the bypass list. Reuses the
        // same `should_bypass` policy the TCP egress uses.
        let socks = self.proxy_env.as_ref().and_then(|env| {
            if dst_ip == self.gateway_ip || env.should_bypass(&host) {
                return None;
            }
            env.socks_proxy
                .as_ref()
                .map(|p| (format!("{}:{}", p.host, p.port), host.clone()))
        });

        tokio::spawn(async move {
            // Race the whole flow — including the SOCKS handshake, which can hang
            // on a slow proxy — against cancellation so a stalled setup never
            // outlives shutdown.
            let pump = async move {
                let transport = match build_udp_transport(socks, connect_ip, dst_port).await {
                    Some(t) => t,
                    None => return, // setup failed (already logged)
                };

                // Send the initial payload.
                if let Err(e) = transport.send(&payload).await {
                    tracing::warn!("UDP proxy: send failed: {}", e);
                    return;
                }

                let mut buf = vec![0u8; 65535];
                loop {
                    tokio::select! {
                        // Subsequent payloads from the same flow.
                        msg = payload_rx.recv() => match msg {
                            Some(data) => {
                                if let Err(e) = transport.send(&data).await {
                                    tracing::trace!("UDP proxy: send failed: {e}");
                                    return;
                                }
                            }
                            None => return, // Channel closed, flow removed.
                        },
                        // Replies from the remote host (or the proxy relay).
                        recv = tokio::time::timeout(
                            std::time::Duration::from_mins(1),
                            transport.recv(&mut buf),
                        ) => match recv {
                            Ok(Ok(Some(n))) => {
                                let reply_frame = build_udp_ip_ethernet(
                                    dst_ip,
                                    src_ip,
                                    dst_port,
                                    src_port,
                                    &buf[..n],
                                    gateway_mac,
                                    guest_mac,
                                );
                                if reply_tx.send(reply_frame).await.is_err() {
                                    return;
                                }
                            }
                            // A fragmented / malformed relay datagram: skip it (the
                            // loop iterates), keeping the flow up.
                            Ok(Ok(None)) => {}
                            // Fatal socket error or the 60s idle timeout.
                            Ok(Err(_)) | Err(_) => return,
                        },
                    }
                }
            };

            tokio::select! {
                () = cancel.cancelled() => {}
                () = pump => {}
            }
        });
    }

    /// Removes flows inactive for more than 60 seconds.
    pub(super) fn cleanup_stale_flows(&mut self) {
        let now = Instant::now();
        self.flows
            .retain(|_, flow| now.duration_since(flow.last_active).as_secs() < 60);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_util::sync::CancellationToken;

    /// Builds a minimal Ethernet + IPv4 + UDP frame.
    fn make_udp_frame(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let ip_total = 20 + udp_len;
        let mut frame = vec![0u8; ETH_HEADER_LEN + ip_total];

        // Ethernet: EtherType = IPv4
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        let ip = ETH_HEADER_LEN;
        // IPv4: version=4, IHL=5, total length, protocol=17 (UDP)
        frame[ip] = 0x45;
        frame[ip + 2..ip + 4].copy_from_slice(&(ip_total as u16).to_be_bytes());
        frame[ip + 8] = 64; // TTL
        frame[ip + 9] = 17; // UDP
        frame[ip + 12..ip + 16].copy_from_slice(&src_ip.octets());
        frame[ip + 16..ip + 20].copy_from_slice(&dst_ip.octets());

        let l4 = ip + 20;
        frame[l4..l4 + 2].copy_from_slice(&src_port.to_be_bytes());
        frame[l4 + 2..l4 + 4].copy_from_slice(&dst_port.to_be_bytes());
        frame[l4 + 4..l4 + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
        frame[l4 + 8..l4 + 8 + payload.len()].copy_from_slice(payload);
        frame
    }

    #[test]
    fn test_udp_proxy_cleanup_stale_flows() {
        let (tx, _rx) = mpsc::channel(16);
        let gw_ip = Ipv4Addr::new(192, 168, 64, 1);
        let gw_mac = [0x02, 0xAB, 0xCD, 0x00, 0x00, 0x01];
        let mut proxy = UdpProxy::new(tx, gw_mac, gw_ip);

        // Insert a flow that is already expired.
        let key = (
            Ipv4Addr::new(192, 168, 64, 2),
            1234,
            Ipv4Addr::new(8, 8, 8, 8),
            53,
        );
        proxy.flows.insert(
            key,
            UdpFlow {
                last_active: Instant::now()
                    .checked_sub(std::time::Duration::from_secs(120))
                    .unwrap(),
                payload_tx: mpsc::channel(1).0,
            },
        );
        assert_eq!(proxy.flows.len(), 1);

        proxy.cleanup_stale_flows();
        assert_eq!(proxy.flows.len(), 0, "Stale flow should be cleaned up");
    }

    /// Verifies that a UDP packet destined for the gateway IP is delivered
    /// to a loopback listener via the gateway→localhost translation.
    #[tokio::test]
    async fn test_udp_proxy_gateway_translates_to_loopback() {
        let (reply_tx, _reply_rx) = mpsc::channel(64);
        let gw_ip = Ipv4Addr::new(10, 0, 2, 1);
        let gw_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let mut proxy = UdpProxy::new(reply_tx, gw_mac, gw_ip);

        // Bind a UDP listener on loopback.
        let listener = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let payload = b"hello-host";
        let frame = make_udp_frame(
            Ipv4Addr::new(10, 0, 2, 15),
            gw_ip, // targeting gateway, should be translated to 127.0.0.1
            9999,
            port,
            payload,
        );
        let guest_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x99];

        proxy.proxy_udp(&frame, guest_mac, CancellationToken::new());

        // The proxy spawns a task — give it time to send.
        let mut buf = [0u8; 64];
        let len = tokio::time::timeout(std::time::Duration::from_secs(2), listener.recv(&mut buf))
            .await
            .expect("timed out waiting for UDP packet")
            .expect("recv failed");

        assert_eq!(&buf[..len], payload);
    }

    /// With a SOCKS proxy in the env, a non-gateway flow is relayed through the
    /// SOCKS5 proxy (UDP ASSOCIATE) instead of a direct host socket; the echoed
    /// reply still comes back to the guest as an L2 frame.
    #[tokio::test]
    async fn udp_proxy_routes_through_socks5_when_configured() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        // Mock SOCKS5 UDP proxy: control handshake + a UDP relay that echoes the
        // datagram (header preserved) back to the client.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let relay_addr = relay.local_addr().unwrap();
            let (mut ctrl, _) = listener.accept().await.unwrap();
            let mut g = [0u8; 3];
            ctrl.read_exact(&mut g).await.unwrap();
            ctrl.write_all(&[0x05, 0x00]).await.unwrap();
            let mut req = [0u8; 4];
            ctrl.read_exact(&mut req).await.unwrap();
            let mut rest = [0u8; 6];
            ctrl.read_exact(&mut rest).await.unwrap();
            let mut reply = vec![0x05, 0x00, 0x00, 0x01];
            match relay_addr.ip() {
                std::net::IpAddr::V4(v4) => reply.extend_from_slice(&v4.octets()),
                std::net::IpAddr::V6(_) => unreachable!("bound to v4"),
            }
            reply.extend_from_slice(&relay_addr.port().to_be_bytes());
            ctrl.write_all(&reply).await.unwrap();

            let mut buf = vec![0u8; 2048];
            let (n, client) = relay.recv_from(&mut buf).await.unwrap();
            relay.send_to(&buf[..n], client).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            drop(ctrl);
        });

        let (reply_tx, mut reply_rx) = mpsc::channel(16);
        let gw_ip = Ipv4Addr::new(10, 0, 2, 1);
        let gw_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        let mut proxy = UdpProxy::new(reply_tx, gw_mac, gw_ip);
        let (phost, pport) = (proxy_addr.ip().to_string(), proxy_addr.port());
        proxy.proxy_env = Some(ProxyEnvironment {
            socks_proxy: Some(arcbox_fakeip::proxy_detect::ProxyConfig {
                host: phost,
                port: pport,
            }),
            ..Default::default()
        });

        // Non-gateway destination → routed through the SOCKS5 relay.
        let payload = b"proxied-udp";
        let frame = make_udp_frame(
            Ipv4Addr::new(10, 0, 2, 15),
            Ipv4Addr::new(1, 2, 3, 4),
            5000,
            9999,
            payload,
        );
        let guest_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x99];
        proxy.proxy_udp(&frame, guest_mac, CancellationToken::new());

        let reply = tokio::time::timeout(std::time::Duration::from_secs(2), reply_rx.recv())
            .await
            .expect("timed out waiting for the proxied reply")
            .expect("reply frame");
        assert!(
            reply.ends_with(payload),
            "echoed payload returns to the guest via the SOCKS5 relay"
        );
        server.await.unwrap();
    }
}
