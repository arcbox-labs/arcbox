//! Egress resolution seam.
//!
//! Decouples the "decide + dial an upstream transport for an outbound SYN"
//! policy from the TCP bridge. The bridge holds an [`EgressResolver`] trait
//! object and calls [`EgressResolver::resolve`] per flow; the default
//! [`DefaultEgress`] reproduces the bridge's historical inline behavior
//! (system-proxy aware connect via SOCKS5 / HTTP CONNECT, or a direct
//! `TcpStream::connect`, with the gateway→loopback translation and a connect
//! timeout). A consumer (e.g. an Inbound/Router/Outbound host) can replace the
//! resolver to inject its own egress policy.

use std::net::Ipv4Addr;

use arcbox_fakeip::proxy_detect::ProxyEnvironment;
use tokio::sync::oneshot;

/// The flow a SYN opened — everything a resolver needs to decide egress.
#[derive(Clone, Debug)]
pub struct FlowMeta {
    pub src_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_ip: Ipv4Addr,
    pub dst_port: u16,
    /// Destination domain recovered from the DNS log, if known.
    pub domain: Option<String>,
}

/// A resolved egress transport.
///
/// Currently always a real fd, which the bridge splices on the fast path. A
/// boxed-stream variant for relayed (no-fd) encrypted protocols will be added
/// together with its bridge relay implementation, rather than reserved ahead of
/// a consumer.
pub enum EgressConn {
    /// Has a real fd → the bridge splices it on the fast path.
    Tcp(tokio::net::TcpStream),
}

/// Decides + establishes egress for a flow. Injected into the bridge so a
/// consumer (e.g. an Inbound/Router/Outbound host) can replace the policy.
pub trait EgressResolver: Send + Sync {
    fn resolve(&self, flow: FlowMeta) -> oneshot::Receiver<Option<EgressConn>>;
}

/// A terminated fast-path flow's 4-tuple — the key handed to a [`FlowObserver`].
/// A public mirror of the bridge's internal flow key (whose fields are private).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_ip: Ipv4Addr,
    pub dst_port: u16,
}

/// Observes the byte totals of fast-path flows the bridge spliced.
///
/// Those bytes are otherwise invisible to the [`EgressResolver`] host, which only
/// hands in the egress stream and never sees what transits it. Injected into the
/// bridge (mirroring [`EgressResolver`]) so a consumer can account per-flow traffic.
pub trait FlowObserver: Send + Sync {
    /// Called once when a fast-path flow is torn down (guest FIN/RST, host EOF,
    /// or an I/O error). `up_bytes` = guest→host (client→server), `down_bytes` =
    /// host→guest (server→client).
    fn on_flow_close(&self, key: FlowKey, up_bytes: u64, down_bytes: u64);
}

/// Default egress policy reproducing the TCP bridge's historical inline behavior.
///
/// Resolves a system-proxy CONNECT/SOCKS5 target (or direct), translates the
/// gateway IP to loopback, and dials with a connect timeout.
pub struct DefaultEgress {
    gateway_ip: Ipv4Addr,
    proxy_env: Option<ProxyEnvironment>,
    connect_timeout_secs: u64,
}

impl DefaultEgress {
    pub fn new(
        gateway_ip: Ipv4Addr,
        proxy_env: Option<ProxyEnvironment>,
        connect_timeout_secs: u64,
    ) -> Self {
        Self {
            gateway_ip,
            proxy_env,
            connect_timeout_secs,
        }
    }

    /// Determines whether to connect via a proxy tunnel for the given destination.
    ///
    /// Returns `Some((proxy_authority, target_host, target_port, protocol))` if a
    /// proxy should be used, or `None` for direct connection. The proxy authority
    /// is a `"host:port"` string that `TcpStream::connect` can resolve (supports
    /// both IP addresses and hostnames like `proxy.corp.com`).
    fn resolve_proxy_target(
        &self,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        domain: Option<&str>,
    ) -> Option<(String, String, u16, &'static str)> {
        let env = self.proxy_env.as_ref()?;

        // No proxy configured → always direct.
        if !env.has_usable_proxy() {
            return None;
        }

        // A usable proxy is configured (checked above), so every destination is
        // tunnelled through it — including IP literals and DNS-log misses, not
        // just Fake-IP. Resolve the CONNECT/SOCKS5 target host: the recovered
        // domain when known, otherwise the destination IP string, which the
        // proxy resolves on its end (Surge does this). Fake-IP destinations
        // (198.18.0.0/15) without a recovered domain fall here too and are
        // mapped back by the proxy.
        let host = match domain {
            Some(d) => d.to_string(),
            None => dst_ip.to_string(),
        };

        // Honor the bypass list (direct for excepted hosts).
        if env.should_bypass(&host) {
            return None;
        }

        // Prefer SOCKS5 (supports all protocols and avoids TLS issues),
        // then HTTPS proxy (HTTP CONNECT works on any port, not just 443),
        // then HTTP proxy as last resort.
        if let Some(ref socks) = env.socks_proxy {
            let authority = format!("{}:{}", socks.host, socks.port);
            return Some((authority, host, dst_port, "socks5"));
        }

        if let Some(ref https) = env.https_proxy {
            let authority = format!("{}:{}", https.host, https.port);
            return Some((authority, host, dst_port, "http-connect"));
        }

        if let Some(ref http) = env.http_proxy {
            let authority = format!("{}:{}", http.host, http.port);
            return Some((authority, host, dst_port, "http-connect"));
        }

        None
    }
}

impl EgressResolver for DefaultEgress {
    fn resolve(&self, flow: FlowMeta) -> oneshot::Receiver<Option<EgressConn>> {
        let proxy_target =
            self.resolve_proxy_target(flow.dst_ip, flow.dst_port, flow.domain.as_deref());
        // Direct connect target. Gateway IP → loopback for host.docker.internal.
        let target_ip = if flow.dst_ip == self.gateway_ip {
            Ipv4Addr::LOCALHOST
        } else {
            flow.dst_ip
        };
        let connect_addr =
            std::net::SocketAddr::V4(std::net::SocketAddrV4::new(target_ip, flow.dst_port));
        let timeout_secs = self.connect_timeout_secs;
        let (tx, rx) = oneshot::channel();
        tokio::spawn(async move {
            let connect = async {
                match proxy_target {
                    // SOCKS5 (preferred): the proxy resolves the hostname.
                    Some((authority, host, port, "socks5")) => {
                        arcbox_proxy::socks5::connect_via_socks5(&authority, &host, port).await
                    }
                    // HTTP CONNECT (https/http system proxy).
                    Some((authority, host, port, _)) => {
                        arcbox_proxy::http_connect::connect_via_http_proxy(&authority, &host, port)
                            .await
                    }
                    // No proxy configured / bypassed → direct.
                    None => tokio::net::TcpStream::connect(connect_addr).await,
                }
            };
            let stream =
                tokio::time::timeout(std::time::Duration::from_secs(timeout_secs), connect)
                    .await
                    .ok()
                    .and_then(Result::ok);
            let _ = tx.send(stream.map(EgressConn::Tcp));
        });
        rx
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arcbox_fakeip::proxy_detect::ProxyConfig;

    fn env(http: bool, https: bool, socks: bool) -> ProxyEnvironment {
        let cfg = |port| {
            Some(ProxyConfig {
                host: "127.0.0.1".to_string(),
                port,
            })
        };
        ProxyEnvironment {
            fake_ip_active: false,
            http_proxy: if http { cfg(3128) } else { None },
            https_proxy: if https { cfg(3129) } else { None },
            socks_proxy: if socks { cfg(1080) } else { None },
            bypass_domains: vec![],
        }
    }

    fn egress(env: Option<ProxyEnvironment>) -> DefaultEgress {
        DefaultEgress::new(Ipv4Addr::new(10, 0, 0, 1), env, 5)
    }

    // Regression: a domain-less, non-Fake-IP destination must still be proxied
    // (via the IP literal) when a system proxy is configured, instead of
    // bypassing to a direct connect.
    #[test]
    fn domainless_ip_dst_proxied_via_socks() {
        let eg = egress(Some(env(false, false, true)));
        assert_eq!(
            eg.resolve_proxy_target(Ipv4Addr::new(1, 2, 3, 4), 443, None),
            Some((
                "127.0.0.1:1080".to_string(),
                "1.2.3.4".to_string(),
                443,
                "socks5"
            )),
        );
    }

    #[test]
    fn domainless_ip_dst_proxied_via_https_then_http() {
        // HTTPS preferred over HTTP.
        let eg = egress(Some(env(true, true, false)));
        assert_eq!(
            eg.resolve_proxy_target(Ipv4Addr::new(1, 2, 3, 4), 80, None),
            Some((
                "127.0.0.1:3129".to_string(),
                "1.2.3.4".to_string(),
                80,
                "http-connect"
            )),
        );
        // HTTP only.
        let eg = egress(Some(env(true, false, false)));
        assert_eq!(
            eg.resolve_proxy_target(Ipv4Addr::new(1, 2, 3, 4), 80, None),
            Some((
                "127.0.0.1:3128".to_string(),
                "1.2.3.4".to_string(),
                80,
                "http-connect"
            )),
        );
    }

    // SOCKS5 wins when several proxies are present.
    #[test]
    fn socks_preferred_over_http_proxies() {
        let eg = egress(Some(env(true, true, true)));
        let got = eg.resolve_proxy_target(Ipv4Addr::new(1, 2, 3, 4), 443, None);
        assert_eq!(got.unwrap().3, "socks5");
    }

    // No usable proxy → direct, regardless of domain.
    #[test]
    fn no_proxy_is_direct() {
        let eg = egress(Some(env(false, false, false)));
        assert_eq!(
            eg.resolve_proxy_target(Ipv4Addr::new(1, 2, 3, 4), 443, Some("example.com")),
            None,
        );
        assert_eq!(
            egress(None).resolve_proxy_target(Ipv4Addr::new(1, 2, 3, 4), 443, None),
            None,
        );
    }
}
