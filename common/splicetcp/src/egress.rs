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
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::oneshot;

/// Boxed bidirectional stream (for relay-path egress; see EgressConn::Stream).
pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin + ?Sized> AsyncReadWrite for T {}

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
pub enum EgressConn {
    /// Has a real fd → the bridge splices it on the fast path.
    Tcp(tokio::net::TcpStream),
    /// No fd (e.g. an in-process encrypted protocol) → relayed. NOT YET
    /// IMPLEMENTED in the bridge (M4); the default resolver never returns it.
    Stream(Box<dyn AsyncReadWrite>),
}

/// Decides + establishes egress for a flow. Injected into the bridge so a
/// consumer (e.g. an Inbound/Router/Outbound host) can replace the policy.
pub trait EgressResolver: Send + Sync {
    fn resolve(&self, flow: FlowMeta) -> oneshot::Receiver<Option<EgressConn>>;
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

        // Check fake-ip BEFORE requiring a domain name. Fake-IP destinations
        // (198.18.0.0/15 from Surge/ClashX) always need proxy routing, even
        // if the DNS log hasn't recorded the domain yet (race between DNS
        // response and TCP SYN). Use the IP as fallback CONNECT target.
        let is_fake = env.is_fake_ip(dst_ip);

        // Resolve the host for the CONNECT/SOCKS5 tunnel target.
        // For fake-IP without domain, fall back to the IP string — the proxy
        // will resolve it on its end (Surge handles this correctly).
        let host = match domain {
            Some(d) => d.to_string(),
            None if is_fake => dst_ip.to_string(),
            None => return None,
        };

        // Check bypass list.
        if env.should_bypass(&host) {
            return None;
        }

        // Proxy fake-ip destinations and traffic when an explicit system proxy
        // is configured (corporate proxy environments).
        let need_proxy = is_fake
            || env.http_proxy.is_some()
            || env.https_proxy.is_some()
            || env.socks_proxy.is_some();
        if !need_proxy {
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
                        arcbox_proxy::proxy_tunnel::connect_via_socks5(&authority, &host, port).await
                    }
                    // HTTP CONNECT (https/http system proxy).
                    Some((authority, host, port, _)) => {
                        arcbox_proxy::proxy_tunnel::connect_via_http_proxy(&authority, &host, port)
                            .await
                    }
                    // No proxy configured / bypassed → direct.
                    None => tokio::net::TcpStream::connect(connect_addr).await,
                }
            };
            let stream = tokio::time::timeout(std::time::Duration::from_secs(timeout_secs), connect)
                .await
                .ok()
                .and_then(Result::ok);
            let _ = tx.send(stream.map(EgressConn::Tcp));
        });
        rx
    }
}
