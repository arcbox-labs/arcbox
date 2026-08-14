//! Async UDP DNS server for the runtime's configured local domain.
//!
//! Listens on `127.0.0.1:{port}` and resolves container hostnames registered
//! via [`NetworkManager`]. Queries for unregistered names in that domain
//! get an NXDOMAIN response; all other queries are forwarded to upstream DNS.

use anyhow::{Context, Result};
use arcbox_net::NetworkManager;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

/// Async UDP DNS server backed by [`NetworkManager`]'s DNS forwarder.
pub struct DnsService {
    network_manager: Arc<NetworkManager>,
    socket: UdpSocket,
}

impl DnsService {
    /// Binds the UDP socket on `127.0.0.1:{port}`.
    ///
    /// Called eagerly at daemon startup so that a bind failure (port already in
    /// use) propagates up and aborts the daemon before it enters the main loop.
    pub async fn bind(network_manager: Arc<NetworkManager>, port: u16) -> Result<Self> {
        let addr = format!("127.0.0.1:{port}");
        let socket = UdpSocket::bind(&addr)
            .await
            .with_context(|| format!("DNS service failed to bind {addr}"))?;
        let actual_addr = socket
            .local_addr()
            .context("Failed to read DNS service address")?;

        tracing::info!(%actual_addr, "DNS service bound");
        Ok(Self {
            network_manager,
            socket,
        })
    }

    /// Returns the actual UDP port selected by the bound socket.
    ///
    /// # Errors
    ///
    /// Returns an error if the socket address cannot be queried.
    pub fn host_port(&self) -> Result<u16> {
        Ok(self
            .socket
            .local_addr()
            .context("Failed to read DNS service address")?
            .port())
    }

    /// Runs the DNS event loop. Only called after [`Self::bind`] succeeds.
    ///
    /// This method never returns under normal operation. Each incoming UDP
    /// packet is handled inline for local queries (fast path) or dispatched
    /// to a blocking task for upstream forwarding (slow path).
    pub async fn run(self, shutdown: CancellationToken) -> Result<()> {
        let mut buf = [0u8; 512];
        let socket = Arc::new(self.socket);

        loop {
            let (len, src) = tokio::select! {
                result = socket.recv_from(&mut buf) => result?,
                () = shutdown.cancelled() => {
                    tracing::info!("DNS service shutting down");
                    return Ok(());
                }
            };

            // Fast path: local resolution or NXDOMAIN for the configured domain.
            // Operates on a borrowed slice to avoid allocation.
            if let Some(response) = self
                .network_manager
                .try_resolve_dns_or_nxdomain(&buf[..len])
            {
                if let Err(e) = socket.send_to(&response, src).await {
                    tracing::debug!("Failed to send DNS response to {}: {}", src, e);
                }
                continue;
            }

            // Slow path: forward to upstream DNS via blocking I/O.
            // Only clone into owned buffer when actually needed.
            let query = buf[..len].to_vec();
            let nm = Arc::clone(&self.network_manager);
            let sock = Arc::clone(&socket);
            tokio::spawn(async move {
                // Pre-build SERVFAIL before query is moved into spawn_blocking.
                let servfail = build_servfail(&query);
                let result = tokio::task::spawn_blocking(move || nm.handle_dns_query(&query))
                    .await
                    .ok()
                    .and_then(|r| r.ok());

                match result {
                    Some(response) => {
                        if let Err(e) = sock.send_to(&response, src).await {
                            tracing::debug!("Failed to send DNS response to {}: {}", src, e);
                        }
                    }
                    None => {
                        // Send SERVFAIL so the client fails fast instead of timing out.
                        if let Some(servfail) = servfail {
                            let _ = sock.send_to(&servfail, src).await;
                        }
                        tracing::debug!("Upstream DNS forwarding failed for query from {}", src);
                    }
                }
            });
        }
    }
}

/// Builds a SERVFAIL response from the original query bytes.
fn build_servfail(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let mut response = query.to_vec();
    // QR=1, RD preserved, RCODE=2 (SERVFAIL)
    response[2] |= 0x80; // set QR
    response[3] = (response[3] & 0xF0) | 0x02; // RCODE=SERVFAIL
    // Zero answer/authority counts; keep question.
    response[6] = 0x00;
    response[7] = 0x00;
    response[8] = 0x00;
    response[9] = 0x00;
    response[10] = 0x00;
    response[11] = 0x00;
    // Truncate to just header + question (strip any additional sections).
    // For simplicity, return the full query as response — the counts are zeroed
    // so extra bytes are harmless, and most DNS libraries ignore trailing data.
    Some(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// Builds a minimal DNS query packet for a given domain name (A record, IN class).
    fn build_dns_query(name: &str) -> Vec<u8> {
        let mut packet = Vec::with_capacity(64);
        // Header: ID=0x1234, QR=0, QDCOUNT=1
        packet.extend_from_slice(&[0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00]);
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        // Question: encode name labels
        for label in name.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0x00); // root label
        packet.extend_from_slice(&[0x00, 0x01]); // QTYPE = A
        packet.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN
        packet
    }

    #[tokio::test]
    async fn test_dns_bind_fail_fast() {
        // Occupy a port, then verify DnsService::bind on the same port fails.
        let blocker = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = blocker.local_addr().unwrap().port();

        let nm = Arc::new(NetworkManager::new(arcbox_net::NetConfig::default()));
        let result = DnsService::bind(nm, port).await;
        assert!(
            result.is_err(),
            "expected DnsService::bind to fail on occupied port"
        );
    }

    #[tokio::test]
    async fn test_dns_local_resolution_roundtrip() {
        let nm = Arc::new(NetworkManager::new(arcbox_net::NetConfig::default()));
        let ip = std::net::IpAddr::V4(Ipv4Addr::new(172, 17, 0, 2));
        nm.register_dns("my-nginx", ip);

        // Bind server on random port via DnsService::bind.
        let service = DnsService::bind(Arc::clone(&nm), 0).await.unwrap();
        let server_addr = ("127.0.0.1", service.host_port().unwrap());

        let server_handle =
            tokio::spawn(async move { service.run(CancellationToken::new()).await });

        // Send query from client.
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let query = build_dns_query("my-nginx.arcbox.local");
        client.send_to(&query, server_addr).await.unwrap();

        let mut buf = [0u8; 512];
        let (len, _) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.recv_from(&mut buf),
        )
        .await
        .expect("DNS response timeout")
        .unwrap();

        let response = &buf[..len];
        // Verify it's a response (QR=1) with RCODE=0 (no error) and ANCOUNT=1.
        assert_eq!(response[2] & 0x80, 0x80, "QR bit should be set");
        assert_eq!(response[3] & 0x0F, 0, "RCODE should be 0 (NoError)");
        assert_eq!(response[7], 1, "ANCOUNT should be 1");

        // Extract the A record IP from the answer section.
        let answer_start = 12 + query.len() - 12; // skip header + question
        let rdata_offset = answer_start + 2 + 2 + 2 + 4 + 2; // name_ptr + type + class + ttl + rdlen
        let ip_bytes = &response[rdata_offset..rdata_offset + 4];
        assert_eq!(ip_bytes, &[172, 17, 0, 2]);

        server_handle.abort();
    }

    #[tokio::test]
    async fn test_dns_nxdomain_for_unregistered_local() {
        let nm = Arc::new(NetworkManager::new(arcbox_net::NetConfig::default()));
        // Don't register anything — query should get NXDOMAIN.

        let service = DnsService::bind(Arc::clone(&nm), 0).await.unwrap();
        let server_addr = ("127.0.0.1", service.host_port().unwrap());

        let server_handle =
            tokio::spawn(async move { service.run(CancellationToken::new()).await });

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let query = build_dns_query("nonexistent.arcbox.local");
        client.send_to(&query, server_addr).await.unwrap();

        let mut buf = [0u8; 512];
        let (len, _) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.recv_from(&mut buf),
        )
        .await
        .expect("DNS response timeout")
        .unwrap();

        let response = &buf[..len];
        // Verify NXDOMAIN: QR=1, RCODE=3.
        assert_eq!(response[2] & 0x80, 0x80, "QR bit should be set");
        assert_eq!(response[3] & 0x0F, 3, "RCODE should be 3 (NXDOMAIN)");
        assert_eq!(response[7], 0, "ANCOUNT should be 0");

        server_handle.abort();
    }

    #[test]
    fn test_build_servfail() {
        let query = build_dns_query("example.com");
        let response = build_servfail(&query).unwrap();
        assert_eq!(response[2] & 0x80, 0x80, "QR bit should be set");
        assert_eq!(response[3] & 0x0F, 2, "RCODE should be 2 (SERVFAIL)");
        assert_eq!(response[7], 0, "ANCOUNT should be 0");
    }

    #[test]
    fn test_build_servfail_too_short() {
        assert!(build_servfail(&[0; 5]).is_none());
    }
}
