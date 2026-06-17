//! Proxy tunnel implementations: HTTP CONNECT and SOCKS5.
//!
//! Used by [`TcpBridge`] when the host has a system proxy configured, to
//! connect using the domain name (from [`DnsResolutionLog`]) rather than the
//! raw IP address. This is critical for fake-ip proxy environments where the
//! destination IP is a virtual address that only the proxy can resolve.

use std::io;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Establishes a TCP tunnel via an HTTP CONNECT proxy (RFC 7231 §4.3.6).
///
/// The returned `TcpStream` is an end-to-end tunnel — all subsequent reads
/// and writes go directly to the target host through the proxy.
pub async fn connect_via_http_proxy(proxy: &str, host: &str, port: u16) -> io::Result<TcpStream> {
    let mut stream = TcpStream::connect(proxy).await?;

    let request = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n");
    stream.write_all(request.as_bytes()).await?;

    // Read until we find "\r\n" marking the end of the status line. The
    // response may arrive split across multiple TCP segments, so we loop.
    let mut buf = Vec::with_capacity(256);
    let mut tmp = [0u8; 1];
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "proxy closed connection before completing status line",
            ));
        }
        buf.push(tmp[0]);
        if buf.ends_with(b"\r\n") {
            break;
        }
        if buf.len() > 1024 {
            return Err(io::Error::other(
                "HTTP CONNECT status line exceeds 1024 bytes",
            ));
        }
    }

    let status_line = String::from_utf8_lossy(&buf);
    // Accept any 2xx status as success (200, 204, etc).
    let status_ok = status_line.starts_with("HTTP/1.1 2") || status_line.starts_with("HTTP/1.0 2");

    if !status_ok {
        let line = status_line.trim_end();
        return Err(io::Error::other(format!(
            "HTTP CONNECT proxy rejected: {line}"
        )));
    }

    // Consume remaining headers until a blank line. We already read the
    // status line (including its \r\n). The headers end with \r\n\r\n, so
    // we look for two consecutive \r\n sequences in the remaining data.
    let mut header_buf = Vec::with_capacity(512);
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        header_buf.push(tmp[0]);
        // A standalone \r\n (i.e. header_buf == b"\r\n") means the first
        // header line is blank → end of headers. Otherwise \r\n\r\n at the
        // tail means the previous header ended and a blank line followed.
        if header_buf.len() >= 2
            && header_buf.ends_with(b"\r\n")
            && (header_buf.len() == 2 || header_buf[..header_buf.len() - 2].ends_with(b"\r\n"))
        {
            break;
        }
        if header_buf.len() > 8192 {
            return Err(io::Error::other(
                "HTTP CONNECT response headers exceed 8192 bytes",
            ));
        }
    }

    tracing::debug!(
        proxy = proxy,
        target = %format!("{host}:{port}"),
        "HTTP CONNECT tunnel established"
    );
    Ok(stream)
}

/// Establishes a TCP tunnel via a SOCKS5 proxy (RFC 1928, no-auth subset).
///
/// Uses ATYP=0x03 (domain name) so the proxy resolves the hostname, avoiding
/// fake-ip issues entirely.
pub async fn connect_via_socks5(proxy: &str, host: &str, port: u16) -> io::Result<TcpStream> {
    use crate::socks5::{self, VER};

    let mut stream = TcpStream::connect(proxy).await?;

    // Phase 1: no-auth greeting (shared with the UDP-ASSOCIATE client).
    socks5::greet(&mut stream).await?;

    // Phase 2: CONNECT request. The shared codec sends a domain by name (so the
    // proxy resolves it — no fake-ip leak) and IP literals as ATYP v4/v6.
    let mut req = vec![VER, 0x01, 0x00]; // VER | CMD=CONNECT | RSV
    socks5::encode_addr(&mut req, host, port);
    stream.write_all(&req).await?;

    // Phase 3: response — [VER, REP, RSV] then the bind address (discarded).
    let mut hdr = [0u8; 3];
    stream.read_exact(&mut hdr).await?;
    if hdr[0] != VER {
        return Err(io::Error::other(format!(
            "SOCKS5: unexpected version in response: {}",
            hdr[0]
        )));
    }
    if hdr[1] != 0x00 {
        return Err(socks5::rep_error(hdr[1]));
    }
    let _bind = socks5::read_addr(&mut stream).await?;

    tracing::debug!(
        proxy = %proxy,
        target = %format!("{host}:{port}"),
        "SOCKS5 tunnel established"
    );
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    /// Minimal no-auth SOCKS5 server: validates the client's greeting and
    /// domain-ATYP CONNECT request, replies success, then echoes one message
    /// back through the established tunnel.
    async fn mock_socks5(listener: TcpListener, expect_host: &'static str, expect_port: u16) {
        let (mut s, _) = listener.accept().await.unwrap();

        // Greeting: VER=5, NMETHODS=1, METHODS=[0x00].
        let mut greeting = [0u8; 3];
        s.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [0x05, 0x01, 0x00], "client greeting");
        s.write_all(&[0x05, 0x00]).await.unwrap(); // choose no-auth

        // Connect request: VER, CMD=CONNECT, RSV, ATYP=domain.
        let mut hdr = [0u8; 4];
        s.read_exact(&mut hdr).await.unwrap();
        assert_eq!(hdr, [0x05, 0x01, 0x00, 0x03], "connect request header");
        let mut len = [0u8; 1];
        s.read_exact(&mut len).await.unwrap();
        let mut host = vec![0u8; len[0] as usize];
        s.read_exact(&mut host).await.unwrap();
        let mut port = [0u8; 2];
        s.read_exact(&mut port).await.unwrap();
        assert_eq!(host, expect_host.as_bytes(), "CONNECT host (by name)");
        assert_eq!(u16::from_be_bytes(port), expect_port, "CONNECT port");

        // Reply: success, ATYP=IPv4, BND.ADDR=0.0.0.0, BND.PORT=0.
        s.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();

        // Tunnel is now end-to-end; echo one payload.
        let mut buf = [0u8; 5];
        s.read_exact(&mut buf).await.unwrap();
        s.write_all(&buf).await.unwrap();
    }

    #[tokio::test]
    async fn socks5_connects_by_domain_and_tunnels() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(mock_socks5(listener, "example.com", 443));

        let mut stream = connect_via_socks5(&addr.to_string(), "example.com", 443)
            .await
            .expect("SOCKS5 handshake should complete");

        // The returned stream is an end-to-end tunnel through the proxy.
        stream.write_all(b"hello").await.unwrap();
        let mut got = [0u8; 5];
        stream.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"hello", "payload round-trips through the tunnel");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn socks5_propagates_server_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            s.read_exact(&mut greeting).await.unwrap();
            s.write_all(&[0x05, 0x00]).await.unwrap();
            // Drain the connect request, then reply REP=0x05 (connection refused).
            let mut hdr = [0u8; 4];
            s.read_exact(&mut hdr).await.unwrap();
            let mut len = [0u8; 1];
            s.read_exact(&mut len).await.unwrap();
            let mut rest = vec![0u8; len[0] as usize + 2];
            s.read_exact(&mut rest).await.unwrap();
            s.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });

        let err = connect_via_socks5(&addr.to_string(), "blocked.example", 443)
            .await
            .expect_err("server failure must surface as an error");
        assert!(err.to_string().contains("connection refused"), "{err}");
    }

    /// Minimal HTTP CONNECT proxy: validates the request line and replies 200.
    #[tokio::test]
    async fn http_connect_establishes_tunnel() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            let mut byte = [0u8; 1];
            while !buf.ends_with(b"\r\n\r\n") {
                s.read_exact(&mut byte).await.unwrap();
                buf.push(byte[0]);
            }
            let req = String::from_utf8_lossy(&buf);
            assert!(req.starts_with("CONNECT example.com:443 HTTP/1.1"), "{req}");
            s.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
            let mut echo = [0u8; 3];
            s.read_exact(&mut echo).await.unwrap();
            s.write_all(&echo).await.unwrap();
        });

        let mut stream = connect_via_http_proxy(&addr.to_string(), "example.com", 443)
            .await
            .expect("HTTP CONNECT should establish");
        stream.write_all(b"abc").await.unwrap();
        let mut got = [0u8; 3];
        stream.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"abc");
        server.await.unwrap();
    }
}
