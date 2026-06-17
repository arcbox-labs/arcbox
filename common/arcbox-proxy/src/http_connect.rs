//! HTTP CONNECT proxy client.
//!
//! Used when the host has a system HTTP proxy configured, to tunnel a TCP
//! connection by hostname (from the `DnsResolutionLog`) rather than the raw IP —
//! critical for fake-IP environments where the destination IP only the proxy can
//! resolve. The SOCKS5 equivalent lives in [`crate::socks5`].

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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

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
