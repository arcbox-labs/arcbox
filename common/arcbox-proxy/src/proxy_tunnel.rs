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
    let mut stream = TcpStream::connect(proxy).await?;

    // Phase 1: Greeting — version=5, 1 method (no auth).
    stream.write_all(&[0x05, 0x01, 0x00]).await?;

    let mut greeting_resp = [0u8; 2];
    stream.read_exact(&mut greeting_resp).await?;

    if greeting_resp[0] != 0x05 {
        return Err(io::Error::other(format!(
            "SOCKS5: unsupported version {}",
            greeting_resp[0]
        )));
    }
    if greeting_resp[1] != 0x00 {
        return Err(io::Error::other(format!(
            "SOCKS5: server chose unsupported auth method 0x{:02X} (expected 0x00 no-auth)",
            greeting_resp[1]
        )));
    }

    // Phase 2: Connect request — ATYP=0x03 (domain name).
    let host_bytes = host.as_bytes();
    if host_bytes.len() > 255 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "SOCKS5: domain name too long",
        ));
    }

    let mut req = Vec::with_capacity(7 + host_bytes.len());
    req.push(0x05); // version
    req.push(0x01); // cmd: CONNECT
    req.push(0x00); // reserved
    req.push(0x03); // atyp: domain name
    req.push(host_bytes.len() as u8);
    req.extend_from_slice(host_bytes);
    req.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&req).await?;

    // Phase 3: Parse response incrementally.
    // Read the 4-byte header: [VER, REP, RSV, ATYP].
    let mut hdr = [0u8; 4];
    stream.read_exact(&mut hdr).await?;

    if hdr[0] != 0x05 {
        return Err(io::Error::other(format!(
            "SOCKS5: unexpected version in response: {}",
            hdr[0]
        )));
    }

    if hdr[1] != 0x00 {
        let reason = match hdr[1] {
            0x01 => "general SOCKS server failure",
            0x02 => "connection not allowed by ruleset",
            0x03 => "network unreachable",
            0x04 => "host unreachable",
            0x05 => "connection refused",
            0x06 => "TTL expired",
            0x07 => "command not supported",
            0x08 => "address type not supported",
            _ => "unknown error",
        };
        return Err(io::Error::other(format!(
            "SOCKS5: connect failed: {reason} (code {})",
            hdr[1]
        )));
    }

    // Consume the bind address based on ATYP. We discard the data.
    match hdr[3] {
        0x01 => {
            // IPv4: 4 bytes address + 2 bytes port.
            let mut buf = [0u8; 6];
            stream.read_exact(&mut buf).await?;
        }
        0x04 => {
            // IPv6: 16 bytes address + 2 bytes port.
            let mut buf = [0u8; 18];
            stream.read_exact(&mut buf).await?;
        }
        0x03 => {
            // Domain: 1 byte length, N bytes domain, 2 bytes port.
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf).await?;
            let dlen = len_buf[0] as usize;
            let mut domain_and_port = vec![0u8; dlen + 2];
            stream.read_exact(&mut domain_and_port).await?;
        }
        atyp => {
            return Err(io::Error::other(format!(
                "SOCKS5: unsupported ATYP 0x{atyp:02X} in response"
            )));
        }
    }

    tracing::debug!(
        proxy = %proxy,
        target = %format!("{host}:{port}"),
        "SOCKS5 tunnel established"
    );
    Ok(stream)
}

#[cfg(test)]
mod tests {
    // Integration tests require a running proxy server. These are tested
    // manually against Surge/Clash in development.
    //
    // TODO: Add mock proxy server tests.
}
