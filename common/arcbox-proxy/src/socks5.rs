//! SOCKS5 (RFC 1928) shared primitives + the UDP-ASSOCIATE client.
//!
//! The greeting and the ATYP address codec are the single source of truth for
//! the SOCKS5 address wire format, shared by the CONNECT tunnel client
//! ([`connect_via_socks5`]), the UDP-ASSOCIATE client ([`Socks5UdpAssociation`]),
//! and (cross-crate) the downstream aroxy Shadowsocks / Trojan target encoders —
//! all of which use the same `ATYP | ADDR | PORT` layout. The latter lets arcbox
//! (and aroxy) route guest UDP through an upstream SOCKS5 proxy.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio_util::sync::CancellationToken;

/// SOCKS protocol version (5).
pub(crate) const VER: u8 = 0x05;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
/// Upper bound on the UDP ASSOCIATE handshake (TCP connect + greeting + reply).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Performs the no-auth SOCKS5 greeting on an established control stream: sends
/// `[VER, 1, 0x00]` and requires the server to select method `0x00`.
pub(crate) async fn greet(stream: &mut TcpStream) -> io::Result<()> {
    stream.write_all(&[VER, 0x01, 0x00]).await?;
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await?;
    if resp[0] != VER {
        return Err(io::Error::other(format!(
            "SOCKS5: unsupported version {}",
            resp[0]
        )));
    }
    if resp[1] != 0x00 {
        return Err(io::Error::other(format!(
            "SOCKS5: server chose unsupported auth method 0x{:02X} (expected 0x00 no-auth)",
            resp[1]
        )));
    }
    Ok(())
}

/// Appends a SOCKS5 address (`ATYP | ADDR | PORT`) to `out`. IP-literal hosts
/// use ATYP v4/v6; everything else is sent as a domain name (ATYP 0x03) so the
/// proxy resolves it — avoiding fake-IP leaks.
pub fn encode_addr(out: &mut Vec<u8>, host: &str, port: u16) {
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            out.push(ATYP_IPV4);
            out.extend_from_slice(&ip.octets());
        }
        Ok(IpAddr::V6(ip)) => {
            out.push(ATYP_IPV6);
            out.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            out.push(ATYP_DOMAIN);
            // DNS names are ≤253 bytes, so the 1-byte length field always fits; a
            // longer `host` is malformed and cannot occur for a real destination,
            // so the cap is a defensive no-op rather than a silent corruption.
            let bytes = host.as_bytes();
            let len = bytes.len().min(255);
            out.push(len as u8);
            out.extend_from_slice(&bytes[..len]);
        }
    }
    out.extend_from_slice(&port.to_be_bytes());
}

/// Decodes a SOCKS5 address from the front of `buf`, returning
/// `(host, port, bytes_consumed)`, or `None` if truncated / bad ATYP / non-UTF8
/// domain.
#[must_use]
pub fn decode_addr(buf: &[u8]) -> Option<(String, u16, usize)> {
    let (host, after) = match *buf.first()? {
        ATYP_IPV4 => {
            let o: [u8; 4] = buf.get(1..5)?.try_into().ok()?;
            (Ipv4Addr::from(o).to_string(), 5)
        }
        ATYP_IPV6 => {
            let o: [u8; 16] = buf.get(1..17)?.try_into().ok()?;
            (Ipv6Addr::from(o).to_string(), 17)
        }
        ATYP_DOMAIN => {
            let len = *buf.get(1)? as usize;
            let name = std::str::from_utf8(buf.get(2..2 + len)?).ok()?.to_string();
            (name, 2 + len)
        }
        _ => return None,
    };
    let port = u16::from_be_bytes([*buf.get(after)?, *buf.get(after + 1)?]);
    Some((host, port, after + 2))
}

/// Reads a SOCKS5 address (`ATYP | ADDR | PORT`) from any async stream. Domains
/// are decoded strictly (non-UTF8 is an error, matching [`decode_addr`]).
pub async fn read_addr<R: AsyncReadExt + Unpin>(r: &mut R) -> io::Result<(String, u16)> {
    let mut atyp = [0u8; 1];
    r.read_exact(&mut atyp).await?;
    let host = match atyp[0] {
        ATYP_IPV4 => {
            let mut o = [0u8; 4];
            r.read_exact(&mut o).await?;
            Ipv4Addr::from(o).to_string()
        }
        ATYP_IPV6 => {
            let mut o = [0u8; 16];
            r.read_exact(&mut o).await?;
            Ipv6Addr::from(o).to_string()
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            r.read_exact(&mut len).await?;
            let mut name = vec![0u8; len[0] as usize];
            r.read_exact(&mut name).await?;
            String::from_utf8(name).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "SOCKS5: non-UTF8 domain")
            })?
        }
        other => {
            return Err(io::Error::other(format!(
                "SOCKS5: unsupported ATYP 0x{other:02X} in response"
            )));
        }
    };
    let mut port = [0u8; 2];
    r.read_exact(&mut port).await?;
    Ok((host, u16::from_be_bytes(port)))
}

/// Maps a SOCKS5 REP error code to an `io::Error` (RFC 1928 §6).
pub(crate) fn rep_error(code: u8) -> io::Error {
    let reason = match code {
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
    io::Error::other(format!("SOCKS5: request failed: {reason} (code {code})"))
}

/// Establishes a TCP tunnel via a SOCKS5 proxy (RFC 1928 CONNECT, no-auth subset).
///
/// Hostnames are sent as ATYP=domain so the proxy resolves them (no fake-IP
/// leak); IP literals use ATYP v4/v6. The returned stream is an end-to-end
/// tunnel to `host:port`.
pub async fn connect_via_socks5(proxy: &str, host: &str, port: u16) -> io::Result<TcpStream> {
    let mut stream = TcpStream::connect(proxy).await?;

    // Phase 1: no-auth greeting (shared with the UDP-ASSOCIATE client).
    greet(&mut stream).await?;

    // Phase 2: CONNECT request via the shared address codec.
    let mut req = vec![VER, 0x01, 0x00]; // VER | CMD=CONNECT | RSV
    encode_addr(&mut req, host, port);
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
        return Err(rep_error(hdr[1]));
    }
    let _bind = read_addr(&mut stream).await?;

    tracing::debug!(
        proxy = %proxy,
        target = %format!("{host}:{port}"),
        "SOCKS5 tunnel established"
    );
    Ok(stream)
}

/// Aborts the control-connection watcher task when the association is dropped,
/// which closes the control TCP stream the watcher owns — tearing down the
/// association (and the proxy's relay binding).
#[derive(Debug)]
struct WatcherGuard(tokio::task::JoinHandle<()>);

impl Drop for WatcherGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// A SOCKS5 UDP association (RFC 1928 §7).
///
/// The control TCP connection is owned by a watcher task that detects a
/// proxy-initiated close (EOF) and cancels [`closed`](Self::closed), so a dead
/// relay surfaces as an error instead of a silent black-hole. The local UDP
/// socket is connected to the proxy's relay endpoint; datagrams to arbitrary
/// targets carry their own address header, so one association serves a whole flow.
#[derive(Debug)]
pub struct Socks5UdpAssociation {
    socket: UdpSocket,
    /// Cancelled when the control connection closes; [`recv_from`](Self::recv_from)
    /// selects on it so a half-closed proxy is detected promptly.
    closed: CancellationToken,
    /// Aborts the control watcher (and thus closes control) on drop.
    _watcher: WatcherGuard,
}

impl Socks5UdpAssociation {
    /// Opens a UDP association via the no-auth SOCKS5 `proxy` (`host:port`),
    /// bounded by [`HANDSHAKE_TIMEOUT`].
    pub async fn associate(proxy: &str) -> io::Result<Self> {
        tokio::time::timeout(HANDSHAKE_TIMEOUT, Self::handshake(proxy))
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, "SOCKS5 UDP associate timed out")
            })?
    }

    async fn handshake(proxy: &str) -> io::Result<Self> {
        let mut control = TcpStream::connect(proxy).await?;
        greet(&mut control).await?;

        // UDP ASSOCIATE: DST.ADDR/PORT advertise where we'll send from. We don't
        // know our source port yet, so send the wildcard 0.0.0.0:0.
        let mut req = vec![VER, CMD_UDP_ASSOCIATE, 0x00];
        encode_addr(&mut req, "0.0.0.0", 0);
        control.write_all(&req).await?;

        // Reply: [VER, REP, RSV] then BND.ADDR / BND.PORT.
        let mut hdr = [0u8; 3];
        control.read_exact(&mut hdr).await?;
        if hdr[0] != VER {
            return Err(io::Error::other(format!(
                "SOCKS5: unexpected version in response: {}",
                hdr[0]
            )));
        }
        if hdr[1] != 0x00 {
            return Err(rep_error(hdr[1]));
        }
        let (bnd_host, bnd_port) = read_addr(&mut control).await?;

        // An unspecified BND.ADDR means "same host as the control connection" —
        // substitute the proxy's IP; otherwise honour the advertised relay.
        let relay: SocketAddr = match bnd_host.parse::<IpAddr>() {
            Ok(ip) if ip.is_unspecified() => {
                let mut peer = control.peer_addr()?;
                peer.set_port(bnd_port);
                peer
            }
            Ok(ip) => SocketAddr::new(ip, bnd_port),
            Err(_) => tokio::net::lookup_host((bnd_host.as_str(), bnd_port))
                .await?
                .next()
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "SOCKS5: BND address unresolved")
                })?,
        };

        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(relay).await?;

        // The control stream carries nothing after the handshake; a read that
        // completes means the proxy closed (EOF) or errored → tear the
        // association down. The watcher owns `control`, so dropping the
        // association (→ WatcherGuard::drop → abort) closes it.
        let closed = CancellationToken::new();
        let watcher_token = closed.clone();
        let watcher = tokio::spawn(async move {
            let mut control = control;
            let mut scratch = [0u8; 1];
            let _ = control.read(&mut scratch).await;
            watcher_token.cancel();
        });

        tracing::debug!(proxy = %proxy, relay = %relay, "SOCKS5 UDP association established");
        Ok(Self {
            socket,
            closed,
            _watcher: WatcherGuard(watcher),
        })
    }

    /// Sends `payload` to `host:port` through the proxy's UDP relay. The target
    /// is encoded by name when not an IP literal so the proxy resolves it.
    pub async fn send_to(&self, payload: &[u8], host: &str, port: u16) -> io::Result<usize> {
        let mut dgram = vec![0x00, 0x00, 0x00]; // RSV(2) | FRAG(0)
        encode_addr(&mut dgram, host, port);
        dgram.extend_from_slice(payload);
        self.socket.send(&dgram).await?;
        Ok(payload.len())
    }

    /// Receives one relayed datagram into `buf`, returning `Some((len, host,
    /// port))` with the inner payload moved to the front of `buf`, or `None` if
    /// the datagram is fragmented / malformed (skip it, the flow stays up). Errors
    /// only on a real socket error or a proxy-initiated control close.
    ///
    /// `buf` must be large enough for a full UDP datagram (65 535 bytes); a
    /// smaller buffer truncates at the OS recv as with any UDP socket.
    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<Option<(usize, String, u16)>> {
        let n = tokio::select! {
            () = self.closed.cancelled() => {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "SOCKS5 UDP: control connection closed",
                ));
            }
            r = self.socket.recv(buf) => r?,
        };

        // [RSV(2) | FRAG(1) | ATYP ADDR PORT | payload]. Drop fragments (FRAG!=0)
        // and anything too short to hold a header.
        if n < 4 || buf[2] != 0x00 {
            return Ok(None);
        }
        let Some((host, port, consumed)) = decode_addr(&buf[3..]) else {
            return Ok(None);
        };
        let start = 3 + consumed;
        if start > n {
            return Ok(None);
        }
        let len = n - start;
        buf.copy_within(start..n, 0);
        Ok(Some((len, host, port)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn addr_codec_round_trips() {
        for (host, port) in [("example.com", 443u16), ("1.2.3.4", 53), ("::1", 80)] {
            let mut buf = Vec::new();
            encode_addr(&mut buf, host, port);
            let (h, p, used) = decode_addr(&buf).expect("decodes");
            assert_eq!((h.as_str(), p, used), (host, port, buf.len()));
        }
    }

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

    /// Mock SOCKS5 UDP relay: completes the control handshake, advertises a real
    /// UDP relay socket as BND, then echoes one datagram back (re-headered with
    /// the decoded target as the source).
    async fn mock_socks5_udp(listener: TcpListener) {
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay.local_addr().unwrap();

        let (mut ctrl, _) = listener.accept().await.unwrap();
        let mut g = [0u8; 3];
        ctrl.read_exact(&mut g).await.unwrap();
        assert_eq!(g, [0x05, 0x01, 0x00], "greeting");
        ctrl.write_all(&[0x05, 0x00]).await.unwrap();

        // UDP ASSOCIATE request: [5, 3, 0, ATYP=1, 0.0.0.0, 0].
        let mut req = [0u8; 4];
        ctrl.read_exact(&mut req).await.unwrap();
        assert_eq!(&req[..2], &[0x05, 0x03], "UDP ASSOCIATE cmd");
        assert_eq!(req[3], 0x01, "wildcard DST is ATYP v4");
        let mut rest = [0u8; 6];
        ctrl.read_exact(&mut rest).await.unwrap();

        // Reply success, BND = the relay socket.
        let mut reply = vec![0x05, 0x00, 0x00];
        encode_addr(&mut reply, &relay_addr.ip().to_string(), relay_addr.port());
        ctrl.write_all(&reply).await.unwrap();

        // Relay one datagram: decode target + payload, echo it back.
        let mut buf = vec![0u8; 2048];
        let (n, client) = relay.recv_from(&mut buf).await.unwrap();
        let pkt = &buf[..n];
        assert_eq!(pkt[2], 0x00, "FRAG 0");
        let (host, port, consumed) = decode_addr(&pkt[3..]).unwrap();
        let payload = &pkt[3 + consumed..];
        let mut echo = vec![0x00, 0x00, 0x00];
        encode_addr(&mut echo, &host, port);
        echo.extend_from_slice(payload);
        relay.send_to(&echo, client).await.unwrap();

        // Hold the control conn open until the client has finished.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        drop(ctrl);
    }

    #[tokio::test]
    async fn udp_associate_round_trips_through_relay() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = listener.local_addr().unwrap();
        let server = tokio::spawn(mock_socks5_udp(listener));

        let assoc = Socks5UdpAssociation::associate(&proxy.to_string())
            .await
            .expect("association established");
        assoc.send_to(b"ping", "example.com", 53).await.unwrap();

        let mut buf = [0u8; 64];
        let (n, host, port) = assoc
            .recv_from(&mut buf)
            .await
            .unwrap()
            .expect("a deliverable datagram");
        assert_eq!(&buf[..n], b"ping", "payload round-trips through the relay");
        assert_eq!(
            (host.as_str(), port),
            ("example.com", 53),
            "target echoed back"
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn udp_associate_surfaces_rep_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut ctrl, _) = listener.accept().await.unwrap();
            let mut g = [0u8; 3];
            ctrl.read_exact(&mut g).await.unwrap();
            ctrl.write_all(&[0x05, 0x00]).await.unwrap();
            let mut req = [0u8; 4];
            ctrl.read_exact(&mut req).await.unwrap();
            let mut rest = [0u8; 6];
            ctrl.read_exact(&mut rest).await.unwrap();
            // REP = 0x07 (command not supported).
            ctrl.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });

        let err = Socks5UdpAssociation::associate(&proxy.to_string())
            .await
            .expect_err("REP failure surfaces");
        assert!(err.to_string().contains("command not supported"), "{err}");
    }

    /// A fragmented (FRAG!=0) relayed datagram is skipped (Ok(None)), not fatal.
    #[tokio::test]
    async fn fragmented_datagram_is_skipped_not_fatal() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = listener.local_addr().unwrap();
        tokio::spawn(async move {
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
            let mut reply = vec![0x05, 0x00, 0x00];
            encode_addr(&mut reply, &relay_addr.ip().to_string(), relay_addr.port());
            ctrl.write_all(&reply).await.unwrap();
            let (_n, client) = relay.recv_from(&mut [0u8; 64]).await.unwrap();
            // FRAG = 1 → must be skipped.
            let mut frag = vec![0x00, 0x00, 0x01];
            encode_addr(&mut frag, "1.2.3.4", 9);
            frag.extend_from_slice(b"x");
            relay.send_to(&frag, client).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(80)).await;
            drop(ctrl);
        });

        let assoc = Socks5UdpAssociation::associate(&proxy.to_string())
            .await
            .unwrap();
        assoc.send_to(b"hi", "1.2.3.4", 9).await.unwrap();
        let mut buf = [0u8; 64];
        let got = assoc.recv_from(&mut buf).await.unwrap();
        assert!(
            got.is_none(),
            "fragmented datagram is skipped, flow survives"
        );
    }
}
