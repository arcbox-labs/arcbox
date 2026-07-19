//! In-process network origins and sinks for the network workload and fault
//! suites (`internal-docs/plans/network-workload-e2e.md`,
//! `internal-docs/plans/network-fault-e2e.md`).
//!
//! Everything binds `127.0.0.1:0` and runs until the process exits; guests
//! reach a fixture at `10.0.2.1:<port>` via the TcpBridge gateway→loopback
//! translation, so tests exercise the full egress datapath with no external
//! network and no fixed host ports (parallel-safe per the README contract).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

use crate::docker::docker_output;

/// Gateway IP the guest sees on its primary NIC. TcpBridge translates
/// connections to it into host `127.0.0.1` — the `host.docker.internal`
/// mechanism, and the datapath every fixture here sits behind.
pub const GUEST_GATEWAY_IP: &str = "10.0.2.1";

/// Reads request headers until the `\r\n\r\n` terminator. Returns false on
/// EOF or error before the terminator.
fn drain_request_headers(stream: &mut TcpStream) -> bool {
    let mut buf = [0u8; 4096];
    let mut request = Vec::new();
    loop {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => return false,
            Ok(n) => {
                request.extend_from_slice(&buf[..n]);
                if request.windows(4).any(|w| w == b"\r\n\r\n") {
                    return true;
                }
            }
        }
    }
}

/// HTTP origin serving `blob_bytes` of zeroes per request.
///
/// Records one duration per connection: accept → the client closing its
/// side after reading the full body. Client-close (not last-write) is the
/// completion signal, so a flow whose tail stalls in flight shows up as a
/// long duration even though the server buffered its final bytes early.
pub struct BlobServer {
    port: u16,
    timings: Arc<Mutex<Vec<Duration>>>,
}

impl BlobServer {
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Per-connection durations in completion order.
    pub fn timings(&self) -> Vec<Duration> {
        self.timings.lock().expect("timings poisoned").clone()
    }

    pub fn reset_timings(&self) {
        self.timings.lock().expect("timings poisoned").clear();
    }
}

pub fn spawn_blob_server(blob_bytes: usize) -> Result<BlobServer> {
    let listener = TcpListener::bind("127.0.0.1:0").context("binding blob server")?;
    let port = listener.local_addr()?.port();
    let timings: Arc<Mutex<Vec<Duration>>> = Arc::default();
    let recorded = Arc::clone(&timings);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let recorded = Arc::clone(&recorded);
            std::thread::spawn(move || {
                let started = Instant::now();
                if !drain_request_headers(&mut stream) {
                    return;
                }
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {blob_bytes}\r\nConnection: close\r\n\r\n"
                );
                if stream.write_all(header.as_bytes()).is_err() {
                    return;
                }
                let chunk = vec![0u8; 64 * 1024];
                let mut remaining = blob_bytes;
                while remaining > 0 {
                    let n = remaining.min(chunk.len());
                    if stream.write_all(&chunk[..n]).is_err() {
                        return;
                    }
                    remaining -= n;
                }
                // Wait for the client's close so the timing covers actual
                // receipt, not just our last buffered write.
                let mut sink = [0u8; 1024];
                while matches!(stream.read(&mut sink), Ok(n) if n > 0) {}
                recorded
                    .lock()
                    .expect("timings poisoned")
                    .push(started.elapsed());
            });
        }
    });
    Ok(BlobServer { port, timings })
}

/// HTTP origin that serves `partial_body` bytes of an `advertised_len`
/// body, then turns its close into a RST (`SO_LINGER` zero).
///
/// The daemon's upstream leg sees ECONNRESET mid-transfer. One thread per
/// connection.
pub fn spawn_chaos_origin(partial_body: usize, advertised_len: usize) -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").context("binding chaos origin")?;
    let port = listener.local_addr()?.port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            std::thread::spawn(move || serve_then_reset(stream, partial_body, advertised_len));
        }
    });
    Ok(port)
}

fn serve_then_reset(mut stream: TcpStream, partial_body: usize, advertised_len: usize) {
    if !drain_request_headers(&mut stream) {
        return;
    }
    let header =
        format!("HTTP/1.1 200 OK\r\nContent-Length: {advertised_len}\r\nConnection: close\r\n\r\n");
    if stream.write_all(header.as_bytes()).is_err() {
        return;
    }
    let chunk = vec![0u8; partial_body];
    if stream.write_all(&chunk).is_err() {
        return;
    }
    let _ = stream.flush();

    // SO_LINGER with a zero timeout turns the close into a RST rather than a
    // graceful FIN. (std's set_linger is still unstable, so go through libc.)
    let linger = libc::linger {
        l_onoff: 1,
        l_linger: 0,
    };
    // SAFETY: `stream` owns the fd for the duration of the call, and `linger`
    // is a valid, correctly-sized SO_LINGER payload.
    unsafe {
        libc::setsockopt(
            std::os::unix::io::AsRawFd::as_raw_fd(&stream),
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            std::ptr::addr_of!(linger).cast(),
            std::mem::size_of::<libc::linger>() as libc::socklen_t,
        );
    }
    drop(stream);
}

/// Mid-stream read pause for [`SlowSink`]: after `after_bytes` have been
/// read, reading stops for `duration`.
///
/// With the client still pushing, the host socket buffers fill and the
/// daemon's upload write hits `WouldBlock` — the no-backpressure-queue path
/// (payload dropped, guest RTO recovers).
#[derive(Clone, Copy)]
pub struct SinkPause {
    pub after_bytes: usize,
    pub duration: Duration,
}

/// Raw-TCP upload sink: counts received bytes and closes once `expected`
/// bytes have arrived (the client sees a clean EOF).
///
/// The receive side is the assertion surface for W2: exact byte count
/// within a deadline, regardless of the in-guest client's own EOF-handling
/// quirks.
pub struct SlowSink {
    port: u16,
    received: Arc<AtomicUsize>,
    done: Arc<AtomicBool>,
    transfer: Arc<Mutex<Option<Duration>>>,
}

pub struct SinkReport {
    pub received: usize,
    /// Accept → the sink's read loop ending (byte count reached or client
    /// hangup), measured sink-side. Includes any configured pause.
    pub transfer: Duration,
}

impl SlowSink {
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Blocks until the sink has received its expected byte count (or the
    /// client hung up early), then returns the report. Errors on timeout
    /// with the byte count reached so far.
    pub fn wait_complete(&self, timeout: Duration) -> Result<SinkReport> {
        let started = Instant::now();
        while started.elapsed() < timeout {
            if self.done.load(Ordering::Acquire) {
                return Ok(SinkReport {
                    received: self.received.load(Ordering::Acquire),
                    transfer: self
                        .transfer
                        .lock()
                        .expect("transfer poisoned")
                        .unwrap_or_default(),
                });
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        bail!(
            "sink did not complete within {timeout:?} ({} bytes received)",
            self.received.load(Ordering::Acquire)
        )
    }
}

pub fn spawn_slow_sink(expected: usize, pause: Option<SinkPause>) -> Result<SlowSink> {
    let listener = TcpListener::bind("127.0.0.1:0").context("binding slow sink")?;
    let port = listener.local_addr()?.port();
    let received = Arc::new(AtomicUsize::new(0));
    let done = Arc::new(AtomicBool::new(false));
    let transfer: Arc<Mutex<Option<Duration>>> = Arc::default();
    let sink_received = Arc::clone(&received);
    let sink_done = Arc::clone(&done);
    let sink_transfer = Arc::clone(&transfer);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let accepted = Instant::now();
            let mut buf = vec![0u8; 64 * 1024];
            let mut paused = false;
            loop {
                let count = sink_received.load(Ordering::Acquire);
                if count >= expected {
                    break;
                }
                if let Some(pause) = pause
                    && !paused
                    && count >= pause.after_bytes
                {
                    paused = true;
                    std::thread::sleep(pause.duration);
                }
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        sink_received.fetch_add(n, Ordering::AcqRel);
                    }
                }
            }
            drop(stream);
            *sink_transfer.lock().expect("transfer poisoned") = Some(accepted.elapsed());
            sink_done.store(true, Ordering::Release);
        }
    });
    Ok(SlowSink {
        port,
        received,
        done,
        transfer,
    })
}

/// Asserts no `ESTABLISHED` flow to `10.0.2.1:<port>` remains inside the
/// container's netns.
///
/// Retries for `grace` so in-flight FIN teardown passes while a frozen flow
/// — the 2026-07-19 incident shape — fails with the offending `netstat`
/// lines. The exec rides vsock, not the datapath under test.
pub fn assert_no_established_flows(
    data_dir: &Path,
    container: &str,
    port: u16,
    grace: Duration,
) -> Result<()> {
    let needle = format!("{GUEST_GATEWAY_IP}:{port}");
    let started = Instant::now();
    loop {
        let out = docker_output(
            data_dir,
            &["exec", container, "netstat", "-tn"],
            Duration::from_secs(20),
        )
        .context("netstat in workload container")?;
        let zombies: Vec<&str> = out
            .lines()
            .filter(|l| l.contains("ESTABLISHED") && l.contains(&needle))
            .collect();
        if zombies.is_empty() {
            return Ok(());
        }
        if started.elapsed() >= grace {
            bail!(
                "flows to {needle} still ESTABLISHED {:?} after the workload ended:\n{}",
                started.elapsed(),
                zombies.join("\n")
            );
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

/// Position marker into the daemon's JSON log (`<data_dir>/log/daemon.log`)
/// for the workload suites' quiet-log assertion.
///
/// Normal traffic must not produce proxy-layer ERROR lines (the
/// observability inverse of the fault plan, which asserts faults are loud).
pub struct DaemonLogCursor {
    path: PathBuf,
    offset: u64,
}

pub fn daemon_log_cursor(data_dir: &Path) -> DaemonLogCursor {
    let path = data_dir.join("log/daemon.log");
    let offset = std::fs::metadata(&path).map_or(0, |m| m.len());
    DaemonLogCursor { path, offset }
}

impl DaemonLogCursor {
    /// Proxy-layer (`arcbox_net`/`splicetcp`/`arcbox_proxy`) ERROR lines
    /// appended since the cursor was taken. Reads from the start if the log
    /// rotated underneath the cursor.
    pub fn proxy_errors(&self) -> Result<Vec<String>> {
        let contents = std::fs::read(&self.path)
            .with_context(|| format!("reading {}", self.path.display()))?;
        let tail = if contents.len() as u64 >= self.offset {
            &contents[self.offset as usize..]
        } else {
            contents.as_slice()
        };
        Ok(String::from_utf8_lossy(tail)
            .lines()
            .filter(|l| {
                l.contains(r#""level":"ERROR""#)
                    && [
                        r#""target":"arcbox_net"#,
                        r#""target":"splicetcp"#,
                        r#""target":"arcbox_proxy"#,
                    ]
                    .iter()
                    .any(|t| l.contains(t))
            })
            .map(str::to_owned)
            .collect())
    }
}
