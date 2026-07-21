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
use sha2::{Digest, Sha256};

use crate::docker::docker_output;

/// Gateway IP the guest sees on its primary NIC. TcpBridge translates
/// connections to it into host `127.0.0.1` — the `host.docker.internal`
/// mechanism, and the datapath every fixture here sits behind.
pub const GUEST_GATEWAY_IP: &str = "10.0.2.1";

/// Fills `buf` with a deterministic, position-dependent pattern.
///
/// A seeded xorshift64* stream. Unlike a run of zeroes, this makes any
/// truncation, reordering, or duplication in transit change the SHA-256 —
/// the integrity check that byte-count-only assertions miss (the datapath's
/// silent-upload-loss bug advanced the ACK past unwritten bytes, so a
/// length check alone could pass on corrupt data). Distinct seeds give
/// distinct streams (only the degenerate all-zero state is remapped).
pub fn fill_pattern(buf: &mut [u8], seed: u64) {
    // xorshift sticks at zero; remap only that one state so every other
    // seed stays distinct (`seed | 1` would collide 42 and 43).
    let mut state = if seed == 0 {
        0x9E37_79B9_7F4A_7C15
    } else {
        seed
    };
    for chunk in buf.chunks_mut(8) {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        let bytes = state.wrapping_mul(0x2545_F491_4F6C_DD1D).to_le_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
}

/// Lowercase-hex encoding of a byte stream.
fn hex_encode(bytes: impl IntoIterator<Item = u8>) -> String {
    use std::fmt::Write;
    let mut hex = String::new();
    for byte in bytes {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// Lowercase-hex SHA-256 of `data`.
pub fn sha256_hex(data: &[u8]) -> String {
    hex_encode(Sha256::digest(data))
}

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

    /// [`timings`](Self::timings), but waits up to `grace` for `expected`
    /// recordings to land first. A recording is pushed only once the
    /// fixture thread sees the client's TCP close, which races the
    /// client command's own (vsock-delivered) completion — without the
    /// wait, an exact-count check can miss the last flows despite every
    /// client having succeeded.
    pub fn wait_for_timings(&self, expected: usize, grace: Duration) -> Vec<Duration> {
        let deadline = Instant::now() + grace;
        loop {
            let snapshot = self.timings();
            if snapshot.len() >= expected || Instant::now() >= deadline {
                return snapshot;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
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

/// HTTP origin serving a fixed deterministic-pattern body of known SHA-256.
///
/// For download **integrity** (not just completion) checks: the body is
/// generated once and served verbatim, so the guest can pipe the download
/// through `sha256sum` and compare to [`sha256`](Self::sha256).
pub struct PatternServer {
    port: u16,
    sha256: String,
    len: usize,
}

impl PatternServer {
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Lowercase-hex SHA-256 of the exact bytes this origin serves.
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

pub fn spawn_pattern_server(len: usize, seed: u64) -> Result<PatternServer> {
    let mut body = vec![0u8; len];
    fill_pattern(&mut body, seed);
    let sha256 = sha256_hex(&body);
    let body = std::sync::Arc::new(body);

    let listener = TcpListener::bind("127.0.0.1:0").context("binding pattern server")?;
    let port = listener.local_addr()?.port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let body = std::sync::Arc::clone(&body);
            std::thread::spawn(move || {
                if !drain_request_headers(&mut stream) {
                    return;
                }
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                if stream.write_all(header.as_bytes()).is_err() {
                    return;
                }
                let _ = stream.write_all(&body);
            });
        }
    });
    Ok(PatternServer { port, sha256, len })
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
    /// SHA-256 of the received byte stream, present only when the sink was
    /// spawned with hashing enabled (upload integrity). Hashing every byte
    /// costs CPU, so throughput-only sinks leave it `None`.
    hasher: Option<Arc<Mutex<Sha256>>>,
}

pub struct SinkReport {
    pub received: usize,
    /// Accept → the sink's read loop ending (byte count reached or client
    /// hangup), measured sink-side. Includes any configured pause.
    pub transfer: Duration,
    /// Lowercase-hex SHA-256 of the received bytes, when hashing was
    /// enabled; empty otherwise.
    pub sha256: String,
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
                let sha256 = self.hasher.as_ref().map_or_else(String::new, |h| {
                    hex_encode(h.lock().expect("hasher poisoned").clone().finalize())
                });
                return Ok(SinkReport {
                    received: self.received.load(Ordering::Acquire),
                    transfer: self
                        .transfer
                        .lock()
                        .expect("transfer poisoned")
                        .unwrap_or_default(),
                    sha256,
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
    spawn_slow_sink_inner(expected, pause, false)
}

/// [`spawn_slow_sink`] that also SHA-256s the received stream, for upload
/// integrity (compare [`SinkReport::sha256`] against what the client sent).
pub fn spawn_hashing_sink(expected: usize) -> Result<SlowSink> {
    spawn_slow_sink_inner(expected, None, true)
}

fn spawn_slow_sink_inner(
    expected: usize,
    pause: Option<SinkPause>,
    hash: bool,
) -> Result<SlowSink> {
    let listener = TcpListener::bind("127.0.0.1:0").context("binding slow sink")?;
    let port = listener.local_addr()?.port();
    let received = Arc::new(AtomicUsize::new(0));
    let done = Arc::new(AtomicBool::new(false));
    let transfer: Arc<Mutex<Option<Duration>>> = Arc::default();
    let hasher = hash.then(|| Arc::new(Mutex::new(Sha256::new())));
    let sink_received = Arc::clone(&received);
    let sink_done = Arc::clone(&done);
    let sink_transfer = Arc::clone(&transfer);
    let sink_hasher = hasher.clone();
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
                        if let Some(h) = &sink_hasher {
                            h.lock().expect("hasher poisoned").update(&buf[..n]);
                        }
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
        hasher,
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
    /// Inode of the file the cursor was taken in — rotation renames the
    /// file, so a changed inode (not a shorter length: the new file can
    /// grow past the old offset) is the rotation signal.
    ino: Option<u64>,
}

pub fn daemon_log_cursor(data_dir: &Path) -> DaemonLogCursor {
    let path = data_dir.join("log/daemon.log");
    let meta = std::fs::metadata(&path).ok();
    DaemonLogCursor {
        offset: meta.as_ref().map_or(0, std::fs::Metadata::len),
        ino: meta.map(|m| std::os::unix::fs::MetadataExt::ino(&m)),
        path,
    }
}

impl DaemonLogCursor {
    /// Proxy-layer (`arcbox_net`/`splicetcp`/`arcbox_proxy` and their
    /// submodules — the needles are prefixes) ERROR lines appended since
    /// the cursor was taken.
    ///
    /// Rotation is detected by inode identity, not length — after a
    /// rotation the new `daemon.log` can grow past the old offset. When
    /// the cursor's file has been renamed away, every generation from the
    /// cursor's inode (`daemon.log.N`, oldest first) through the current
    /// file is stitched into one stream so the offset still lands on the
    /// cursor byte; if the cursor's generation already aged out of
    /// retention, everything is scanned (over-matching boot-phase lines
    /// beats silently dropping workload-phase ones).
    pub fn proxy_errors(&self) -> Result<Vec<String>> {
        let current = std::fs::read(&self.path)
            .with_context(|| format!("reading {}", self.path.display()))?;
        let current_ino = std::fs::metadata(&self.path)
            .ok()
            .map(|m| std::os::unix::fs::MetadataExt::ino(&m));

        let (contents, offset) = if self.ino.is_none() || current_ino == self.ino {
            (current, self.offset)
        } else {
            // Oldest → newest: daemon.log.9 .. daemon.log.1, then current.
            let mut generations: Vec<(Option<u64>, Vec<u8>)> = Vec::new();
            for n in (1..=9).rev() {
                let rotated = self.path.with_extension(format!("log.{n}"));
                if let Ok(bytes) = std::fs::read(&rotated) {
                    let ino = std::fs::metadata(&rotated)
                        .ok()
                        .map(|m| std::os::unix::fs::MetadataExt::ino(&m));
                    generations.push((ino, bytes));
                }
            }
            generations.push((current_ino, current));
            let start = generations
                .iter()
                .position(|(ino, _)| *ino == self.ino)
                .unwrap_or(0);
            let offset = if generations[start].0 == self.ino {
                self.offset
            } else {
                0
            };
            let stitched = generations
                .drain(start..)
                .flat_map(|(_, bytes)| bytes)
                .collect();
            (stitched, offset)
        };

        let tail = if contents.len() as u64 >= offset {
            &contents[offset as usize..]
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

#[cfg(test)]
mod tests {
    use super::*;

    const ERR: &str = r#"{"level":"ERROR","fields":{"message":"x"},"target":"arcbox_net::darwin::datapath_loop::guest_tx"}"#;

    #[test]
    fn pattern_is_deterministic_and_seed_sensitive() {
        let mut a = vec![0u8; 4096];
        let mut b = vec![0u8; 4096];
        fill_pattern(&mut a, 42);
        fill_pattern(&mut b, 42);
        assert_eq!(a, b, "same seed ⇒ same bytes");
        assert_eq!(sha256_hex(&a), sha256_hex(&b));

        let mut c = vec![0u8; 4096];
        fill_pattern(&mut c, 43);
        assert_ne!(a, c, "different seed ⇒ different bytes");

        // Not a trivial constant run — this is what makes reordering /
        // truncation detectable where a zero blob would not be.
        assert!(a.windows(64).any(|w| w.iter().any(|&x| x != a[0])));
    }

    #[test]
    fn pattern_length_changes_the_hash() {
        let mut short = vec![0u8; 1000];
        let mut long = vec![0u8; 1001];
        fill_pattern(&mut short, 7);
        fill_pattern(&mut long, 7);
        // A prefix relationship (truncation) must not collide on the hash.
        assert_ne!(sha256_hex(&short), sha256_hex(&long));
    }

    #[test]
    fn sha256_hex_is_lowercase_64_hex() {
        let h = sha256_hex(b"");
        assert_eq!(
            h,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(h.len(), 64);
        assert!(
            h.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
    }

    fn write_log(dir: &Path, name: &str, lines: &[&str]) {
        std::fs::write(dir.join("log").join(name), lines.join("\n") + "\n").unwrap();
    }

    #[test]
    fn proxy_errors_sees_across_rotation_even_when_new_file_outgrows_offset() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("log")).unwrap();
        // Pre-cursor content, including an ERROR that must NOT be reported.
        write_log(dir.path(), "daemon.log", &[ERR, "boot line"]);
        let cursor = daemon_log_cursor(dir.path());

        // Post-cursor ERROR lands in the same file, then the log rotates and
        // the NEW current file grows well past the old cursor offset.
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(dir.path().join("log/daemon.log"))
            .unwrap();
        std::io::Write::write_all(&mut f, format!("{ERR}\n").as_bytes()).unwrap();
        drop(f);
        std::fs::rename(
            dir.path().join("log/daemon.log"),
            dir.path().join("log/daemon.log.1"),
        )
        .unwrap();
        let filler = vec!["info line"; 64].join("\n");
        write_log(dir.path(), "daemon.log", &[&filler, ERR]);

        let errors = cursor.proxy_errors().unwrap();
        assert_eq!(
            errors.len(),
            2,
            "one rotated-away post-cursor ERROR + one in the new file; \
             the pre-cursor ERROR stays excluded: {errors:?}"
        );
    }

    #[test]
    fn proxy_errors_matches_module_qualified_targets() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("log")).unwrap();
        write_log(dir.path(), "daemon.log", &[]);
        let cursor = daemon_log_cursor(dir.path());
        write_log(dir.path(), "daemon.log", &[ERR]);
        // Same inode (rewritten in place on most filesystems is not
        // guaranteed, so re-take metadata semantics: the assertion is on
        // needle matching, which is inode-independent).
        let errors = cursor.proxy_errors().unwrap();
        assert_eq!(errors.len(), 1, "submodule target must match: {errors:?}");
    }
}
