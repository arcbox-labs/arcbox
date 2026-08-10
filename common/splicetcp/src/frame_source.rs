//! The frame ingest seam.
//!
//! [`FrameClassifier`](crate::classifier::FrameClassifier) is fed frames
//! rather than owning an fd; a [`FrameSource`] is "an fd to await for read
//! readiness plus a non-blocking `drain` that yields each available frame".
//! Both the VM datapath (over a socketpair) and the host tunnel (over a
//! `utun`, via the [`shim`](crate::shim)) supply a [`FrameSource`].

use std::io;
use std::os::fd::RawFd;

use arcbox_xnu_net::BatchDgram;

/// Largest L2 frame we read from a source in a single `read`.
///
/// Also the batch-receive slot size: a datagram that overruns its slot is
/// truncated silently (see [`BatchDgram::recv_batch_chunked`]), so this must
/// stay at or above the largest datagram the peer can hand us.
const MAX_FRAME_SIZE: usize = 65535;

/// Frames one `recvmsg_x` collects. The backing buffer is
/// `RX_BATCH * MAX_FRAME_SIZE` of zeroed — hence lazily faulted — address
/// space, so the resident cost tracks the frames that actually arrive, not
/// the reservation.
const RX_BATCH: usize = 32;

/// A source of inbound L2 Ethernet frames.
///
/// The datapath loop registers [`as_raw_fd`](FrameSource::as_raw_fd) with its
/// async runtime for read readiness, then calls [`drain`](FrameSource::drain)
/// to consume every currently-available frame without blocking.
///
/// The trait is generic over the per-frame callback (so the hot loop
/// monomorphizes — no per-frame virtual dispatch) and is therefore not
/// dyn-compatible, which is intentional: callers hold a concrete source.
pub trait FrameSource {
    /// The fd to register for read readiness.
    fn as_raw_fd(&self) -> RawFd;

    /// Drains all currently-available frames, invoking `f` once per frame.
    /// Returns when the source would block (or hits EOF/error).
    fn drain(&mut self, f: impl FnMut(&[u8]));
}

/// A [`FrameSource`] backed by a raw `SOCK_DGRAM` fd read in batches.
///
/// Suitable for a datagram fd that delivers whole L2 frames — the VM's
/// `SOCK_DGRAM` socketpair. The fd must already be non-blocking; the
/// datapath sets `O_NONBLOCK` before registering it for readiness.
/// (A `utun` is L3 and has its own source,
/// [`UtunFrameSource`](crate::utun::UtunFrameSource), wrapped for the
/// classifier by the [`shim`](crate::shim).)
pub struct FdFrameSource {
    fd: RawFd,
    /// [`RX_BATCH`] back-to-back [`MAX_FRAME_SIZE`] slots.
    read_buf: Vec<u8>,
    /// Pre-allocated `msghdr_x`/`iovec` arrays for the batched read.
    batch: BatchDgram,
}

impl FdFrameSource {
    /// Wraps a (non-blocking) raw fd. The fd is not owned — its lifetime is
    /// managed by the caller (typically an `AsyncFd<OwnedFd>` registered for
    /// readiness on the same descriptor).
    #[must_use]
    pub fn new(fd: RawFd) -> Self {
        Self {
            fd,
            read_buf: vec![0u8; RX_BATCH * MAX_FRAME_SIZE],
            batch: BatchDgram::new(),
        }
    }
}

impl FrameSource for FdFrameSource {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }

    /// Collects up to [`RX_BATCH`] frames per syscall, and keeps going until
    /// the fd would block.
    ///
    /// Draining to `WouldBlock` — rather than stopping on the first short
    /// batch — is load-bearing: the caller clears read readiness afterwards,
    /// so a frame that arrived mid-drain would otherwise sit unread until
    /// the next unrelated wakeup.
    fn drain(&mut self, mut f: impl FnMut(&[u8])) {
        let Self {
            fd,
            read_buf,
            batch,
        } = self;
        loop {
            match batch.recv_batch_chunked(*fd, read_buf, MAX_FRAME_SIZE) {
                Ok(entries) => {
                    if entries.is_empty() {
                        break;
                    }
                    for (i, entry) in entries.iter().enumerate() {
                        // A zero-length datagram carries no frame; skipping
                        // it keeps the drain going, where a plain `read`
                        // could not tell it from EOF.
                        if entry.len > 0 {
                            f(&read_buf[i * MAX_FRAME_SIZE..][..entry.len]);
                        }
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => {
                    tracing::warn!("frame source read error: {e}");
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    use super::{FdFrameSource, FrameSource, MAX_FRAME_SIZE, RX_BATCH};

    /// Non-blocking `AF_UNIX SOCK_DGRAM` pair with room for the test's frames.
    fn socketpair() -> (OwnedFd, OwnedFd) {
        let mut fds = [0i32; 2];
        // SAFETY: `fds` is a valid 2-element array; AF_UNIX SOCK_DGRAM is
        // universally supported.
        let ret = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) };
        assert_eq!(ret, 0, "socketpair failed");
        for fd in fds {
            let size: libc::c_int = 1024 * 1024;
            for opt in [libc::SO_SNDBUF, libc::SO_RCVBUF] {
                // SAFETY: setsockopt on a valid fd with a correctly sized payload.
                unsafe {
                    libc::setsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        opt,
                        (&raw const size).cast(),
                        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                    );
                }
            }
            // SAFETY: fcntl on a valid fd.
            unsafe {
                let flags = libc::fcntl(fd, libc::F_GETFL);
                libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
            }
        }
        // SAFETY: both fds are freshly created by socketpair and owned by us.
        unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
    }

    fn write_frame(fd: &OwnedFd, data: &[u8]) {
        // SAFETY: writing our own buffer to a valid socketpair fd.
        let n = unsafe { libc::write(fd.as_raw_fd(), data.as_ptr().cast(), data.len()) };
        assert_eq!(n, data.len().cast_signed(), "short write");
    }

    /// Frame boundaries and ordering survive the batched read, including
    /// across the batch edge — the drain must keep going past a full batch
    /// or the caller's `clear_ready()` strands the remainder.
    #[test]
    fn drain_preserves_frame_boundaries_across_batches() {
        let (host, guest) = socketpair();

        let count = RX_BATCH + RX_BATCH / 2;
        for i in 0..count {
            write_frame(&guest, &vec![u8::try_from(i % 251).unwrap(); 100 + i]);
        }

        let mut source = FdFrameSource::new(host.as_raw_fd());
        let mut seen: Vec<(usize, u8)> = Vec::new();
        source.drain(|frame| seen.push((frame.len(), frame[0])));

        assert_eq!(seen.len(), count, "every frame must be delivered");
        for (i, &(len, tag)) in seen.iter().enumerate() {
            assert_eq!(len, 100 + i, "frame {i} length");
            assert_eq!(tag, u8::try_from(i % 251).unwrap(), "frame {i} order");
        }
    }

    /// An empty source yields nothing and returns rather than spinning.
    #[test]
    fn drain_on_an_idle_fd_yields_nothing() {
        let (host, _guest) = socketpair();

        let mut source = FdFrameSource::new(host.as_raw_fd());
        let mut count = 0;
        source.drain(|_| count += 1);
        assert_eq!(count, 0);
    }

    /// A zero-length datagram is skipped without ending the drain — a plain
    /// `read` could not tell it from EOF.
    #[test]
    fn drain_skips_a_zero_length_datagram() {
        let (host, guest) = socketpair();

        write_frame(&guest, &[]);
        write_frame(&guest, b"after the empty one");

        let mut source = FdFrameSource::new(host.as_raw_fd());
        let mut frames: Vec<Vec<u8>> = Vec::new();
        source.drain(|frame| frames.push(frame.to_vec()));

        assert_eq!(frames, vec![b"after the empty one".to_vec()]);
    }

    /// The largest frame the slot size admits round-trips intact.
    #[test]
    fn drain_delivers_a_max_size_frame() {
        let (host, guest) = socketpair();

        let frame: Vec<u8> = (0..MAX_FRAME_SIZE).map(|i| (i % 256) as u8).collect();
        write_frame(&guest, &frame);

        let mut source = FdFrameSource::new(host.as_raw_fd());
        let mut got: Option<Vec<u8>> = None;
        source.drain(|f| got = Some(f.to_vec()));

        assert_eq!(got.as_deref(), Some(frame.as_slice()));
    }
}
