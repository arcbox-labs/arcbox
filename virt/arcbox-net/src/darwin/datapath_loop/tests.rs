use super::fd::{fd_read, fd_write, set_nonblocking, write_to_guest};
use super::guest_tx::{DeliveryClass, GuestTx, LOSSY_QUEUE_CAP};
use super::intercept::build_dns_servfail_response;
use super::*;
use std::os::fd::{FromRawFd, RawFd};

/// Creates a SOCK_DGRAM socketpair, returning (fd_a, fd_b) as OwnedFds.
fn socketpair() -> (OwnedFd, OwnedFd) {
    let mut fds: [i32; 2] = [0; 2];
    // SAFETY: valid pointer to 2-element array.
    let ret = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) };
    assert_eq!(ret, 0, "socketpair() failed");
    // SAFETY: fds are valid file descriptors from socketpair.
    unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
}

/// Shrinks a socket's send/receive buffers so overflow is reached quickly.
fn shrink_socket_buffers(fd: RawFd) {
    let size: libc::c_int = 8192;
    for opt in [libc::SO_SNDBUF, libc::SO_RCVBUF] {
        // SAFETY: setsockopt on a valid fd with a valid c_int payload.
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                opt,
                (&raw const size).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        assert_eq!(ret, 0, "setsockopt failed");
    }
}

/// Sends reliable frames until the socketpair overflows and a backlog forms.
/// Returns the number of frames sent. Panics if overflow is never reached.
fn send_until_backlog(tx: &mut GuestTx, fd: RawFd, frame: &[u8]) -> usize {
    let mut sent = 0usize;
    for _ in 0..10_000 {
        tx.send(fd, frame, DeliveryClass::Reliable);
        sent += 1;
        if tx.has_backlog() {
            return sent;
        }
    }
    panic!("socketpair never overflowed; cannot exercise backpressure");
}

#[test]
fn test_set_nonblocking() {
    let (a, _b) = socketpair();
    set_nonblocking(a.as_raw_fd()).unwrap();

    // SAFETY: fcntl on a valid fd.
    let flags = unsafe { libc::fcntl(a.as_raw_fd(), libc::F_GETFL) };
    assert!(flags >= 0);
    assert_ne!(flags & libc::O_NONBLOCK, 0, "O_NONBLOCK should be set");
}

#[test]
fn test_fd_read_write_roundtrip() {
    let (a, b) = socketpair();
    let data = b"hello network";

    // SAFETY: writing from valid buffer to valid fd.
    let n = unsafe { libc::write(b.as_raw_fd(), data.as_ptr().cast(), data.len()) };
    assert_eq!(n as usize, data.len());

    let mut buf = [0u8; 64];
    let n = fd_read(a.as_raw_fd(), &mut buf).unwrap();
    assert_eq!(n, data.len());
    assert_eq!(&buf[..n], data);
}

#[tokio::test]
async fn test_write_to_guest_roundtrip() {
    let (a, b) = socketpair();

    set_nonblocking(a.as_raw_fd()).unwrap();
    let guest_async = AsyncFd::new(FdWrapper(a)).unwrap();

    let frame = b"test ethernet frame data";
    write_to_guest(&guest_async, frame);

    let mut buf = [0u8; 128];
    let n = fd_read(b.as_raw_fd(), &mut buf).unwrap();
    assert_eq!(n, frame.len());
    assert_eq!(&buf[..n], frame.as_slice());
}

#[test]
fn test_fd_write_roundtrip() {
    let (a, b) = socketpair();
    let data = b"fd_write test data";
    let n = fd_write(b.as_raw_fd(), data).unwrap();
    assert_eq!(n, data.len());

    let mut buf = [0u8; 64];
    let n = fd_read(a.as_raw_fd(), &mut buf).unwrap();
    assert_eq!(&buf[..n], data);
}

#[test]
fn guest_tx_direct_write_when_unblocked() {
    let (a, b) = socketpair();
    set_nonblocking(a.as_raw_fd()).unwrap();

    let mut tx = GuestTx::new(None);
    let frame_data = b"direct write frame";
    tx.send(a.as_raw_fd(), frame_data, DeliveryClass::Reliable);

    assert!(
        !tx.has_backlog(),
        "queue should be empty after direct write"
    );

    let mut buf = [0u8; 128];
    let n = fd_read(b.as_raw_fd(), &mut buf).unwrap();
    assert_eq!(&buf[..n], frame_data.as_slice());
}

/// Regression test for the container-egress black hole: when the socketpair
/// overflows (macOS returns `ENOBUFS`, not `EAGAIN`), reliable frames must
/// be queued — never dropped — and delivered in order once the peer drains.
/// The shim has no retransmission, so a single lost frame stalls its TCP
/// connection permanently.
#[test]
fn guest_tx_reliable_survives_socketpair_overflow() {
    let (a, b) = socketpair();
    set_nonblocking(a.as_raw_fd()).unwrap();
    set_nonblocking(b.as_raw_fd()).unwrap();
    shrink_socket_buffers(a.as_raw_fd());
    shrink_socket_buffers(b.as_raw_fd());

    let mut tx = GuestTx::new(None);
    // Each frame carries its sequence number so ordering is verifiable.
    let make_frame = |seq: u32| {
        let mut f = vec![0xAB_u8; 2048];
        f[..4].copy_from_slice(&seq.to_be_bytes());
        f
    };

    let mut sent = 0usize;
    for _ in 0..10_000 {
        tx.send(
            a.as_raw_fd(),
            &make_frame(sent as u32),
            DeliveryClass::Reliable,
        );
        sent += 1;
        if tx.has_backlog() {
            break;
        }
    }
    assert!(tx.has_backlog(), "socketpair never overflowed");
    // Exactly one resume mechanism must be armed for the blocked state.
    assert!(
        tx.awaits_writable() ^ tx.awaits_retry(),
        "blocked backlog must arm exactly one resume mechanism"
    );
    // Keep producing while blocked — everything must queue.
    for _ in 0..16 {
        tx.send(
            a.as_raw_fd(),
            &make_frame(sent as u32),
            DeliveryClass::Reliable,
        );
        sent += 1;
    }

    // Alternately drain the peer and retry until everything is delivered.
    let mut buf = vec![0u8; 4096];
    let mut received = 0usize;
    let mut idle_rounds = 0;
    while received < sent && idle_rounds < 1_000 {
        let mut progressed = false;
        while let Ok(n) = fd_read(b.as_raw_fd(), &mut buf) {
            if n == 0 {
                break;
            }
            assert_eq!(
                u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]),
                received as u32,
                "frames must arrive in send order"
            );
            received += 1;
            progressed = true;
        }
        tx.drain(a.as_raw_fd());
        if !progressed {
            idle_rounds += 1;
        }
    }

    assert_eq!(received, sent, "reliable frames were lost across overflow");
    assert!(!tx.has_backlog(), "queue must fully drain");
    assert!(
        tx.stats.enobufs_events + tx.stats.would_block_events >= 1,
        "the overflow path was never exercised"
    );
    assert_eq!(tx.stats.lossy_dropped, 0);
    assert_eq!(tx.stats.io_errors, 0);
    assert_eq!(tx.stats.short_writes, 0);
}

/// Lossy frames are bounded at `LOSSY_QUEUE_CAP` and dropped beyond it;
/// reliable frames are still accepted past the cap.
#[test]
fn guest_tx_lossy_capped_reliable_uncapped() {
    let (a, b) = socketpair();
    set_nonblocking(a.as_raw_fd()).unwrap();
    set_nonblocking(b.as_raw_fd()).unwrap();
    shrink_socket_buffers(a.as_raw_fd());
    shrink_socket_buffers(b.as_raw_fd());

    let mut tx = GuestTx::new(None);
    let frame = vec![0xCD_u8; 2048];
    send_until_backlog(&mut tx, a.as_raw_fd(), &frame);

    for _ in 0..(LOSSY_QUEUE_CAP + 100) {
        tx.send(a.as_raw_fd(), &frame, DeliveryClass::Lossy);
    }
    assert!(
        tx.stats.lossy_dropped >= 100,
        "lossy frames must drop at the cap (dropped: {})",
        tx.stats.lossy_dropped
    );

    let hwm_before = tx.stats.queue_high_water;
    tx.send(a.as_raw_fd(), &frame, DeliveryClass::Reliable);
    assert!(
        tx.stats.queue_high_water > hwm_before,
        "reliable frames must still be accepted past the lossy cap"
    );
}

#[test]
fn test_build_dns_servfail_response() {
    let query = vec![
        0x12, 0x34, // ID
        0x01, 0x00, // Flags (RD)
        0x00, 0x01, // QDCOUNT
        0x00, 0x00, // ANCOUNT
        0x00, 0x00, // NSCOUNT
        0x00, 0x00, // ARCOUNT
        0x01, b'a', // QNAME label "a"
        0x00, // root
        0x00, 0x01, // QTYPE A
        0x00, 0x01, // QCLASS IN
    ];

    let response = build_dns_servfail_response(&query).expect("should build servfail");
    assert_eq!(response[0..2], query[0..2]); // ID preserved
    assert_eq!(response[2] & 0x80, 0x80); // QR=1
    assert_eq!(response[3] & 0x0F, 0x02); // RCODE=SERVFAIL
    assert_eq!(&response[4..6], &1u16.to_be_bytes()); // QDCOUNT=1
    assert_eq!(&response[6..8], &0u16.to_be_bytes()); // ANCOUNT=0
    assert_eq!(&response[8..10], &0u16.to_be_bytes()); // NSCOUNT=0
    assert_eq!(&response[10..12], &0u16.to_be_bytes()); // ARCOUNT=0
    assert_eq!(&response[12..], &query[12..]); // Question echoed
}
