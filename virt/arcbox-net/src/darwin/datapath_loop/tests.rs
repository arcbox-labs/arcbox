use super::fd::{fd_read, fd_write, set_nonblocking, write_to_guest};
use super::guest_tx::enqueue_or_write;
use super::intercept::build_dns_servfail_response;
use super::*;
use std::os::fd::FromRawFd;

/// Creates a SOCK_DGRAM socketpair, returning (fd_a, fd_b) as OwnedFds.
fn socketpair() -> (OwnedFd, OwnedFd) {
    let mut fds: [i32; 2] = [0; 2];
    // SAFETY: valid pointer to 2-element array.
    let ret = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) };
    assert_eq!(ret, 0, "socketpair() failed");
    // SAFETY: fds are valid file descriptors from socketpair.
    unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
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

#[tokio::test]
async fn test_enqueue_or_write_direct() {
    let (a, b) = socketpair();
    set_nonblocking(a.as_raw_fd()).unwrap();
    let guest_async = AsyncFd::new(FdWrapper(a)).unwrap();

    let mut queue = VecDeque::new();
    let frame_data = b"direct write frame";
    enqueue_or_write(
        &guest_async,
        FrameBuf::from(frame_data.to_vec()),
        &mut queue,
    );

    assert!(queue.is_empty(), "Queue should be empty after direct write");

    let mut buf = [0u8; 128];
    let n = fd_read(b.as_raw_fd(), &mut buf).unwrap();
    assert_eq!(&buf[..n], frame_data.as_slice());
}

#[tokio::test]
async fn test_enqueue_or_write_queues_when_nonempty() {
    let (a, _b) = socketpair();
    set_nonblocking(a.as_raw_fd()).unwrap();
    let guest_async = AsyncFd::new(FdWrapper(a)).unwrap();

    let mut queue: VecDeque<FrameBuf> = VecDeque::new();
    queue.push_back(FrameBuf::from(b"already queued".to_vec()));

    enqueue_or_write(
        &guest_async,
        FrameBuf::from(b"new frame".to_vec()),
        &mut queue,
    );

    assert_eq!(queue.len(), 2);
    assert_eq!(&queue[1][..], b"new frame");
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
