//! Benchmarks comparing single-datagram vs batch I/O on AF_UNIX SOCK_DGRAM
//! socketpairs. Measures the syscall overhead reduction from recvmsg_x/sendmsg_x
//! (macOS) or recvmmsg/sendmmsg (Linux).
//!
//! Send and receive are interleaved in ping-pong chunks so the kernel
//! socket buffer is drained between chunks — running 10000 × 4 KB through
//! an 8 MB buffer without draining would otherwise deadlock on the first
//! WouldBlock.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

use arcbox_xnu_net::BatchDgram;

const DATAGRAM_SIZE: usize = 4000;
const TOTAL_DATAGRAMS: usize = 10_000;
const SOCKET_BUF_BYTES: libc::c_int = 8 * 1024 * 1024;

/// Chunk size for the single-syscall ping-pong. Keep `CHUNK *
/// DATAGRAM_SIZE` below `SOCKET_BUF_BYTES` so writes complete without
/// blocking before the matching reads drain the buffer.
const PINGPONG_CHUNK: usize = 256;

const _: () = assert!(
    PINGPONG_CHUNK * DATAGRAM_SIZE < SOCKET_BUF_BYTES as usize,
    "ping-pong chunk exceeds socket buffer — bench will deadlock"
);

/// Creates a non-blocking socketpair with 8 MB buffers.
fn socketpair() -> (OwnedFd, OwnedFd) {
    let mut fds: [i32; 2] = [0; 2];
    // SAFETY: fds is a valid 2-element array; AF_UNIX SOCK_DGRAM is universally supported.
    let ret = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) };
    assert_eq!(ret, 0, "socketpair failed: {}", io::Error::last_os_error());
    // SAFETY: fds[0]/fds[1] are freshly allocated by socketpair, owned by us.
    let (a, b) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    for fd in [a.as_raw_fd(), b.as_raw_fd()] {
        set_buf_size(fd, libc::SO_SNDBUF, SOCKET_BUF_BYTES);
        set_buf_size(fd, libc::SO_RCVBUF, SOCKET_BUF_BYTES);
        set_nonblocking(fd);
    }
    (a, b)
}

fn set_buf_size(fd: RawFd, name: libc::c_int, size: libc::c_int) {
    // SAFETY: fd is valid for the duration of the setsockopt call.
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            name,
            std::ptr::from_ref(&size).cast(),
            std::mem::size_of_val(&size) as libc::socklen_t,
        )
    };
    assert_eq!(
        ret,
        0,
        "setsockopt(name={name}) failed for fd {fd}: {}",
        io::Error::last_os_error()
    );
}

fn set_nonblocking(fd: RawFd) {
    // SAFETY: fd is valid; F_GETFL/F_SETFL are safe fcntl operations.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    assert!(
        flags >= 0,
        "fcntl(F_GETFL) failed for fd {fd}: {}",
        io::Error::last_os_error()
    );
    // SAFETY: same as above.
    let ret = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    assert!(
        ret >= 0,
        "fcntl(F_SETFL, O_NONBLOCK) failed for fd {fd}: {}",
        io::Error::last_os_error()
    );
}

/// Writes one datagram, retrying on `EAGAIN`/`EINTR` so the bench never
/// silently drops payload (which would distort throughput comparisons).
fn single_write(fd: RawFd, data: &[u8]) {
    loop {
        // SAFETY: valid fd and buffer.
        let n = unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) };
        if n >= 0 {
            assert_eq!(n as usize, data.len(), "short write on AF_UNIX SOCK_DGRAM");
            return;
        }
        let err = io::Error::last_os_error();
        match err.kind() {
            io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock => std::hint::spin_loop(),
            _ => panic!("write failed: {err}"),
        }
    }
}

fn single_read(fd: RawFd, buf: &mut [u8]) {
    loop {
        // SAFETY: valid fd and buffer.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n >= 0 {
            return;
        }
        let err = io::Error::last_os_error();
        match err.kind() {
            io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock => std::hint::spin_loop(),
            _ => panic!("read failed: {err}"),
        }
    }
}

fn send_batch_all(batch: &mut BatchDgram, fd: RawFd, bufs: &[&[u8]]) {
    let mut remaining = bufs.len();
    while remaining > 0 {
        let offset = bufs.len() - remaining;
        match batch.send_batch(fd, &bufs[offset..]) {
            Ok(n) if n > 0 => remaining -= n,
            Ok(_) => std::hint::spin_loop(),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => std::hint::spin_loop(),
            Err(e) => panic!("send_batch failed: {e}"),
        }
    }
}

fn recv_batch_all(batch: &mut BatchDgram, fd: RawFd, bufs: &mut [&mut [u8]], expected: usize) {
    let mut received = 0;
    while received < expected {
        match batch.recv_batch(fd, &mut bufs[received..]) {
            Ok(entries) if !entries.is_empty() => received += entries.len(),
            Ok(_) => std::hint::spin_loop(),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => std::hint::spin_loop(),
            Err(e) => panic!("recv_batch failed: {e}"),
        }
    }
}

fn bench_single_rw(c: &mut Criterion) {
    let (a, b) = socketpair();
    let fd_a = a.as_raw_fd();
    let fd_b = b.as_raw_fd();
    let payload = vec![0xABu8; DATAGRAM_SIZE];
    let mut read_buf = vec![0u8; DATAGRAM_SIZE + 64];

    let mut group = c.benchmark_group("single_rw");
    group.throughput(Throughput::Elements(TOTAL_DATAGRAMS as u64));

    group.bench_function("write+read", |bencher| {
        bencher.iter(|| {
            let mut remaining = TOTAL_DATAGRAMS;
            while remaining > 0 {
                let n = remaining.min(PINGPONG_CHUNK);
                for _ in 0..n {
                    single_write(fd_a, &payload);
                }
                for _ in 0..n {
                    single_read(fd_b, &mut read_buf);
                }
                remaining -= n;
            }
        });
    });

    group.finish();
}

fn bench_batch_rw(c: &mut Criterion) {
    let (a, b) = socketpair();
    let fd_a = a.as_raw_fd();
    let fd_b = b.as_raw_fd();
    let payload = vec![0xABu8; DATAGRAM_SIZE];

    let mut group = c.benchmark_group("batch_rw");
    group.throughput(Throughput::Elements(TOTAL_DATAGRAMS as u64));

    for &batch_size in &[64usize, 128, 256] {
        group.bench_with_input(
            BenchmarkId::from_parameter(batch_size),
            &batch_size,
            |bencher, &bs| {
                let mut batch = BatchDgram::new();
                // Hoist the bulk allocations (payload data and recv buffers)
                // out of the timed loop. The `Vec<&[u8]>` of send refs is
                // also reused across iterations.
                let send_payloads: Vec<&[u8]> = vec![payload.as_slice(); bs];
                let mut recv_buffers: Vec<Vec<u8>> =
                    (0..bs).map(|_| vec![0u8; DATAGRAM_SIZE + 64]).collect();

                bencher.iter(|| {
                    let mut remaining = TOTAL_DATAGRAMS;
                    while remaining > 0 {
                        let n = remaining.min(bs);
                        send_batch_all(&mut batch, fd_a, &send_payloads[..n]);

                        // The Vec<&mut [u8]> view must be rebuilt per chunk
                        // because mutable borrows are exclusive. The cost is
                        // ~bs * 16 bytes — negligible next to the bs * DATAGRAM_SIZE
                        // of actual I/O.
                        let mut recv_bufs: Vec<&mut [u8]> = recv_buffers[..n]
                            .iter_mut()
                            .map(|v| v.as_mut_slice())
                            .collect();
                        recv_batch_all(&mut batch, fd_b, &mut recv_bufs, n);

                        remaining -= n;
                    }
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_single_rw, bench_batch_rw);
criterion_main!(benches);
