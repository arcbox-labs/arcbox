//! Benchmarks comparing single-datagram vs batch I/O on AF_UNIX SOCK_DGRAM
//! socketpairs. Measures the syscall overhead reduction from recvmsg_x/sendmsg_x
//! (macOS) or recvmmsg/sendmmsg (Linux).

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

use arcbox_xnu_net::BatchDgram;

const DATAGRAM_SIZE: usize = 4000;
const TOTAL_DATAGRAMS: usize = 10_000;

/// Creates a non-blocking socketpair with 8 MB buffers.
fn socketpair() -> (OwnedFd, OwnedFd) {
    let mut fds: [i32; 2] = [0; 2];
    let ret = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) };
    assert_eq!(ret, 0);
    let (a, b) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    let buf_size: libc::c_int = 8 * 1024 * 1024;
    for fd in [a.as_raw_fd(), b.as_raw_fd()] {
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                std::ptr::from_ref(&buf_size).cast(),
                std::mem::size_of_val(&buf_size) as libc::socklen_t,
            );
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                std::ptr::from_ref(&buf_size).cast(),
                std::mem::size_of_val(&buf_size) as libc::socklen_t,
            );
            let flags = libc::fcntl(fd, libc::F_GETFL);
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
    }
    (a, b)
}

fn single_write(fd: RawFd, data: &[u8]) {
    // SAFETY: valid fd and buffer.
    unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) };
}

fn single_read(fd: RawFd, buf: &mut [u8]) -> usize {
    // SAFETY: valid fd and buffer.
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 { 0 } else { n as usize }
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
            for _ in 0..TOTAL_DATAGRAMS {
                single_write(fd_a, &payload);
            }
            for _ in 0..TOTAL_DATAGRAMS {
                single_read(fd_b, &mut read_buf);
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

    for batch_size in [64, 128, 256] {
        group.bench_with_input(
            BenchmarkId::from_parameter(batch_size),
            &batch_size,
            |bencher, &bs| {
                let mut batch = BatchDgram::new();
                let mut recv_buffers: Vec<Vec<u8>> =
                    (0..bs).map(|_| vec![0u8; DATAGRAM_SIZE + 64]).collect();

                bencher.iter(|| {
                    let send_payloads: Vec<&[u8]> = (0..bs).map(|_| payload.as_slice()).collect();
                    let mut remaining = TOTAL_DATAGRAMS;

                    // Send all datagrams in batches.
                    while remaining > 0 {
                        let this_batch = remaining.min(bs);
                        let bufs = &send_payloads[..this_batch];
                        match batch.send_batch(fd_a, bufs) {
                            Ok(n) if n > 0 => remaining -= n,
                            _ => {}
                        }
                    }

                    // Receive all datagrams in batches.
                    let mut received = 0;
                    while received < TOTAL_DATAGRAMS {
                        let mut bufs: Vec<&mut [u8]> =
                            recv_buffers.iter_mut().map(|b| b.as_mut_slice()).collect();
                        if let Ok((_, n)) = batch.recv_batch(fd_b, &mut bufs) {
                            received += n;
                        }
                    }
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_single_rw, bench_batch_rw);
criterion_main!(benches);
