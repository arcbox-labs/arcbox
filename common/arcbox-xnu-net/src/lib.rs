//! Batch datagram I/O via `sendmsg_x`/`recvmsg_x` (macOS) and
//! `sendmmsg`/`recvmmsg` (Linux).
//!
//! Provides safe wrappers around platform-specific batch datagram syscalls,
//! reducing syscall overhead by up to 99% for high-throughput datagram
//! workloads (e.g., L2 Ethernet frames over `AF_UNIX SOCK_DGRAM` socketpairs).
//!
//! # Platform support
//!
//! - **macOS**: Uses XNU's `recvmsg_x(2)` / `sendmsg_x(2)` (private but
//!   stable since OS X 10.11, syscalls 480/481).
//! - **Linux**: Uses `recvmmsg(2)` / `sendmmsg(2)`.
//!
//! # Example
//!
//! ```no_run
//! use arcbox_xnu_net::BatchDgram;
//!
//! # fn example(fd: std::os::fd::RawFd) -> std::io::Result<()> {
//! let mut batch = BatchDgram::new();
//! let mut buf = vec![0u8; 4096];
//! let mut bufs: Vec<&mut [u8]> = vec![buf.as_mut_slice()];
//! let entries = batch.recv_batch(fd, &mut bufs)?;
//! for (i, entry) in entries.iter().enumerate() {
//!     println!("datagram {i}: {} bytes", entry.len);
//! }
//! # Ok(())
//! # }
//! ```

#![cfg(any(target_os = "macos", target_os = "linux"))]

pub mod batch;
pub(crate) mod ffi;

// Compiled under `cfg(test)` as well as the `tokio` feature so the async
// test suite runs by default via `cargo test` (the workspace CI does not
// pass `--all-features`). The `tokio` dev-dependency is unconditional.
#[cfg(any(feature = "tokio", test))]
pub mod async_batch;

pub use batch::{BatchDgram, MAX_BATCH, RxEntry};

#[cfg(any(feature = "tokio", test))]
pub use async_batch::AsyncBatchDgram;
