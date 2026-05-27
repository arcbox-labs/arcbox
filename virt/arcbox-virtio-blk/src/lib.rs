//! `VirtIO` block device (virtio-blk).
//!
//! Implements the `VirtIO` block device specification for disk I/O.
//!
//! Supports:
//! - Synchronous I/O with standard file operations
//! - Asynchronous I/O with tokio
//! - Direct I/O (`O_DIRECT`) for bypassing OS cache
//! - Memory-mapped I/O for zero-copy operations
//!
//! ## Module layout
//!
//! - `backend`: `AsyncBlockBackend` trait
//! - `mmap`: memory-mapped backend (zero-copy)
//! - `direct_io`: `O_DIRECT` backend (Linux only)
//! - `request`: wire types — config, header, status, request type
//! - `device`: `VirtioBlock` device + `VirtioDevice` impl

#![allow(clippy::ptr_as_ptr)]
#![allow(clippy::borrow_as_ptr)]
#![allow(clippy::unnecessary_cast)]
#![allow(clippy::cognitive_complexity)]
#![allow(clippy::map_unwrap_or)]
#![allow(clippy::useless_vec)]
#![allow(clippy::unnecessary_wraps)]
#![allow(clippy::redundant_clone)]
#![allow(clippy::unnecessary_map_or)]
#![allow(clippy::missing_fields_in_debug)]
#![allow(clippy::needless_lifetimes)]
#![allow(clippy::needless_collect)]
#![allow(mismatched_lifetime_syntaxes)]

mod backend;
mod device;
#[cfg(target_os = "linux")]
mod direct_io;
mod mmap;
mod request;

pub use backend::AsyncBlockBackend;
pub use device::VirtioBlock;
#[cfg(target_os = "linux")]
pub use direct_io::DirectIoBackend;
pub use mmap::MmapBackend;
pub use request::{BlockConfig, BlockRequestHeader, BlockRequestType, BlockStatus};
