//! `VirtIO` filesystem device (virtio-fs).
//!
//! This implements the high-performance shared filesystem using virtiofs
//! protocol for host-guest file sharing.
//!
//! # Architecture
//!
//! ```text
//! Guest Driver (virtio-fs)
//!       │
//!       ▼ (virtqueue)
//! ┌─────────────────────────┐
//! │      VirtioFs           │
//! │  ┌─────────────────┐   │
//! │  │   FuseSession   │   │
//! │  │  - INIT state   │   │
//! │  │  - features     │   │
//! │  └─────────────────┘   │
//! └───────────┬─────────────┘
//!             │ dispatch
//!             ▼
//!     FuseRequestHandler
//!       (implemented by arcbox-fs)
//! ```
//!
//! ## Module layout
//!
//! - `protocol`: FUSE wire-protocol constants
//! - `request`: `FuseRequest` / `FuseResponse` envelopes
//! - `session`: `FuseSession` — INIT handshake + negotiated state
//! - `handler`: `FuseRequestHandler` trait
//! - `device`: `FsConfig`, `VirtioFs`, `VirtioDevice` impl

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
#![allow(clippy::too_many_lines)]

mod device;
mod handler;
mod protocol;
mod request;
mod session;

pub use device::{FsConfig, VirtioFs};
pub use handler::FuseRequestHandler;
pub use protocol::{
    DEFAULT_MAX_PAGES, DEFAULT_MAX_READAHEAD, DEFAULT_MAX_WRITE, FUSE_ASYNC_READ, FUSE_BIG_WRITES,
    FUSE_CACHE_SYMLINKS, FUSE_KERNEL_MINOR_VERSION, FUSE_KERNEL_VERSION, FUSE_MAP_ALIGNMENT,
    FUSE_PARALLEL_DIROPS, FUSE_WRITEBACK_CACHE,
};
pub use request::{FuseRequest, FuseResponse};
pub use session::FuseSession;
