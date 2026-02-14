//! # arcbox-fs
//!
//! High-performance filesystem service for `ArcBox`.
//!
//! This crate implements VirtioFS-based file sharing between host and guest,
//! providing near-native file I/O performance.
//!
//! ## Key Features
//!
//! - **Zero-copy**: Direct memory mapping when possible
//! - **Parallel I/O**: Concurrent request handling
//! - **Intelligent caching**: Host-side metadata and data caching
//! - **FUSE protocol**: Compatible with standard virtiofs drivers
//!
//! ## Architecture
//!
//! ```text
//! Guest: mount -t virtiofs arcbox /mnt/arcbox
//!                    │
//!                    ▼
//! ┌─────────────────────────────────────────┐
//! │              arcbox-fs                   │
//! │  ┌─────────────────────────────────┐   │
//! │  │         FuseServer               │   │
//! │  │  - Request dispatch              │   │
//! │  │  - Reply handling                │   │
//! │  └─────────────────────────────────┘   │
//! │  ┌─────────────────────────────────┐   │
//! │  │        PassthroughFs             │   │
//! │  │  - Direct host filesystem access │   │
//! │  │  - File handle management        │   │
//! │  └─────────────────────────────────┘   │
//! └─────────────────────────────────────────┘
//! ```

#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]
// Filesystem code involves many low-level operations.
#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(clippy::all)]
#![allow(clippy::pedantic)]
#![allow(clippy::nursery)]

pub mod cache;
pub mod dispatcher;
pub mod error;
pub mod fuse;
pub mod passthrough;
pub mod server;

pub use cache::{NegativeCache, NegativeCacheConfig, NegativeCacheStats};
pub use dispatcher::{DispatcherConfig, FuseDispatcher, RequestContext, ResponseBuilder};
pub use error::{FsError, Result};
pub use fuse::{FuseAttr, FuseInHeader, FuseOpcode, FuseOutHeader, StatFs};
pub use passthrough::{DirEntry, FileType, PassthroughConfig, PassthroughFs};
pub use server::FsServer;

/// Filesystem configuration.
#[derive(Debug, Clone)]
pub struct FsConfig {
    /// Tag for virtiofs mount.
    pub tag: String,
    /// Host directory to share.
    pub source: String,
    /// Number of worker threads.
    pub num_threads: usize,
    /// Enable writeback caching.
    pub writeback_cache: bool,
    /// Cache timeout for directory entries (seconds).
    pub cache_timeout: u64,
}

impl Default for FsConfig {
    fn default() -> Self {
        Self {
            tag: "arcbox".to_string(),
            source: String::new(),
            num_threads: 4,
            writeback_cache: true,
            cache_timeout: 1,
        }
    }
}
