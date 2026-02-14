//! # arcbox-fs-enhanced
//!
//! Enhanced filesystem service for ArcBox Pro.
//!
//! This crate extends arcbox-fs with advanced features:
//!
//! - **Intelligent caching**: ML-based prefetching
//! - **Write coalescing**: Batch small writes
//! - **Compression**: Transparent compression
//! - **Deduplication**: Block-level dedup
//!
//! ## License
//!
//! This crate is licensed under BSL-1.1, which converts to MIT after 2 years.

#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::module_name_repetitions)]
// TODO: Remove these allows once the module is complete.
#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(clippy::all)]
#![allow(clippy::pedantic)]
#![allow(clippy::nursery)]

pub mod cache;
pub mod prefetch;

pub use cache::{CacheConfig, CacheStats, FileCache};
pub use prefetch::{PrefetchConfig, PrefetchEngine, PrefetchStats};

/// Enhanced filesystem configuration.
#[derive(Debug, Clone)]
pub struct EnhancedFsConfig {
    /// Base filesystem configuration.
    pub base: arcbox_fs::FsConfig,
    /// Enable intelligent prefetching.
    pub prefetch: bool,
    /// Cache size in MB.
    pub cache_size_mb: u64,
    /// Enable compression.
    pub compression: bool,
}

impl Default for EnhancedFsConfig {
    fn default() -> Self {
        Self {
            base: arcbox_fs::FsConfig::default(),
            prefetch: true,
            cache_size_mb: 512,
            compression: false,
        }
    }
}
