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
pub mod cache;
pub mod dispatcher;
pub mod error;
pub mod fuse;
pub mod passthrough;
pub mod server;

pub use cache::{
    AdaptiveTtlConfig, NegativeCache, NegativeCacheConfig, NegativeCacheStats, TtlRule,
};
pub use dispatcher::{DispatcherConfig, FuseDispatcher, RequestContext, ResponseBuilder};
pub use error::{FsError, Result};
pub use fuse::{FuseAttr, FuseInHeader, FuseOpcode, FuseOutHeader, StatFs};
pub use passthrough::{DirEntry, FileType, PassthroughConfig, PassthroughFs};
pub use server::FsServer;

/// Trait for DAX (Direct Access) memory mapping between host files and guest IPA.
///
/// Implemented by the VMM to map/unmap host file pages into the guest's
/// DAX window. The FUSE dispatcher calls this when handling
/// `FUSE_SETUPMAPPING` / `FUSE_REMOVEMAPPING` requests.
pub trait DaxMapper: Send + Sync {
    /// Maps a host file region into the guest DAX window.
    ///
    /// - `host_fd`: file descriptor of the host file
    /// - `file_offset`: byte offset within the file
    /// - `window_offset`: byte offset within the DAX window
    /// - `length`: mapping length in bytes (page-aligned)
    /// - `writable`: whether the mapping is writable
    fn setup_mapping(
        &self,
        host_fd: i32,
        file_offset: u64,
        window_offset: u64,
        length: u64,
        writable: bool,
    ) -> std::result::Result<(), i32>;

    /// Removes a mapping from the guest DAX window.
    fn remove_mapping(&self, window_offset: u64, length: u64) -> std::result::Result<(), i32>;
}

/// Cache profile for a VirtioFS share.
///
/// Controls the FUSE entry and attribute cache timeouts reported to the
/// guest kernel. Higher values reduce FUSE round-trips at the cost of
/// delayed visibility of host filesystem changes.
#[derive(Debug, Clone)]
pub enum CacheProfile {
    /// Static content (runtime binaries, container images).
    /// Entry/attr timeout: 300s. Aggressive caching.
    Static,
    /// Dynamic content (user source files).
    /// Entry/attr timeout: 1s. Minimal caching.
    Dynamic,
    /// Custom timeout values.
    Custom {
        entry_timeout_secs: u64,
        attr_timeout_secs: u64,
    },
}

impl CacheProfile {
    /// Returns the entry timeout for FUSE responses.
    #[must_use]
    pub fn entry_timeout(&self) -> std::time::Duration {
        match self {
            Self::Static => std::time::Duration::from_secs(300),
            Self::Dynamic => std::time::Duration::from_secs(1),
            Self::Custom {
                entry_timeout_secs, ..
            } => std::time::Duration::from_secs(*entry_timeout_secs),
        }
    }

    /// Returns the attr timeout for FUSE responses.
    #[must_use]
    pub fn attr_timeout(&self) -> std::time::Duration {
        match self {
            Self::Static => std::time::Duration::from_secs(300),
            Self::Dynamic => std::time::Duration::from_secs(1),
            Self::Custom {
                attr_timeout_secs, ..
            } => std::time::Duration::from_secs(*attr_timeout_secs),
        }
    }
}

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
    /// Cache profile controlling FUSE entry/attr timeouts.
    /// Takes precedence over `cache_timeout` when set.
    pub cache_profile: CacheProfile,
    /// Cache timeout for directory entries and attributes (seconds).
    /// Used as a fallback when `cache_profile` is not explicitly set.
    /// Higher values reduce FUSE round-trips but delay visibility of
    /// host filesystem changes inside the guest.
    pub cache_timeout: u64,
    /// Negative lookup cache TTL (seconds). Caches ENOENT results to avoid
    /// repeated stat() calls for non-existent paths.
    pub negative_cache_ttl: u64,
}

impl Default for FsConfig {
    fn default() -> Self {
        Self {
            tag: "arcbox".to_string(),
            source: String::new(),
            num_threads: 4,
            writeback_cache: true,
            cache_profile: CacheProfile::Custom {
                entry_timeout_secs: 10,
                attr_timeout_secs: 10,
            },
            cache_timeout: 10,
            negative_cache_ttl: 5,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_cache_profile_static() {
        let profile = CacheProfile::Static;
        assert_eq!(profile.entry_timeout(), Duration::from_secs(300));
        assert_eq!(profile.attr_timeout(), Duration::from_secs(300));
    }

    #[test]
    fn test_cache_profile_dynamic() {
        let profile = CacheProfile::Dynamic;
        assert_eq!(profile.entry_timeout(), Duration::from_secs(1));
        assert_eq!(profile.attr_timeout(), Duration::from_secs(1));
    }

    #[test]
    fn test_cache_profile_custom() {
        let profile = CacheProfile::Custom {
            entry_timeout_secs: 42,
            attr_timeout_secs: 7,
        };
        assert_eq!(profile.entry_timeout(), Duration::from_secs(42));
        assert_eq!(profile.attr_timeout(), Duration::from_secs(7));
    }

    #[test]
    fn test_fs_config_default_uses_custom_profile() {
        let config = FsConfig::default();
        // Default profile should use the same timeout as cache_timeout
        assert_eq!(
            config.cache_profile.entry_timeout(),
            Duration::from_secs(10)
        );
        assert_eq!(config.cache_profile.attr_timeout(), Duration::from_secs(10));
    }
}
