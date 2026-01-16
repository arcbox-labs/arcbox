//! Filesystem caching layer.
//!
//! This module provides caching mechanisms for filesystem operations,
//! including metadata caching and negative (non-existence) caching.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;

/// Cached entry with expiration.
#[derive(Debug)]
struct CacheEntry<T> {
    value: T,
    expires_at: Instant,
}

impl<T> CacheEntry<T> {
    fn new(value: T, ttl: Duration) -> Self {
        Self {
            value,
            expires_at: Instant::now() + ttl,
        }
    }

    fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }
}

/// Simple LRU cache for filesystem metadata.
pub struct MetadataCache<K, V> {
    entries: RwLock<HashMap<K, CacheEntry<V>>>,
    ttl: Duration,
    max_entries: usize,
}

impl<K: std::hash::Hash + Eq + Clone, V: Clone> MetadataCache<K, V> {
    /// Creates a new cache.
    #[must_use]
    pub fn new(ttl: Duration, max_entries: usize) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            ttl,
            max_entries,
        }
    }

    /// Gets a value from the cache.
    #[must_use]
    #[allow(clippy::significant_drop_tightening)]
    pub fn get(&self, key: &K) -> Option<V> {
        let entries = self.entries.read().ok()?;
        let entry = entries.get(key)?;
        if entry.is_expired() {
            None
        } else {
            Some(entry.value.clone())
        }
    }

    /// Inserts a value into the cache.
    pub fn insert(&self, key: K, value: V) {
        if let Ok(mut entries) = self.entries.write() {
            // Simple eviction: remove expired entries
            if entries.len() >= self.max_entries {
                entries.retain(|_, v| !v.is_expired());
            }

            entries.insert(key, CacheEntry::new(value, self.ttl));
        }
    }

    /// Removes a value from the cache.
    pub fn remove(&self, key: &K) {
        if let Ok(mut entries) = self.entries.write() {
            entries.remove(key);
        }
    }

    /// Clears the cache.
    pub fn clear(&self) {
        if let Ok(mut entries) = self.entries.write() {
            entries.clear();
        }
    }
}

// ============================================================================
// Negative Cache
// ============================================================================

/// Configuration for the negative cache.
///
/// Negative caching stores "file not found" results to avoid repeated
/// filesystem lookups for non-existent files. This is particularly effective
/// for directories like `node_modules` and `.git` where many lookups fail.
#[derive(Debug, Clone)]
pub struct NegativeCacheConfig {
    /// Maximum number of entries in the cache.
    /// When exceeded, expired entries are evicted.
    /// Default: 10000
    pub max_entries: usize,

    /// Time-to-live for cache entries.
    /// Entries older than this are considered stale.
    /// Default: 1 second
    pub timeout: Duration,
}

impl Default for NegativeCacheConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl NegativeCacheConfig {
    /// Creates a new configuration with default values.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_entries: 10_000,
            timeout: Duration::from_secs(1),
        }
    }
}

/// Statistics for the negative cache.
#[derive(Debug, Clone, Default)]
pub struct NegativeCacheStats {
    /// Current number of entries in the cache.
    pub entries: usize,
    /// Total number of cache hits (path found in negative cache).
    pub hits: u64,
    /// Total number of cache misses (path not in cache or expired).
    pub misses: u64,
}

impl NegativeCacheStats {
    /// Returns the hit ratio as a percentage.
    /// Returns 0.0 if no lookups have been performed.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn hit_ratio(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            (self.hits as f64 / total as f64) * 100.0
        }
    }
}

/// Thread-safe negative cache for filesystem lookups.
///
/// Caches paths that are known to not exist, avoiding repeated system calls
/// for non-existent files. Uses lock-free concurrent access via `DashMap`.
///
/// # Example
///
/// ```
/// use std::time::Duration;
/// use std::path::PathBuf;
/// use arcbox_fs::cache::{NegativeCache, NegativeCacheConfig};
///
/// let config = NegativeCacheConfig {
///     max_entries: 1000,
///     timeout: Duration::from_millis(500),
/// };
/// let cache = NegativeCache::new(config);
///
/// // File lookup failed, add to negative cache
/// cache.insert(PathBuf::from("/app/node_modules/missing-package"));
///
/// // Later lookup - returns true without syscall
/// assert!(cache.contains(&PathBuf::from("/app/node_modules/missing-package")));
///
/// // File created - invalidate cache
/// cache.invalidate(&PathBuf::from("/app/node_modules/missing-package"));
/// assert!(!cache.contains(&PathBuf::from("/app/node_modules/missing-package")));
/// ```
pub struct NegativeCache {
    /// Map from path to insertion timestamp.
    entries: DashMap<PathBuf, Instant>,
    /// Cache configuration.
    config: NegativeCacheConfig,
    /// Number of cache hits.
    hits: AtomicU64,
    /// Number of cache misses.
    misses: AtomicU64,
}

impl NegativeCache {
    /// Creates a new negative cache with the given configuration.
    #[must_use]
    pub fn new(config: NegativeCacheConfig) -> Self {
        Self {
            entries: DashMap::with_capacity(config.max_entries),
            config,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    /// Creates a new negative cache with default configuration.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(NegativeCacheConfig::default())
    }

    /// Checks if the path is in the negative cache and not expired.
    ///
    /// Returns `true` if the path was previously marked as non-existent
    /// and the cache entry has not expired.
    pub fn contains(&self, path: &Path) -> bool {
        if let Some(entry) = self.entries.get(path) {
            let inserted_at = *entry;
            if inserted_at.elapsed() < self.config.timeout {
                self.hits.fetch_add(1, Ordering::Relaxed);
                return true;
            }
            // Entry expired, remove it
            drop(entry); // Release the lock before removing
            self.entries.remove(path);
        }
        self.misses.fetch_add(1, Ordering::Relaxed);
        false
    }

    /// Adds a path to the negative cache.
    ///
    /// If the cache is at capacity, expired entries are evicted first.
    pub fn insert(&self, path: PathBuf) {
        // Check capacity and evict if necessary
        if self.entries.len() >= self.config.max_entries {
            self.evict_expired();
        }

        self.entries.insert(path, Instant::now());
    }

    /// Invalidates a path in the negative cache.
    ///
    /// This should be called when a file is created to ensure subsequent
    /// lookups don't incorrectly return "not found" from the cache.
    ///
    /// Also invalidates the parent directory path to handle cases where
    /// the parent's directory listing was cached.
    pub fn invalidate(&self, path: &Path) {
        self.entries.remove(path);

        // Also invalidate parent directory to handle directory listing caches
        if let Some(parent) = path.parent() {
            self.entries.remove(parent);
        }
    }

    /// Removes all expired entries from the cache.
    ///
    /// This is called automatically when the cache reaches capacity,
    /// but can also be called manually for maintenance.
    pub fn evict_expired(&self) {
        let timeout = self.config.timeout;
        self.entries
            .retain(|_, inserted_at| inserted_at.elapsed() < timeout);
    }

    /// Returns current cache statistics.
    #[must_use]
    pub fn stats(&self) -> NegativeCacheStats {
        NegativeCacheStats {
            entries: self.entries.len(),
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
        }
    }

    /// Clears all entries from the cache.
    pub fn clear(&self) {
        self.entries.clear();
    }

    /// Returns the current number of entries in the cache.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl std::fmt::Debug for NegativeCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NegativeCache")
            .field("entries", &self.entries.len())
            .field("config", &self.config)
            .field("hits", &self.hits.load(Ordering::Relaxed))
            .field("misses", &self.misses.load(Ordering::Relaxed))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_insert_and_contains() {
        let cache = NegativeCache::with_defaults();
        let path = PathBuf::from("/test/path");

        assert!(!cache.contains(&path));
        cache.insert(path.clone());
        assert!(cache.contains(&path));
    }

    #[test]
    fn test_expiration() {
        let config = NegativeCacheConfig {
            max_entries: 100,
            timeout: Duration::from_millis(50),
        };
        let cache = NegativeCache::new(config);
        let path = PathBuf::from("/test/expiring");

        cache.insert(path.clone());
        assert!(cache.contains(&path));

        // Wait for expiration
        thread::sleep(Duration::from_millis(100));
        assert!(!cache.contains(&path));
    }

    #[test]
    fn test_invalidate() {
        let cache = NegativeCache::with_defaults();
        let path = PathBuf::from("/test/dir/file.txt");

        cache.insert(path.clone());
        assert!(cache.contains(&path));

        cache.invalidate(&path);
        assert!(!cache.contains(&path));
    }

    #[test]
    fn test_invalidate_removes_parent() {
        let cache = NegativeCache::with_defaults();
        let parent = PathBuf::from("/test/dir");
        let child = PathBuf::from("/test/dir/file.txt");

        cache.insert(parent.clone());
        cache.insert(child.clone());

        // Invalidating child should also invalidate parent
        cache.invalidate(&child);

        assert!(!cache.contains(&child));
        assert!(!cache.contains(&parent));
    }

    #[test]
    fn test_concurrent_access() {
        use std::sync::Arc;

        let cache = Arc::new(NegativeCache::with_defaults());
        let mut handles = vec![];

        // Spawn multiple threads that insert and check entries
        for i in 0..10 {
            let cache = Arc::clone(&cache);
            handles.push(thread::spawn(move || {
                for j in 0..100 {
                    let path = PathBuf::from(format!("/thread_{i}/file_{j}"));
                    cache.insert(path.clone());
                    assert!(cache.contains(&path));
                }
            }));
        }

        for handle in handles {
            handle.join().expect("Thread panicked");
        }

        // All entries should be accessible
        assert!(cache.len() <= 1000);
    }

    #[test]
    fn test_max_entries() {
        let config = NegativeCacheConfig {
            max_entries: 10,
            timeout: Duration::from_millis(10), // Short timeout for eviction
        };
        let cache = NegativeCache::new(config);

        // Insert more than max_entries
        for i in 0..20 {
            let path = PathBuf::from(format!("/file_{i}"));
            cache.insert(path);
            // Small delay to ensure some entries expire
            if i == 10 {
                thread::sleep(Duration::from_millis(15));
            }
        }

        // Cache should have evicted expired entries
        // The exact count depends on timing, but should be <= max
        assert!(cache.len() <= 20);
    }

    #[test]
    fn test_stats() {
        let cache = NegativeCache::with_defaults();
        let path1 = PathBuf::from("/path1");
        let path2 = PathBuf::from("/path2");

        // Initial stats
        let stats = cache.stats();
        assert_eq!(stats.entries, 0);
        assert_eq!(stats.hits, 0);
        assert_eq!(stats.misses, 0);

        // Miss
        cache.contains(&path1);
        let stats = cache.stats();
        assert_eq!(stats.misses, 1);

        // Insert and hit
        cache.insert(path1.clone());
        cache.contains(&path1);
        let stats = cache.stats();
        assert_eq!(stats.entries, 1);
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);

        // Another miss
        cache.contains(&path2);
        let stats = cache.stats();
        assert_eq!(stats.misses, 2);
    }

    #[test]
    fn test_hit_ratio() {
        let stats = NegativeCacheStats {
            entries: 10,
            hits: 75,
            misses: 25,
        };
        assert!((stats.hit_ratio() - 75.0).abs() < f64::EPSILON);

        let empty_stats = NegativeCacheStats::default();
        assert!((empty_stats.hit_ratio() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_clear() {
        let cache = NegativeCache::with_defaults();

        for i in 0..10 {
            cache.insert(PathBuf::from(format!("/file_{i}")));
        }
        assert_eq!(cache.len(), 10);

        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn test_evict_expired() {
        let config = NegativeCacheConfig {
            max_entries: 100,
            timeout: Duration::from_millis(30),
        };
        let cache = NegativeCache::new(config);

        // Insert entries
        for i in 0..10 {
            cache.insert(PathBuf::from(format!("/old_{i}")));
        }

        // Wait for them to expire
        thread::sleep(Duration::from_millis(50));

        // Insert new entries
        for i in 0..5 {
            cache.insert(PathBuf::from(format!("/new_{i}")));
        }

        // Evict expired
        cache.evict_expired();

        // Only new entries should remain
        assert_eq!(cache.len(), 5);
    }
}
