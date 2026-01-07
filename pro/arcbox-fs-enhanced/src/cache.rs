//! Enhanced caching layer for filesystem operations.
//!
//! Provides an LRU cache for file data with configurable size limits.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

/// Cache entry for file data.
#[derive(Debug, Clone)]
struct CacheEntry {
    /// File data.
    data: Vec<u8>,
    /// File offset.
    offset: u64,
    /// Last access timestamp (monotonic counter).
    last_access: u64,
    /// Size of the entry in bytes.
    size: usize,
}

/// Cache key combining inode and offset.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    /// Inode number.
    inode: u64,
    /// Block-aligned offset.
    block_offset: u64,
}

/// Cache statistics.
#[derive(Debug, Default)]
pub struct CacheStats {
    /// Number of cache hits.
    pub hits: u64,
    /// Number of cache misses.
    pub misses: u64,
    /// Bytes read from cache.
    pub bytes_read: u64,
    /// Bytes written to cache.
    pub bytes_written: u64,
    /// Current cache size in bytes.
    pub current_size: u64,
    /// Number of evictions.
    pub evictions: u64,
}

impl CacheStats {
    /// Returns the hit ratio.
    #[must_use]
    pub fn hit_ratio(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            self.hits as f64 / total as f64
        }
    }
}

/// Cache configuration.
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Maximum cache size in bytes.
    pub max_size: u64,
    /// Block size for caching (default 64KB).
    pub block_size: usize,
    /// Enable write-through caching.
    pub write_through: bool,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_size: 512 * 1024 * 1024, // 512MB
            block_size: 64 * 1024,        // 64KB blocks
            write_through: true,
        }
    }
}

/// LRU cache for file data.
pub struct FileCache {
    /// Cache configuration.
    config: CacheConfig,
    /// Cache entries keyed by (inode, block_offset).
    entries: RwLock<HashMap<CacheKey, CacheEntry>>,
    /// Current cache size in bytes.
    current_size: AtomicU64,
    /// Monotonic counter for LRU tracking.
    access_counter: AtomicU64,
    /// Cache statistics.
    stats: RwLock<CacheStats>,
}

impl FileCache {
    /// Creates a new file cache with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(CacheConfig::default())
    }

    /// Creates a new file cache with custom configuration.
    #[must_use]
    pub fn with_config(config: CacheConfig) -> Self {
        Self {
            config,
            entries: RwLock::new(HashMap::new()),
            current_size: AtomicU64::new(0),
            access_counter: AtomicU64::new(0),
            stats: RwLock::new(CacheStats::default()),
        }
    }

    /// Creates a new file cache with specified max size in MB.
    #[must_use]
    pub fn with_max_size_mb(max_size_mb: u64) -> Self {
        Self::with_config(CacheConfig {
            max_size: max_size_mb * 1024 * 1024,
            ..Default::default()
        })
    }

    /// Reads data from cache.
    ///
    /// Returns `Some(data)` if the requested data is in cache, `None` otherwise.
    pub fn read(&self, inode: u64, offset: u64, size: usize) -> Option<Vec<u8>> {
        let block_offset = self.align_offset(offset);
        let key = CacheKey { inode, block_offset };

        let entries = match self.entries.read() {
            Ok(e) => e,
            Err(_) => {
                self.record_miss();
                return None;
            }
        };

        let entry = match entries.get(&key) {
            Some(e) => e,
            None => {
                drop(entries);
                self.record_miss();
                return None;
            }
        };

        // Check if the requested range is within this cache entry.
        let entry_start = entry.offset;
        let entry_end = entry.offset + entry.data.len() as u64;
        let request_end = offset + size as u64;

        if offset >= entry_start && request_end <= entry_end {
            // Update access time (we need write lock for this).
            drop(entries);

            if let Ok(mut entries) = self.entries.write() {
                if let Some(entry) = entries.get_mut(&key) {
                    entry.last_access = self.access_counter.fetch_add(1, Ordering::Relaxed);
                }
            }

            // Extract the requested portion.
            let entries = match self.entries.read() {
                Ok(e) => e,
                Err(_) => {
                    self.record_miss();
                    return None;
                }
            };

            let entry = match entries.get(&key) {
                Some(e) => e,
                None => {
                    drop(entries);
                    self.record_miss();
                    return None;
                }
            };

            let start_idx = (offset - entry.offset) as usize;
            let end_idx = start_idx + size;

            if end_idx <= entry.data.len() {
                let data = entry.data[start_idx..end_idx].to_vec();

                // Update stats.
                if let Ok(mut stats) = self.stats.write() {
                    stats.hits += 1;
                    stats.bytes_read += data.len() as u64;
                }

                return Some(data);
            }
        }

        // Cache miss.
        self.record_miss();
        None
    }

    /// Records a cache miss in statistics.
    fn record_miss(&self) {
        if let Ok(mut stats) = self.stats.write() {
            stats.misses += 1;
        }
    }

    /// Writes data to cache.
    ///
    /// The data is cached at block-aligned boundaries.
    pub fn write(&self, inode: u64, offset: u64, data: &[u8]) {
        if data.is_empty() {
            return;
        }

        let block_offset = self.align_offset(offset);
        let key = CacheKey { inode, block_offset };

        // Check if we need to evict entries.
        let new_size = data.len();
        self.ensure_space(new_size);

        let access_time = self.access_counter.fetch_add(1, Ordering::Relaxed);

        let entry = CacheEntry {
            data: data.to_vec(),
            offset,
            last_access: access_time,
            size: new_size,
        };

        if let Ok(mut entries) = self.entries.write() {
            // Remove old entry if exists.
            if let Some(old_entry) = entries.remove(&key) {
                self.current_size.fetch_sub(old_entry.size as u64, Ordering::Relaxed);
            }

            // Insert new entry.
            entries.insert(key, entry);
            self.current_size.fetch_add(new_size as u64, Ordering::Relaxed);
        }

        // Update stats.
        if let Ok(mut stats) = self.stats.write() {
            stats.bytes_written += new_size as u64;
            stats.current_size = self.current_size.load(Ordering::Relaxed);
        }
    }

    /// Invalidates cache entries for a file.
    pub fn invalidate(&self, inode: u64) {
        if let Ok(mut entries) = self.entries.write() {
            let keys_to_remove: Vec<_> = entries
                .keys()
                .filter(|k| k.inode == inode)
                .cloned()
                .collect();

            for key in keys_to_remove {
                if let Some(entry) = entries.remove(&key) {
                    self.current_size.fetch_sub(entry.size as u64, Ordering::Relaxed);
                }
            }
        }

        // Update stats.
        if let Ok(mut stats) = self.stats.write() {
            stats.current_size = self.current_size.load(Ordering::Relaxed);
        }
    }

    /// Invalidates a specific range in cache.
    pub fn invalidate_range(&self, inode: u64, offset: u64, _size: usize) {
        let block_offset = self.align_offset(offset);
        let key = CacheKey { inode, block_offset };

        if let Ok(mut entries) = self.entries.write() {
            if let Some(entry) = entries.remove(&key) {
                self.current_size.fetch_sub(entry.size as u64, Ordering::Relaxed);
            }
        }

        // Update stats.
        if let Ok(mut stats) = self.stats.write() {
            stats.current_size = self.current_size.load(Ordering::Relaxed);
        }
    }

    /// Clears all cache entries.
    pub fn clear(&self) {
        if let Ok(mut entries) = self.entries.write() {
            entries.clear();
            self.current_size.store(0, Ordering::Relaxed);
        }

        if let Ok(mut stats) = self.stats.write() {
            stats.current_size = 0;
        }
    }

    /// Returns cache statistics.
    #[must_use]
    pub fn stats(&self) -> CacheStats {
        self.stats
            .read()
            .map(|s| CacheStats {
                hits: s.hits,
                misses: s.misses,
                bytes_read: s.bytes_read,
                bytes_written: s.bytes_written,
                current_size: self.current_size.load(Ordering::Relaxed),
                evictions: s.evictions,
            })
            .unwrap_or_default()
    }

    /// Returns current cache size in bytes.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.current_size.load(Ordering::Relaxed)
    }

    /// Returns cache capacity in bytes.
    #[must_use]
    pub fn capacity(&self) -> u64 {
        self.config.max_size
    }

    /// Aligns offset to block boundary.
    fn align_offset(&self, offset: u64) -> u64 {
        (offset / self.config.block_size as u64) * self.config.block_size as u64
    }

    /// Ensures there's enough space for new data by evicting LRU entries.
    fn ensure_space(&self, needed: usize) {
        let max_size = self.config.max_size;
        let current = self.current_size.load(Ordering::Relaxed);

        if current + needed as u64 <= max_size {
            return;
        }

        // Need to evict entries.
        let target_size = max_size.saturating_sub(needed as u64);

        if let Ok(mut entries) = self.entries.write() {
            // Find LRU entries to evict.
            while self.current_size.load(Ordering::Relaxed) > target_size && !entries.is_empty() {
                // Find the entry with the smallest last_access.
                let lru_key = entries
                    .iter()
                    .min_by_key(|(_, e)| e.last_access)
                    .map(|(k, _)| k.clone());

                if let Some(key) = lru_key {
                    if let Some(entry) = entries.remove(&key) {
                        self.current_size.fetch_sub(entry.size as u64, Ordering::Relaxed);

                        if let Ok(mut stats) = self.stats.write() {
                            stats.evictions += 1;
                        }
                    }
                } else {
                    break;
                }
            }
        }
    }
}

impl Default for FileCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_write_read() {
        let cache = FileCache::with_max_size_mb(1);

        // Write some data.
        let data = vec![1u8, 2, 3, 4, 5];
        cache.write(1, 0, &data);

        // Read it back.
        let result = cache.read(1, 0, 5);
        assert_eq!(result, Some(data));

        // Check stats.
        let stats = cache.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 0);
    }

    #[test]
    fn test_cache_miss() {
        let cache = FileCache::new();

        // Try to read non-existent data.
        let result = cache.read(1, 0, 100);
        assert!(result.is_none());

        let stats = cache.stats();
        assert_eq!(stats.hits, 0);
        assert_eq!(stats.misses, 1);
    }

    #[test]
    fn test_cache_invalidate() {
        let cache = FileCache::new();

        cache.write(1, 0, &[1, 2, 3]);
        cache.write(1, 1000, &[4, 5, 6]);
        cache.write(2, 0, &[7, 8, 9]);

        // Invalidate inode 1.
        cache.invalidate(1);

        // Should miss for inode 1.
        assert!(cache.read(1, 0, 3).is_none());
        assert!(cache.read(1, 1000, 3).is_none());

        // Should still hit for inode 2.
        assert!(cache.read(2, 0, 3).is_some());
    }

    #[test]
    fn test_cache_eviction() {
        // Create a very small cache (1KB).
        let cache = FileCache::with_config(CacheConfig {
            max_size: 1024,
            block_size: 256,
            write_through: true,
        });

        // Write more than 1KB of data.
        for i in 0..10 {
            let data = vec![i as u8; 200];
            cache.write(i, 0, &data);
        }

        // Cache should have evicted some entries.
        assert!(cache.size() <= 1024);

        let stats = cache.stats();
        assert!(stats.evictions > 0);
    }

    #[test]
    fn test_hit_ratio() {
        let cache = FileCache::new();

        cache.write(1, 0, &[1, 2, 3, 4, 5]);

        // 3 hits.
        cache.read(1, 0, 5);
        cache.read(1, 0, 5);
        cache.read(1, 0, 5);

        // 1 miss.
        cache.read(2, 0, 5);

        let stats = cache.stats();
        assert_eq!(stats.hits, 3);
        assert_eq!(stats.misses, 1);
        assert!((stats.hit_ratio() - 0.75).abs() < 0.001);
    }
}
