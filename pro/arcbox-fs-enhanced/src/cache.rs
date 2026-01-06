//! Enhanced caching layer.

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
