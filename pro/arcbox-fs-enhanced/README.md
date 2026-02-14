# arcbox-fs-enhanced

Enhanced filesystem service for ArcBox Pro with intelligent caching and performance optimizations.

## Overview

This crate extends `arcbox-fs` (Core layer) with advanced features designed to maximize filesystem performance in virtualized environments. It provides ML-based prefetching, write coalescing, transparent compression, and block-level deduplication.

## Features

- **Intelligent caching**: ML-based prefetching to reduce latency
- **Write coalescing**: Batch small writes for improved throughput
- **Compression**: Transparent compression to reduce storage and I/O
- **Deduplication**: Block-level dedup for efficient storage

## Usage

```rust
use arcbox_fs_enhanced::{EnhancedFsConfig, FileCache, PrefetchEngine};

// Create enhanced filesystem configuration
let config = EnhancedFsConfig {
    prefetch: true,
    cache_size_mb: 512,
    compression: false,
    ..Default::default()
};

// Use FileCache for in-memory caching
let cache = FileCache::new(CacheConfig::default());

// Use PrefetchEngine for intelligent prefetching
let prefetch = PrefetchEngine::new(PrefetchConfig::default());
```

## License

BSL-1.1 (converts to MIT after 4 years)
