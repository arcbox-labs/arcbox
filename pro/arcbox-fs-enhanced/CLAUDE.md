# CLAUDE.md

This file provides guidance to Claude Code when working with the arcbox-fs-enhanced crate.

## Overview

Enhanced filesystem service for ArcBox Pro. Extends arcbox-fs with advanced features:

- **Intelligent caching**: ML-based prefetching
- **Write coalescing**: Batch small writes
- **Compression**: Transparent compression
- **Deduplication**: Block-level dedup

## License

BSL-1.1 (converts to MIT after 4 years)

## Architecture

```
arcbox-fs-enhanced/src/
├── lib.rs          # Main exports and EnhancedFsConfig
├── cache.rs        # FileCache, CacheConfig, CacheStats
└── prefetch.rs     # PrefetchEngine, PrefetchConfig, PrefetchStats
```

### Dependency

This crate extends `arcbox-fs` (Core layer):
```
arcbox-fs-enhanced → arcbox-fs
```

## Key Types

| Type | Description |
|------|-------------|
| `EnhancedFsConfig` | Configuration with prefetch/cache/compression options |
| `FileCache` | In-memory file cache with configurable size |
| `CacheConfig` | Cache size and eviction settings |
| `CacheStats` | Cache hit/miss statistics |
| `PrefetchEngine` | ML-based prefetching engine |
| `PrefetchConfig` | Prefetch behavior settings |
| `PrefetchStats` | Prefetch effectiveness metrics |

## Status

Pro layer is partially implemented. Current implementation includes:
- Basic cache and prefetch module structure
- Configuration types with sensible defaults
- Integration with arcbox-fs base config

TODO:
- ML-based prefetch logic
- Write coalescing implementation
- Compression layer
- Block-level deduplication

## Common Commands

```bash
# Build
cargo build -p arcbox-fs-enhanced

# Test
cargo test -p arcbox-fs-enhanced

# Build with release optimizations
cargo build -p arcbox-fs-enhanced --release
```
