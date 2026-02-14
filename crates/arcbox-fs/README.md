# arcbox-fs

High-performance filesystem service for ArcBox.

## Overview

This crate implements VirtioFS-based file sharing between host and guest, providing near-native file I/O performance. It handles FUSE protocol requests from the guest and maps them to host filesystem operations.

## Features

- **Zero-copy I/O**: Direct memory mapping when possible
- **Parallel I/O**: Concurrent request handling with multiple worker threads
- **Intelligent caching**: Negative cache for "file not found" results
- **FUSE protocol**: Compatible with standard virtiofs drivers
- **Passthrough filesystem**: Direct mapping of guest operations to host

## Architecture

```
Guest: mount -t virtiofs arcbox /mnt/arcbox
                   |
                   v
+------------------------------------------+
|               arcbox-fs                   |
|  +------------------------------------+  |
|  |          FuseDispatcher            |  |
|  |  - Request parsing                 |  |
|  |  - Reply handling                  |  |
|  +------------------------------------+  |
|  +------------------------------------+  |
|  |         PassthroughFs              |  |
|  |  - Direct host filesystem access   |  |
|  |  - File handle management          |  |
|  +------------------------------------+  |
|  +------------------------------------+  |
|  |         NegativeCache              |  |
|  |  - Caches non-existent paths       |  |
|  +------------------------------------+  |
+------------------------------------------+
```

## Usage

```rust
use arcbox_fs::{FsConfig, PassthroughFs, FuseDispatcher};

let config = FsConfig {
    tag: "arcbox".to_string(),
    source: "/path/to/share".to_string(),
    num_threads: 4,
    writeback_cache: true,
    cache_timeout: 1,
};

let fs = PassthroughFs::new(PassthroughConfig::default())?;
let dispatcher = FuseDispatcher::new(fs);
```

## Performance Optimizations

- **Negative caching**: Avoids repeated stat() calls on non-existent paths (effective for node_modules, .git)
- **Handle reuse**: Keeps file handles open for frequently accessed files
- **Readahead**: Prefetches sequential reads
- **Write combining**: Batches small writes

## License

MIT OR Apache-2.0
