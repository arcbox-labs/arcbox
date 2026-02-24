# CLAUDE.md

This file provides guidance to Claude Code when working with the arcbox-fs crate.

## Overview

VirtioFS implementation for high-performance host-to-guest filesystem sharing. Performance-critical path - custom built for >90% native I/O speed.

## Architecture

```
arcbox-fs/src/
├── lib.rs              # Crate entry
├── passthrough.rs      # PassthroughFs - maps guest ops to host
├── dispatcher.rs       # FuseDispatcher - parses FUSE protocol
├── cache.rs            # NegativeCache - caches "not found" results
├── inode.rs            # InodeData - maps guest inodes to host fds
└── fuse/               # FUSE protocol types
    ├── mod.rs
    ├── request.rs      # FUSE request parsing
    └── reply.rs        # FUSE reply formatting
```

## Data Flow

```
Guest FUSE request
       ↓
FuseDispatcher (parse FUSE op)
       ↓
PassthroughFs (execute on host)
       ↓
NegativeCache (cache miss results)
       ↓
Host syscall
```

## Key Types

```rust
/// Main filesystem implementation
pub struct PassthroughFs {
    inodes: InodeStore,        // inode -> InodeData mapping
    handles: HandleStore,      // file handle management
    cfg: Config,               // mount options
}

/// Negative cache for "file not found"
pub struct NegativeCache {
    entries: LruCache<PathBuf, Instant>,
    ttl: Duration,
}
```

## Platform Differences

```rust
// macOS: mode_t is u16
#[cfg(target_os = "macos")]
let mode = u32::from(libc::S_IFDIR);

// Linux: mode_t is u32
#[cfg(target_os = "linux")]
let mode = libc::S_IFDIR;

// xattr: different argument order
#[cfg(target_os = "macos")]
libc::fsetxattr(fd, name, value, size, 0, 0);
#[cfg(target_os = "linux")]
libc::fsetxattr(fd, name, value, size, 0);
```

## Performance Optimizations

1. **Negative caching**: Avoids repeated stat() on non-existent paths (node_modules, .git)
2. **Handle reuse**: Keep file handles open for frequently accessed files
3. **Readahead**: Prefetch sequential reads
4. **Write combining**: Batch small writes

## Common Commands

```bash
cargo build -p arcbox-fs
cargo test -p arcbox-fs
cargo bench --bench fs_bench -p arcbox-fs
```
