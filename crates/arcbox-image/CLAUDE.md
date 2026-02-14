# CLAUDE.md

This file provides guidance to Claude Code when working with the arcbox-image crate.

## Overview

OCI image management - pulls images from registries, extracts layers, and manages local image storage.

## Architecture

```
arcbox-image/src/
├── lib.rs          # Crate entry, ImageStore
├── pull.rs         # Image pulling from registry
├── extract.rs      # Layer extraction (tar, whiteouts)
├── registry.rs     # Registry client (Docker Hub, etc.)
├── manifest.rs     # OCI manifest parsing
├── digest.rs       # Content-addressable storage
└── error.rs        # ImageError
```

## Key Types

```rust
pub struct ImageStore {
    root: PathBuf,              // ~/.local/share/arcbox/images
    images: RwLock<HashMap<String, Image>>,
}

pub struct Image {
    pub id: String,             // sha256:...
    pub repo_tags: Vec<String>, // ["alpine:latest"]
    pub created: DateTime<Utc>,
    pub size: u64,
    pub layers: Vec<LayerInfo>,
}
```

## Image Pull Flow

```
pull("alpine:latest")
    ↓
Resolve tag → manifest digest
    ↓
Download manifest.json
    ↓
For each layer:
    ├── Check if exists (content-addressable)
    ├── Download layer.tar.gz
    └── Extract with whiteout handling
    ↓
Store image metadata
```

## Layer Storage

```
~/.local/share/arcbox/images/
├── sha256/
│   ├── abc123.../           # Layer directory
│   │   └── diff/            # Extracted files
│   └── def456.../
└── overlay/
    └── alpine_latest/       # Merged view for container
```

## Whiteout Handling

OCI uses special files to mark deletions:
- `.wh.filename` → delete `filename`
- `.wh..wh..opq` → opaque directory (delete all contents)

```rust
// extract.rs
if file_name.starts_with(WHITEOUT_PREFIX) {
    let target = file_name.strip_prefix(WHITEOUT_PREFIX);
    fs::remove_file(dest.join(target))?;
}
```

## Common Commands

```bash
cargo build -p arcbox-image
cargo test -p arcbox-image
```
