# arcbox-image

Container image management for ArcBox.

## Overview

This crate handles OCI image operations including pulling images from registries, managing layers, extracting rootfs, and local image storage. It is fully compatible with the OCI Image Specification and Docker registries.

## Features

- **Image Pull**: Download images from Docker Hub and OCI-compliant registries
- **Layer Management**: Content-addressable storage with deduplication
- **Rootfs Extraction**: Extract and merge layers with whiteout handling
- **Registry Client**: Authentication and manifest resolution
- **ImageStore**: Local image metadata and layer storage

## Usage

```rust
use arcbox_image::{ImageStore, ImagePuller, ImageRef};

// Parse image reference
let image_ref = ImageRef::parse("alpine:latest").unwrap();

// Create image store
let store = ImageStore::new("/path/to/images")?;

// Pull image with progress callback
let puller = ImagePuller::new(&store);
puller.pull(&image_ref, |progress| {
    println!("Pulling: {:?}", progress);
}).await?;

// List local images
for image in store.list() {
    println!("{}: {} bytes", image.repo_tags[0], image.size);
}
```

## OCI Compatibility

- Supports OCI Image Specification v1.0
- Compatible with Docker Registry HTTP API v2
- Handles multi-platform manifests (manifest lists)
- Proper whiteout file handling for layer merging

## License

MIT OR Apache-2.0
