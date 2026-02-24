# arcbox-oci

OCI runtime specification support for ArcBox.

## Overview

This crate provides parsing and management of OCI (Open Container Initiative) runtime specification structures:

- **Configuration**: Parse and validate `config.json` according to OCI runtime-spec
- **Bundles**: Load and create OCI bundles (directory containing config + rootfs)
- **State**: Container lifecycle state management
- **Hooks**: Lifecycle hook definitions and validation

Implements the [OCI Runtime Specification](https://github.com/opencontainers/runtime-spec) v1.2.0.

## Features

- Full OCI runtime-spec v1.2.0 compliance
- Bundle management with builder pattern
- Container state persistence
- Lifecycle hooks (prestart, poststart, poststop, etc.)
- Linux-specific configuration (namespaces, cgroups, devices, seccomp)

## Usage

```rust
use arcbox_oci::{Bundle, BundleBuilder, Spec};

// Load an existing bundle
let bundle = Bundle::load("/path/to/bundle")?;
println!("OCI version: {}", bundle.spec().oci_version);

// Create a new bundle with builder
let bundle = BundleBuilder::new()
    .hostname("my-container")
    .args(vec!["nginx".to_string(), "-g".to_string(), "daemon off;".to_string()])
    .add_env("NGINX_HOST", "localhost")
    .cwd("/")
    .build("/path/to/new-bundle")?;

// Parse config directly
let spec = Spec::load("/path/to/config.json")?;
spec.validate()?;
```

### Container State Management

```rust
use arcbox_oci::{State, Status, StateStore};

let store = StateStore::new("/var/run/arcbox")?;

// Save container state
store.save(&container_id, &state)?;

// Load container state
let state = store.load(&container_id)?;
assert_eq!(state.status, Status::Running);
```

## License

MIT OR Apache-2.0
