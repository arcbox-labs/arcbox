# CLAUDE.md

This file provides guidance to Claude Code when working with the arcbox-oci crate.

## Overview

`arcbox-oci` implements the OCI (Open Container Initiative) runtime specification for ArcBox. It provides parsing, validation, and management of OCI bundles and runtime configuration according to the [OCI Runtime Spec](https://github.com/opencontainers/runtime-spec).

Key capabilities:
- Parse and validate `config.json` files
- Load and create OCI bundles (directory containing config + rootfs)
- Manage container lifecycle state
- Define and validate lifecycle hooks

## Architecture

```
crates/arcbox-oci/src/
├── lib.rs          # Module exports and re-exports
├── config.rs       # OCI runtime-spec config.json types (Spec, Process, Linux, etc.)
├── bundle.rs       # Bundle and BundleBuilder for bundle management
├── state.rs        # Container state (State, Status, StateStore)
├── hooks.rs        # Lifecycle hooks (prestart, poststart, poststop, etc.)
└── error.rs        # OciError and Result types
```

## Key Types

### Spec (config.rs)

The main OCI runtime configuration structure:

```rust
use arcbox_oci::Spec;

// Load from file
let spec = Spec::load("/path/to/config.json")?;

// Parse from JSON string
let spec = Spec::from_json(json_str)?;

// Create default Linux spec
let spec = Spec::default_linux();

// Validate and save
spec.validate()?;
spec.save("/path/to/config.json")?;
```

Key fields:
- `oci_version`: OCI spec version (e.g., "1.2.0")
- `root`: Root filesystem configuration
- `process`: Container process (args, env, cwd, user, capabilities)
- `mounts`: Filesystem mounts
- `linux`: Linux-specific config (namespaces, cgroups, devices, seccomp)
- `hooks`: Lifecycle hooks

### Bundle (bundle.rs)

OCI bundle directory management:

```rust
use arcbox_oci::{Bundle, BundleBuilder};

// Load existing bundle
let bundle = Bundle::load("/path/to/bundle")?;
println!("OCI version: {}", bundle.spec().oci_version);
println!("Rootfs: {}", bundle.rootfs_path().display());

// Create new bundle with builder
let bundle = BundleBuilder::new()
    .hostname("my-container")
    .args(vec!["nginx".to_string(), "-g".to_string(), "daemon off;".to_string()])
    .add_env("NGINX_HOST", "localhost")
    .cwd("/")
    .user(1000, 1000)
    .readonly_rootfs(false)
    .terminal(true)
    .annotation("org.example.key", "value")
    .build("/path/to/bundle")?;
```

### State (state.rs)

Container lifecycle state:

```rust
use arcbox_oci::{State, Status, StateStore};

// Container states
pub enum Status {
    Creating,
    Created,
    Running,
    Stopped,
}

// State management
let store = StateStore::new("/var/run/arcbox")?;
store.save(&container_id, &state)?;
let state = store.load(&container_id)?;
```

### Hooks (hooks.rs)

Lifecycle hook definitions:

```rust
use arcbox_oci::{Hooks, Hook, HookType};

let hooks = Hooks {
    create_runtime: vec![Hook::new("/usr/bin/setup")],
    create_container: vec![],
    start_container: vec![],
    poststart: vec![Hook::new("/usr/bin/notify")],
    poststop: vec![Hook::new("/usr/bin/cleanup")],
    ..Default::default()
};

hooks.validate()?;
```

### Linux Configuration

```rust
use arcbox_oci::{Linux, Namespace, NamespaceType, Resources, CpuResources, MemoryResources};

let linux = Linux {
    namespaces: vec![
        Namespace { ns_type: NamespaceType::Pid, path: None },
        Namespace { ns_type: NamespaceType::Network, path: None },
        Namespace { ns_type: NamespaceType::Mount, path: None },
    ],
    resources: Some(Resources {
        memory: Some(MemoryResources {
            limit: Some(536_870_912),  // 512MB
            ..Default::default()
        }),
        cpu: Some(CpuResources {
            shares: Some(1024),
            quota: Some(100_000),
            period: Some(100_000),
            ..Default::default()
        }),
        ..Default::default()
    }),
    masked_paths: vec!["/proc/kcore".to_string()],
    readonly_paths: vec!["/proc/sys".to_string()],
    ..Default::default()
};
```

## Bundle Utilities

```rust
use arcbox_oci::bundle::utils;

// Check if directory is a valid bundle
if utils::is_bundle("/path/to/dir") {
    println!("Valid OCI bundle");
}

// Find all bundles in a directory
let bundles = utils::find_bundles("/var/lib/arcbox/bundles")?;

// Copy rootfs to bundle
utils::copy_rootfs("/source/rootfs", "/path/to/bundle")?;
```

## Common Commands

```bash
# Build
cargo build -p arcbox-oci

# Test (includes extensive config.json parsing tests)
cargo test -p arcbox-oci

# Run specific test
cargo test -p arcbox-oci test_parse_linux_namespaces
```

## OCI Spec Version

Current implementation supports OCI Runtime Spec v1.2.0 (`OCI_VERSION` constant).

## Error Handling

```rust
use arcbox_oci::{OciError, Result};

pub enum OciError {
    BundleNotFound(PathBuf),
    ConfigNotFound(PathBuf),
    InvalidBundle(String),
    InvalidConfig(String),
    InvalidVersion(String),
    InvalidPath(String),
    MissingField(&'static str),
    Io(std::io::Error),
    Json(serde_json::Error),
}
```
