# CLAUDE.md

This file provides guidance to Claude Code when working with the arcbox-error crate.

## Overview

Provides common error types shared across ArcBox crates. This crate reduces code duplication by defining a unified `CommonError` enum that captures frequently occurring error scenarios.

## Architecture

```
arcbox-error/src/
├── lib.rs          # Crate entry, re-exports
└── common.rs       # CommonError definition
```

## Key Types

### CommonError

```rust
pub enum CommonError {
    Io(std::io::Error),           // I/O errors from std
    Config(String),               // Configuration errors
    NotFound(String),             // Resource not found
    AlreadyExists(String),        // Resource already exists
    InvalidState(String),         // Invalid state transition
    Timeout(String),              // Operation timeout
    PermissionDenied(String),     // Permission denied
    Internal(String),             // Internal/unexpected errors
}
```

## Usage Pattern

### Direct Usage

```rust
use arcbox_error::CommonError;

fn find_resource(id: &str) -> Result<Resource, CommonError> {
    Err(CommonError::not_found(format!("resource {id}")))
}
```

### Wrapping in Crate-Specific Errors

```rust
use arcbox_error::CommonError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MyError {
    #[error(transparent)]
    Common(#[from] CommonError),

    #[error("my crate specific error: {0}")]
    Specific(String),
}
```

### Converting from CommonError

The `#[from]` attribute on `CommonError::Io` allows automatic conversion from `std::io::Error`:

```rust
fn read_config() -> Result<Config, CommonError> {
    let content = std::fs::read_to_string("config.toml")?; // io::Error auto-converts
    // ...
}
```

## Helper Methods

`CommonError` provides constructor methods for cleaner error creation:

```rust
CommonError::config("invalid port")
CommonError::not_found("container abc123")
CommonError::already_exists("network bridge0")
CommonError::invalid_state("container not running")
CommonError::timeout("connection timed out")
CommonError::permission_denied("/var/run/docker.sock")
CommonError::internal("unexpected state")
```

## Predicate Methods

```rust
error.is_io()              // Check if I/O error
error.is_not_found()       // Check if not found
error.is_already_exists()  // Check if already exists
error.is_timeout()         // Check if timeout
```

## Common Commands

```bash
cargo build -p arcbox-error
cargo test -p arcbox-error
cargo clippy -p arcbox-error
```

## Design Rationale

1. **Reduced duplication**: Common error variants like `Io`, `NotFound`, `Config` were duplicated across 6+ crates
2. **Consistent error messages**: Uniform error message format across the codebase
3. **Easier error handling**: Callers can use `?` operator with automatic conversion
4. **Type safety**: Strong typing prevents mixing up error categories

## Dependencies

- `thiserror`: Error derive macro for implementing `std::error::Error`
