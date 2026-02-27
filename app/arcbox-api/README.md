# arcbox-api

API server layer for ArcBox.

## Overview

This crate provides ArcBox gRPC service implementations over `arcbox-core`
runtime state. It is currently machine-focused (`MachineServiceImpl`).
Other service definitions may exist in shared protocol crates but are not all
implemented here.

## Features

- gRPC `MachineService` with machine lifecycle + guest-agent pass-through calls

## Usage

```rust
use arcbox_api::MachineServiceImpl;
use arcbox_core::Runtime;
use std::sync::Arc;

let runtime = Arc::new(Runtime::new(Default::default())?);
let _machine_service = MachineServiceImpl::new(runtime);
```

## License

MIT OR Apache-2.0
