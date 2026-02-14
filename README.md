<div align="center">

# ArcBox

**A high-performance container and VM runtime written in pure Rust**

[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.85+-orange.svg)](https://www.rust-lang.org)
[![Status](https://img.shields.io/badge/status-alpha-red.svg)](#status)

[Features](#features) • [Installation](#installation) • [Quick Start](#quick-start) • [Architecture](#architecture) • [Contributing](#contributing)

</div>

---

## Overview

ArcBox is a next-generation container and virtual machine runtime built from the ground up in Rust, designed for maximum performance on macOS and Linux. Our goal is to deliver the fastest container experience possible—faster cold boots, lower memory usage, and native-speed file I/O.

## Performance Goals

| Metric | ArcBox Target | Comparison |
|--------|---------------|------------|
| Cold boot | **< 1.5s** | ~2s typical |
| Warm boot | **< 500ms** | ~1s typical |
| Idle memory | **< 150MB** | ~200MB typical |
| Idle CPU | **< 0.05%** | ~0.1% typical |
| File I/O | **> 90%** native | 75-95% typical |
| Network | **> 50 Gbps** | ~45 Gbps typical |

## Features

- **Pure Rust** — Memory-safe, no data races, zero-cost abstractions
- **Native virtualization** — Leverages Virtualization.framework (macOS) and KVM (Linux)
- **Custom VirtioFS** — Purpose-built filesystem with smart caching and prefetching
- **High-performance networking** — Custom network stack with zero-copy I/O
- **Docker compatible** — Drop-in replacement via Docker Engine API v1.43

## Status

> **Alpha** — Under active development. APIs may change.

ArcBox is currently in early alpha. Core virtualization, VirtioFS, and basic container operations are functional on macOS (Apple Silicon). We welcome contributors who want to push the boundaries of container performance.

## Platform Support

| Platform | Status |
|----------|--------|
| macOS (Apple Silicon) | 🟢 Primary target |
| macOS (Intel) | 🟡 In progress |
| Linux (x86_64/ARM64) | 🟡 Planned |

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/arcboxd/arcbox.git
cd arcbox

# Build
cargo build --release

# Run
./target/release/arcbox --help
```

### Requirements

- Rust 1.85+ (Edition 2024)
- macOS 13+ or Linux with KVM support
- Xcode Command Line Tools (macOS)

## Quick Start

```bash
# Start the daemon
arcbox daemon

# Run a container (Docker-compatible)
docker run -it alpine sh

# Or use the native CLI
arcbox run alpine
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                       arcbox-cli / arcbox-api                   │
├─────────────────────────────────────────────────────────────────┤
│                          arcbox-core                            │
├──────────────────┬──────────────────┬───────────────────────────┤
│    arcbox-fs     │    arcbox-net    │    arcbox-container       │
├──────────────────┴──────────────────┴───────────────────────────┤
│                         arcbox-virtio                           │
├─────────────────────────────────────────────────────────────────┤
│                          arcbox-vmm                             │
├─────────────────────────────────────────────────────────────────┤
│                       arcbox-hypervisor                         │
├────────────────────────────┬────────────────────────────────────┤
│  Virtualization.framework  │               KVM                  │
│         (macOS)            │             (Linux)                │
└────────────────────────────┴────────────────────────────────────┘
```

### Crate Overview

| Crate | Description |
|-------|-------------|
| `arcbox-hypervisor` | Cross-platform virtualization abstraction |
| `arcbox-vmm` | Virtual machine monitor (vCPU, memory, devices) |
| `arcbox-virtio` | VirtIO device implementations |
| `arcbox-fs` | High-performance VirtioFS with caching |
| `arcbox-net` | Custom network stack |
| `arcbox-container` | Container lifecycle management |
| `arcbox-docker` | Docker Engine API compatibility |

## Development

```bash
# Build
cargo build

# Run tests
cargo test

# Run with logging
RUST_LOG=debug cargo run --bin arcbox

# Lint
cargo clippy -- -D warnings

# Format
cargo fmt
```

### Guest Agent Cross-Compilation

```bash
# Install musl toolchain (macOS)
brew install FiloSottile/musl-cross/musl-cross

# Add target
rustup target add aarch64-unknown-linux-musl

# Build guest agent
cargo build -p arcbox-agent --target aarch64-unknown-linux-musl --release
```

### macOS Signing

VM operations require entitlement signing:

```bash
codesign --entitlements tests/resources/entitlements.plist --force -s - <binary>
```

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Guidelines

- Use `clippy` with pedantic lints
- All `unsafe` code requires justification and audit
- Comments must be in English
- Platform-specific code should be abstracted via traits

## License

ArcBox uses a multi-license structure:

- **Core** (`crates/`) — [MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE)
- **Pro** (`pro/`) — [BSL-1.1](LICENSE-BSL-1.1) (converts to MIT after 4 years)

See [LICENSE](LICENSE) for details.

## Acknowledgments

ArcBox builds on the shoulders of giants:
- The Rust community and ecosystem
- Apple's Virtualization.framework
- The Linux KVM project
- The OCI and Docker communities

---

<div align="center">

**[Website](https://arcbox.dev)** • **[Documentation](https://docs.arcbox.dev)** • **[Discord](https://discord.gg/arcbox)**

</div>
