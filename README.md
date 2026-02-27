<div align="center">

# ArcBox

**A fast, lightweight container runtime for macOS -- built from scratch in Rust.**

[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.85+-orange.svg)](https://www.rust-lang.org)
[![Status](https://img.shields.io/badge/status-alpha-red.svg)](#status)

</div>

---

> **Alpha software.** ArcBox is under active development. Expect rough edges,
> missing features, and breaking changes. We publish early so you can try it,
> break it, and help shape it.

## Quick Start

```bash
# 1. Install ArcBox
curl -sSL https://install.arcbox.dev | sh

# 2. Start the daemon
arcbox start

# 3. Point Docker CLI at ArcBox
arcbox docker enable

# 4. Run a container
docker run -d -p 8080:80 nginx

# 5. Verify
curl http://localhost:8080
```

To switch back to Docker Desktop at any time:

```bash
arcbox docker disable
```

## Requirements

- macOS 13 (Ventura) or later
- Apple Silicon (M1/M2/M3/M4) -- Intel support is in progress
- Docker CLI installed (ArcBox replaces the Docker engine, not the CLI)
- ~500 MB disk space (runtime + boot assets)

## What Works Today

ArcBox can already serve as a drop-in Docker engine for common workflows:

- **Container lifecycle** -- `docker run`, `stop`, `rm`, `logs`, `exec`, `inspect`
- **Image management** -- pull from Docker Hub and OCI registries (ARM64)
- **Port forwarding** -- `-p 8080:80` maps host ports into containers
- **Volume mounts** -- `-v /host/path:/container/path` and named volumes
- **Container networking** -- containers can reach the internet and resolve DNS
- **Inter-container DNS** -- containers on the same network resolve each other by name
- **Docker Compose** -- basic `docker-compose up/down` for multi-container projects
- **Docker context switching** -- `arcbox docker enable/disable` to toggle between ArcBox and Docker Desktop
- **40+ Docker API endpoints** -- compatible with Docker Engine API v1.43

## Known Limitations

ArcBox is alpha software. The following features are not yet available:

| Feature | Status |
|---------|--------|
| `docker build` | Not implemented -- use `docker buildx` with a remote builder or pre-built images |
| x86/amd64 image support (Rosetta) | Not yet -- only ARM64 images work |
| Docker plugins / extensions | Not supported |
| Linux host | macOS only for now |
| GUI | CLI only -- a desktop app is planned |

Other things to be aware of:

- Cold boot takes a few seconds on first launch. Subsequent container starts are faster.
- Some advanced Docker API features (swarm, secrets, configs) are not implemented.
- Error messages may be less polished than Docker Desktop.
- If you hit a bug, please [open an issue](https://github.com/arcboxd/arcbox/issues).

## Performance

ArcBox uses Apple's Virtualization.framework with a custom VirtIO stack, zero-copy
networking, and a purpose-built VirtioFS implementation. Our targets for the
stable release (these are goals, not guarantees at this stage):

| Metric | ArcBox Target | Docker Desktop (typical) |
|--------|---------------|--------------------------|
| Cold boot | < 2s | 5-10s |
| Idle memory | < 150 MB | 1-2 GB |
| Idle CPU | < 0.1% | 0.5-3% |
| File I/O (vs native) | > 90% | 50-70% (with VirtioFS) |

Current alpha performance varies. We are focused on correctness first, then
optimization.

## Building from Source

If you prefer to build ArcBox yourself:

```bash
# Clone
git clone https://github.com/arcboxd/arcbox.git
cd arcbox

# Build
cargo build --release

# Sign (required for macOS virtualization)
codesign --entitlements tests/resources/entitlements.plist --force -s - \
    target/release/arcbox

# Run
./target/release/arcbox --help
```

### Build Requirements

- Rust 1.85+ (install via [rustup](https://rustup.rs))
- Xcode Command Line Tools (`xcode-select --install`)
- musl cross-compiler for guest agent (optional):
  ```bash
  brew install FiloSottile/musl-cross/musl-cross
  rustup target add aarch64-unknown-linux-musl
  ```

## Uninstall

```bash
# Stop the daemon
arcbox stop

# Restore Docker Desktop as default
arcbox docker disable

# Remove ArcBox files
rm -rf ~/.arcbox
rm /usr/local/bin/arcbox

# Remove the launchd service (if installed)
launchctl bootout gui/$(id -u) ~/Library/LaunchAgents/dev.arcbox.daemon.plist
rm ~/Library/LaunchAgents/dev.arcbox.daemon.plist
```

## Contributing

We welcome contributions. See [CLAUDE.md](CLAUDE.md) for current contribution and repository guidelines.

- Use `cargo clippy -- -D warnings` before submitting
- All code comments must be in English
- `unsafe` code requires a `// SAFETY:` justification

## License

- **Core** (`common/`, `hypervisor/`, `services/`, `comm/`, `app/`) -- [MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE)
- **Pro** (`pro/`) -- [BSL-1.1](LICENSE-BSL-1.1) (converts to MIT after 4 years)

See [LICENSE](LICENSE) for the full text.

---

<div align="center">

**[Website](https://arcbox.dev)** -- **[Documentation](https://docs.arcbox.dev)** -- **[Discord](https://discord.gg/arcbox)**

</div>
