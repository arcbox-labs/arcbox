# Contributing to ArcBox

We welcome contributions of all kinds -- bug reports, feature requests, docs
improvements, and code.

## Building from Source

```bash
git clone https://github.com/arcboxlabs/arcbox.git
cd arcbox

# Build, sign, and run the daemon (requires Developer ID certificate)
make run-daemon

# In another terminal, run the privileged helper (requires sudo)
make run-helper
```

The Makefile handles building, code signing, and launching. See
[Code Signing](#code-signing) for certificate setup.

### Prerequisites

- Rust 1.85+ (install via [rustup](https://rustup.rs))
- macOS 13+ with Xcode Command Line Tools (`xcode-select --install`)
- ~500 MB disk space
- ArcBox Developer ID certificate + provisioning profile (see [Code Signing](#code-signing))
- [musl-cross](https://github.com/nicklockwood/musl-cross) for guest agent cross-compilation (see below)

### Guest Agent Cross-Compilation

The `arcbox-agent` runs inside the Linux guest VM. Without it, the VM
cannot boot. Build and install it before running the daemon:

```bash
# One-time toolchain setup
brew install FiloSottile/musl-cross/musl-cross
rustup target add aarch64-unknown-linux-musl

# Build the agent (always builds in release mode)
make build-agent

# Copy to the data directory so the daemon can find it
mkdir -p ~/.arcbox/bin
cp target/aarch64-unknown-linux-musl/release/arcbox-agent ~/.arcbox/bin/
```

### Manual Build (Without Make)

If you prefer not to use `make`:

```bash
# Build CLI and daemon
cargo build -p arcbox-cli -p arcbox-daemon

# Sign the daemon (see "Code Signing" below)
codesign --force --options runtime \
    --entitlements bundle/arcbox.entitlements \
    -s "Developer ID Application: ArcBox, Inc. (422ACSY6Y5)" \
    target/debug/arcbox-daemon

# Run
./target/debug/arcbox-daemon
```

## Project Structure

```
common/          Shared error types, constants, asset utilities
virt/            Virtualization.framework bindings, VMM, VirtIO devices, VirtioFS, networking
rpc/             Protobuf definitions, gRPC services, vsock/unix transport
runtime/         Container state, OCI image/runtime
app/             Core orchestration, API server, Docker Engine API, CLI, daemon
guest/           In-VM agent (cross-compiled for Linux)
bundle/          Entitlements, launchd plists, app bundle resources
scripts/         Dev workflow scripts (boot asset setup, rebuild-and-run)
tests/           Test resources and fixture build scripts
docs/            Supplementary docs (boot assets, daemon lifecycle, data dirs)
```

## Code Standards

- Run `make check` before committing -- zero warnings required (runs
  `cargo clippy --workspace --all-targets -- -D warnings` and `cargo fmt --check`)
- All code comments must be in English
- `unsafe` blocks require a `// SAFETY:` comment explaining the invariant
- Use `thiserror` for crate-specific errors, `anyhow` in CLI/API layers
- Prefer `RwLock` over `Arc<Mutex<T>>` on hot paths

## Commit Guidelines

- Format: `type(scope): summary` (e.g. `fix(net): correct checksum on fragmented packets`)
- Keep commits atomic and compilable; target ~200 lines changed (excluding generated files)
- Do not add `Co-Authored-By` lines

## Code Signing

ArcBox uses restricted macOS entitlements (`com.apple.security.virtualization`,
`com.apple.vm.networking`) that require a **Developer ID certificate** and a
**provisioning profile** approved by Apple. Ad-hoc signing (`-s -`) will not
work — the kernel kills the process on launch.

> [!IMPORTANT]
> You must sign `arcbox-daemon` after **every** build. Without signing, the
> binary is killed immediately on launch with no error message (exit code 137).

### What you need

| Item | Description | How to get |
|------|-------------|-----------|
| **Developer ID certificate** | `Developer ID Application: ArcBox, Inc. (422ACSY6Y5)` | Import the `.p12` file into Keychain Access (ask a team lead) |
| **Provisioning profile** | `ArcBox_Daemon_DeveloperID.provisionprofile` | Double-click to install (ask a team lead) |
| **Entitlements file** | `bundle/arcbox.entitlements` | Already in the repo |

> [!NOTE]
> Both the `.p12` and `.provisionprofile` files are distributed internally.
> Contact a team lead if you don't have them. **Do not commit these files to
> the repository.**

### Signing after build

The Makefile auto-detects the signing identity from Keychain:

```bash
make sign-daemon
```

To sign manually (or to override the identity):

```bash
codesign --force --options runtime \
    --entitlements bundle/arcbox.entitlements \
    -s "Developer ID Application: ArcBox, Inc. (422ACSY6Y5)" \
    target/debug/arcbox-daemon
```

### Verifying your setup

```bash
# 1. Confirm the certificate is installed
security find-identity -v -p codesigning | grep "ArcBox"
# Expected: "Developer ID Application: ArcBox, Inc. (422ACSY6Y5)"

# 2. Confirm entitlements are embedded
codesign -d --entitlements - target/debug/arcbox-daemon
# Should list com.apple.security.virtualization, com.apple.vm.networking, etc.

# 3. Confirm the daemon starts
make run-daemon
# Should print startup logs (Ctrl+C to stop)
```

### Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `zsh: killed` immediately on launch | Missing provisioning profile | Install `ArcBox_Daemon_DeveloperID.provisionprofile` (double-click) |
| `zsh: killed` immediately on launch | Certificate not trusted / incomplete chain | Re-import `.p12`, ensure Keychain shows the private key under the cert |
| `codesign` reports `ambiguous identity` | Multiple certs with same name | `security delete-identity` to remove duplicates |
| `codesign` reports `errSecInternalComponent` | Private key missing (only cert imported) | Re-export `.p12` with both cert **and** private key selected |
| Daemon starts but `--options runtime` was omitted | Restricted entitlements silently ignored | Always include `--options runtime` in the codesign command |

> [!NOTE]
> For deeper diagnostics — chain-to-self-signed-root errors, manual trust
> overrides, and suppressing the per-sign keychain password prompt — see
> [`docs/code-signing-troubleshooting.md`](docs/code-signing-troubleshooting.md).

> [!WARNING]
> The `--options runtime` flag enables Hardened Runtime, which is **required**
> for restricted entitlements to take effect. Without it, macOS accepts the
> signature but the kernel ignores `com.apple.vm.networking` — networking
> features will fail silently or the process may be killed.

## macOS Development Notes

### Platform Pitfalls

- **libc `mode_t`**: `u16` on macOS, `u32` on Linux. Always use `u32::from(libc::S_IFMT)`.
- **xattr API**: Parameter order differs between macOS and Linux. Implement separately with `#[cfg(target_os)]`.
- **`fallocate`**: Not available on macOS. Use `ftruncate` as fallback.

## Privileged Helper (`arcbox-helper`)

`arcbox-helper` is a root-privileged daemon that performs host mutations the
main daemon cannot do as a regular user: routing table changes, DNS resolver
files (`/etc/resolver/`), `/var/run/docker.sock` symlink, and
`/usr/local/bin/` CLI tool symlinks.

Communication uses [tarpc](https://github.com/google/tarpc) over a Unix
socket at `/var/run/arcbox-helper.sock`.

### Architecture

```
arcbox-daemon / abctl
        │  tarpc (bincode over Unix socket)
        ▼
  arcbox-helper  (runs as root)
        │
        ├── route   → /sbin/route add/delete
        ├── dns     → /etc/resolver/<domain>
        ├── socket  → /var/run/docker.sock symlink
        └── cli     → /usr/local/bin/{docker,...} symlinks
```

### Production Registration

```bash
# Build CLI and helper in release mode, then install (requires sudo)
cargo build --release -p arcbox-cli -p arcbox-helper
sudo ./target/release/abctl _install
```

This does three things:
1. Copies `arcbox-helper` to `/usr/local/libexec/arcbox-helper` (owned by `root:wheel`)
2. Writes the launchd plist to `/Library/LaunchDaemons/com.arcboxlabs.desktop.helper.plist`
3. Runs `launchctl bootstrap system <plist>` — launchd then creates the socket and starts the helper on-demand (socket activation)

### Local Development (Manual Mode)

During development you don't need launchd registration. The helper falls back
to binding its own socket when `launch_activate_socket` is unavailable.

The easiest way is via Makefile — both `run-helper` and `run-daemon` default
to `/tmp/arcbox-helper.sock`, so they automatically find each other:

```bash
# Terminal 1: run the helper (builds + sudo)
make run-helper

# Terminal 2: run the daemon (auto-connects to /tmp/arcbox-helper.sock)
make run-daemon
```

You can also override the socket path:

```bash
make run-helper HELPER_SOCKET=/var/run/arcbox-helper.sock
make run-daemon HELPER_SOCKET=/var/run/arcbox-helper.sock
```

#### Key Development Details

| Aspect | Behavior |
|--------|----------|
| **Peer auth** | Skipped in debug builds (`cfg!(debug_assertions)`) — any process can connect |
| **Socket permissions** | `0o666` in manual mode for convenience; in production launchd owns the socket |
| **Idle timeout** | Exits after 30s with zero connections (designed for launchd re-launch). Re-run manually if it exits |
| **Env override** | `ARCBOX_HELPER_SOCKET` overrides the socket path for both server and client |

> **Note**: Even in manual mode, the helper needs `sudo` because it executes
> `/sbin/route`, writes to `/etc/resolver/`, and creates symlinks in
> `/var/run/` and `/usr/local/bin/`. If you only need to test the tarpc
> transport without actually performing mutations, you can run without sudo
> and expect the mutation calls to fail.

### Updating the Helper After Code Changes

If you have the helper registered via launchd and want to test a new build:

```bash
make reload-helper   # bootout → rebuild → copy → bootstrap
```

To do a fresh launchd install from scratch:

```bash
make install-helper   # build → install binary → register plist → bootstrap
```

Or skip launchd entirely and use `make run-helper` as described above.

## Uninstall

The CLI handles full uninstall — daemon, helper, launchd plists, sockets,
symlinks, Docker context, and data:

```bash
sudo abctl _uninstall
```

Use `--keep-data` to preserve container data (`~/.arcbox/data`).

## License

By contributing, you agree that your contributions will be licensed under
[MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE).
