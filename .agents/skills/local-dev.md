---
name: local-dev
description: "ArcBox local development quick loop. Build, sign, run daemon + helper for rapid iteration. Covers code signing with Developer ID, process cleanup, helper/daemon coordination, and common pitfalls. Trigger on: local dev, run daemon, build and run, sign daemon, helper, quick test, iteration."
---

# ArcBox Local Development

Quick build-sign-run loop for daily development iteration.

## Prerequisites

Before first use, ensure you have:

1. **Developer ID certificate** — `security find-identity -v -p codesigning | grep ArcBox`
   should show `Developer ID Application: ArcBox, Inc. (422ACSY6Y5)`.
   If missing, import the `.p12` from a team lead.

2. **Provisioning profile** — double-click `ArcBox_Daemon_DeveloperID.provisionprofile`
   to install. Without it, the daemon is killed on launch (exit 137).

3. **Rust toolchain** — `rustup show` should show 1.85+.

4. **musl cross-compiler** (only if modifying guest agent) —
   `brew install FiloSottile/musl-cross/musl-cross`

## Quick iteration loop

### Build + sign + run (one-shot)

```bash
# Build
cargo build -p arcbox-cli -p arcbox-daemon

# Sign (MUST use Developer ID, ad-hoc will be killed)
codesign --force --options runtime \
    --entitlements bundle/arcbox.entitlements \
    -s "Developer ID Application: ArcBox, Inc. (422ACSY6Y5)" \
    target/debug/arcbox-daemon

# Kill any old daemon (Desktop daemon included)
pkill -9 -f "arcbox-daemon" 2>/dev/null
pkill -9 -f "com.arcboxlabs.desktop.daemon" 2>/dev/null
sleep 2

# Run
RUST_LOG=arcbox=info target/debug/arcbox-daemon
```

### With helper (for L3 routing / DNS / docker socket integration)

```bash
# Terminal 1: helper (needs root)
cargo build -p arcbox-helper
sudo ARCBOX_HELPER_SOCKET=/tmp/arcbox-helper.sock target/debug/arcbox-helper

# Terminal 2: daemon (auto-connects to helper)
ARCBOX_HELPER_SOCKET=/tmp/arcbox-helper.sock \
  RUST_LOG=arcbox=info target/debug/arcbox-daemon
```

Or use Makefile shortcuts:

```bash
make run-helper   # terminal 1
make run-daemon   # terminal 2
```

### Quick smoke test

```bash
export DOCKER_HOST=unix://$HOME/.arcbox/run/docker.sock
docker run --rm alpine echo hello
```

## What needs re-signing

Only `arcbox-daemon` needs Developer ID signing. The other binaries:

| Binary | Signing needed | Why |
|--------|---------------|-----|
| `arcbox-daemon` | Developer ID + entitlements | Uses Virtualization.framework + vmnet |
| `abctl` (CLI) | None | Just a CLI client, no restricted APIs |
| `arcbox-helper` | None | Runs as root via sudo, no entitlement restrictions |
| `arcbox-agent` | None | Runs inside Linux VM, not macOS signed |

## Common issues

### `zsh: killed` immediately on launch

| Cause | Diagnosis | Fix |
|-------|-----------|-----|
| Ad-hoc signature | `codesign -dvv` shows `Signature=adhoc` | Re-sign with Developer ID |
| Missing provisioning profile | cert is correct but still killed | Install `.provisionprofile` |
| Missing `--options runtime` | Entitlements silently ignored | Add `--options runtime` to codesign |
| Forgot to re-sign after build | Binary timestamp > signature timestamp | Re-sign |

### DNS port 5553 already in use

ArcBox's daemon binds 5553. Dev daemon fails silently.

```bash
lsof -i :5553
# If occupied:
pkill -f "com.arcboxlabs.desktop.daemon"
# Or permanently:
launchctl bootout gui/$(id -u) com.arcboxlabs.desktop.daemon
```

### Code changes not taking effect

`abctl daemon start` exec()s a separate `arcbox-daemon` binary.
If you only built `arcbox-cli`, the daemon is still the old version.

```bash
# Always build both
cargo build -p arcbox-cli -p arcbox-daemon
# And re-sign daemon
codesign --force --options runtime \
    --entitlements bundle/arcbox.entitlements \
    -s "Developer ID Application: ArcBox, Inc. (422ACSY6Y5)" \
    target/debug/arcbox-daemon
```

### Helper not reachable

Daemon log: `DEBUG arcbox-helper not reachable, skipping self-setup`

```bash
# Check helper is running
ps aux | grep arcbox-helper

# Check socket exists
ls -la /tmp/arcbox-helper.sock   # dev mode
ls -la /var/run/arcbox-helper.sock  # production mode

# Check env var matches
# Both daemon and helper must use the same ARCBOX_HELPER_SOCKET
```

### Helper exits after 30s idle

This is by design (launchd re-launch pattern). In dev mode, just restart
it. The daemon will reconnect automatically.

## Daemon lifecycle (new flock-based design)

The daemon uses `flock(2)` on `~/.arcbox/run/daemon.lock` for exclusive
ownership. Key behaviors:

- **No stale PID issues**: lock auto-releases on process exit/crash
- **CLI uses flock probe**: `abctl daemon status` checks if lock is held,
  not whether a PID is alive
- **Startup order**: `init_early` → `acquire_lock` → `start_grpc` →
  `wait_for_resources` → `init_runtime`
- **gRPC available early**: desktop can connect while docker.img cleanup
  is still in progress (CLEANING_UP phase)

## Key file paths

| Path | Description |
|------|-------------|
| `bundle/arcbox.entitlements` | Entitlements plist for daemon signing |
| `~/.arcbox/run/daemon.lock` | flock-based daemon lock (+ PID for diagnostics) |
| `~/.arcbox/run/docker.sock` | Docker API socket |
| `~/.arcbox/run/arcbox.sock` | gRPC API socket |
| `~/.arcbox/data/docker.img` | VM data disk (auto-created) |
| `/tmp/arcbox-helper.sock` | Helper socket (dev mode) |
