# ArcBox E2E Tests

End-to-end integration tests for ArcBox container runtime.

## Overview

E2E tests exercise the full ArcBox stack:
- Daemon process
- Virtual machine (via Virtualization.framework)
- Guest agent (arcbox-agent)
- Container runtime

All E2E tests are marked with `#[ignore]` because they require a complete VM environment with kernel, initramfs, and proper entitlements.

## Prerequisites

### 1. Build the ArcBox CLI

```bash
cargo build
```

### 2. Download the Kernel

```bash
cd tests/resources
./download-kernel.sh
```

This downloads:
- `vmlinuz-arm64` - Alpine Linux ARM64 kernel
- `initramfs-arm64` - Base Alpine initramfs

### 3. Build the Guest Agent

The agent runs inside the VM and must be cross-compiled for Linux ARM64:

```bash
# Install cross-compilation toolchain (macOS)
brew install FiloSottile/musl-cross/musl-cross

# Add Rust target
rustup target add aarch64-unknown-linux-musl

# Build agent
cargo build -p arcbox-agent --target aarch64-unknown-linux-musl --release
```

### 4. Build the Initramfs

Create an initramfs that includes the arcbox-agent:

```bash
cd tests/resources
./build-initramfs.sh
```

This creates `initramfs-arcbox` with:
- Base Alpine Linux userspace
- arcbox-agent binary
- vsock and virtiofs kernel modules
- Init script that starts the agent

### 5. Prepare the Kernel Image

The test harness expects `Image-arm64` (uncompressed kernel). If you only have `vmlinuz-arm64` (compressed), extract it:

```bash
cd tests/resources

# If vmlinuz is gzip compressed
gunzip -c vmlinuz-arm64 > Image-arm64

# Or if it's already uncompressed, just rename/copy
cp vmlinuz-arm64 Image-arm64
```

### 6. Sign the Binary (macOS)

Virtualization.framework requires entitlements:

```bash
codesign --entitlements tests/resources/entitlements.plist --force -s - target/debug/arcbox
```

## Running E2E Tests

### Run All E2E Tests

```bash
# Run all E2E tests (including ignored tests)
cargo test -p arcbox-e2e -- --ignored

# Run with verbose output
E2E_VERBOSE=1 cargo test -p arcbox-e2e -- --ignored --nocapture
```

### Run Specific Test Files

```bash
# Container lifecycle tests
cargo test -p arcbox-e2e --test container_lifecycle -- --ignored

# VM lifecycle tests
cargo test -p arcbox-e2e --test vm_lifecycle -- --ignored

# Full workflow tests
cargo test -p arcbox-e2e --test full_workflow -- --ignored

# Image operation tests
cargo test -p arcbox-e2e --test image_ops -- --ignored
```

### Run Specific Tests

```bash
# Run a single test
cargo test -p arcbox-e2e --test container_lifecycle test_container_stdout_capture -- --ignored

# Run tests matching a pattern
cargo test -p arcbox-e2e -- --ignored test_container_run

# Run log capture related tests
cargo test -p arcbox-e2e -- --ignored capture
```

## Test Categories

### Container Output Capture Tests

Tests for stdout/stderr log capture functionality:

| Test | Description |
|------|-------------|
| `test_container_stdout_capture` | Verifies stdout is captured to container logs |
| `test_container_stderr_capture` | Verifies stderr is captured to container logs |
| `test_container_stdout_stderr_separation` | Verifies stdout/stderr are logged separately |
| `test_container_multiline_output_capture` | Verifies multi-line output is captured correctly |
| `test_container_run_stdout_passthrough` | Verifies `run` command returns stdout directly |
| `test_container_run_stderr_passthrough` | Verifies `run` command passes through stderr |
| `test_container_run_exit_code_propagation` | Verifies exit codes (0, 1, 42) are preserved |

### Container Lifecycle Tests

| Test | Description |
|------|-------------|
| `test_container_create` | Basic container creation |
| `test_container_create_with_name` | Container creation with custom name |
| `test_container_start_stop` | Container start and stop operations |
| `test_container_restart` | Container restart operation |
| `test_container_remove` | Container removal |
| `test_container_remove_running` | Remove running container (should fail without -f) |
| `test_container_exec` | Execute command in running container |
| `test_container_exec_exit_code` | Exec preserves exit code |
| `test_container_logs` | Retrieve container logs |
| `test_container_logs_tail` | Retrieve last N lines of logs |
| `test_container_run` | Basic `run` command |
| `test_container_run_rm` | Run with --rm flag |
| `test_container_run_detached` | Run in detached mode |

### Full Workflow Tests

| Test | Description |
|------|-------------|
| `test_workflow_simple_run` | Simplest workflow: pull + run + capture output |
| `test_workflow_file_operations` | File I/O inside container |
| `test_workflow_process_isolation` | PID namespace isolation |
| `test_workflow_multiple_containers` | Running multiple containers |
| `test_workflow_environment_variables` | Environment variable passing |
| `test_workflow_working_directory` | Custom working directory |
| `test_workflow_volume_mount` | Volume mount from host |
| `test_workflow_startup_time` | Container startup performance |
| `test_workflow_exec_latency` | Exec command latency |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `E2E_VERBOSE` | Enable verbose logging (daemon output visible) |
| `RUST_LOG` | Set log level (e.g., `debug`, `trace`) |

## Test Infrastructure

### TestHarness

The `TestHarness` struct manages test lifecycle:

```rust
let mut harness = TestHarness::with_defaults()?;

// Setup: starts daemon, creates VM, waits for agent
harness.setup_full_environment().await?;

// Run commands
let output = harness.run_command(&["run", "--rm", "alpine", "echo", "hello"])?;

// Harness cleans up on drop
```

### TestConfig

Configure test parameters:

```rust
let config = TestConfig {
    arcbox_binary: PathBuf::from("target/debug/arcbox"),
    kernel_path: PathBuf::from("tests/resources/Image-arm64"),
    initramfs_path: PathBuf::from("tests/resources/initramfs-arcbox"),
    cpus: 2,
    memory_mb: 1024,
    timeout: Duration::from_secs(60),
    verbose: true,
};
```

### Resource Check

Tests automatically skip if resources are missing:

```rust
fn skip_if_missing_resources() -> bool {
    let fixtures = TestFixtures::new();
    let check = fixtures.check_resources();

    if !check.all_ready() {
        eprintln!("Skipping: {:?}", check.missing());
        return true;
    }
    false
}
```

## Troubleshooting

### Tests Skipped Due to Missing Resources

```
Skipping test: missing resources: ["kernel (run tests/resources/download-kernel.sh)"]
```

**Solution**: Run the setup scripts as described in Prerequisites.

### Entitlement Errors

```
error: Virtualization.framework requires entitlements
```

**Solution**: Sign the binary:
```bash
codesign --entitlements tests/resources/entitlements.plist --force -s - target/debug/arcbox
```

### Agent Connection Timeout

```
timeout waiting for agent
```

**Possible causes**:
- vsock modules not loaded in guest
- Agent crashed on startup
- Initramfs missing agent binary

**Debug**: Run with `E2E_VERBOSE=1` to see guest console output.

### Test Hangs

If tests hang, the VM might not be shutting down properly.

**Solution**: Kill orphan processes:
```bash
pkill -f arcbox
```

## Writing New E2E Tests

1. Add test to appropriate file in `tests/e2e/tests/`
2. Use `#[ignore = "requires VM resources and network"]` attribute
3. Call `skip_if_missing_resources()` at start
4. Use `TestHarness` for setup and command execution

Example:

```rust
#[tokio::test]
#[ignore = "requires VM resources and network"]
async fn test_my_feature() {
    if skip_if_missing_resources() {
        return;
    }

    let mut harness = TestHarness::with_defaults().expect("failed to create harness");
    harness.setup_full_environment().await.expect("failed to setup");

    // Pull image
    harness.run_command_success(&["pull", "alpine:latest"]).expect("failed to pull");

    // Test your feature
    let output = harness.run_command(&[
        "run", "--rm",
        "--machine", harness.machine_name(),
        "alpine:latest",
        "echo", "test",
    ]).expect("failed to run");

    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("test"));
}
```

## File Structure

```
tests/e2e/
├── Cargo.toml              # E2E test crate config
├── README.md               # This file
├── src/
│   ├── lib.rs              # Crate root
│   ├── harness.rs          # TestHarness implementation
│   ├── vm.rs               # VM controller utilities
│   ├── agent.rs            # Agent client utilities
│   ├── fixtures.rs         # Test fixtures and constants
│   └── assertions.rs       # Custom assertions
└── tests/
    ├── vm_lifecycle.rs     # VM lifecycle tests
    ├── image_ops.rs        # Image operation tests
    ├── container_lifecycle.rs  # Container tests (including output capture)
    └── full_workflow.rs    # Full workflow tests

tests/resources/
├── download-kernel.sh      # Download Alpine kernel
├── build-initramfs.sh      # Build initramfs with agent
├── entitlements.plist      # macOS entitlements for VM
├── Image-arm64             # Uncompressed kernel (generated)
├── initramfs-arcbox        # Initramfs with agent (generated)
└── vmlinuz-arm64           # Compressed kernel (downloaded)
```
