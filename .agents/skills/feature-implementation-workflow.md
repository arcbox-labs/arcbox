# Feature Implementation Workflow

## Overview

A comprehensive workflow for implementing new features in the ArcBox codebase, covering:
- Feature implementation with proper error handling
- Test suite creation (unit tests + E2E tests)
- CI/CD pipeline setup
- Documentation and i18n compliance

---

## Skill 1: Implement Auto-Pull Feature (Docker-like UX)

### Problem
When running `docker run` with an image not present locally, Docker automatically pulls it. ArcBox was missing this behavior.

### Solution Pattern

**Location**: `crates/arcbox-core/src/runtime.rs`

```rust
// 1. Add imports
use arcbox_image::{ImageError, ImagePuller, ImageRef, ImageStore, RegistryClient};

// 2. In create_container(), after parsing image reference:
// Check if image exists locally, if not, pull it automatically (Docker-like UX).
if let Err(ImageError::NotFound(_)) = self.image_store.get_image_config(&image_ref) {
    tracing::info!(
        "Image {} not found locally, pulling from registry...",
        config.image
    );
    let client = RegistryClient::new(&image_ref.registry);
    let puller = ImagePuller::new(self.image_store.clone(), client);
    puller.pull(&image_ref).await?;
    tracing::info!("Successfully pulled image {}", config.image);
}

// 3. Continue with normal flow
let image_config = self.image_store.get_image_config(&image_ref)?;
```

### Key Points
- Use `ImageError::NotFound` to detect missing images
- Let `?` operator auto-convert `ImageError` to `CoreError` via `#[from]`
- Log both start and completion of pull operation

---

## Skill 2: Add Test Suite for New Feature

### Unit Tests (arcbox-image)

**Location**: `crates/arcbox-image/src/extract.rs`

```rust
#[test]
fn test_get_image_config_not_found() {
    let dir = tempdir().unwrap();
    let store = ImageStore::new(dir.path().to_path_buf()).unwrap();

    let reference = ImageRef::parse("alpine:latest").unwrap();
    let result = store.get_image_config(&reference);

    // Should return NotFound since the image hasn't been pulled.
    assert!(result.is_err());
    match result.unwrap_err() {
        ImageError::NotFound(_) => { /* Expected */ }
        err => panic!("Expected NotFound error, got: {:?}", err),
    }
}

#[test]
fn test_image_not_found_triggers_auto_pull_condition() {
    // Verify the exact error type that triggers auto-pull in runtime.
    let dir = tempdir().unwrap();
    let store = ImageStore::new(dir.path().to_path_buf()).unwrap();

    let reference = ImageRef::parse("busybox:latest").unwrap();
    let result = store.get_image_config(&reference);

    assert!(
        matches!(result, Err(ImageError::NotFound(_))),
        "Missing image should return ImageError::NotFound to trigger auto-pull"
    );
}
```

### E2E Tests (tests/e2e)

**Location**: `tests/e2e/tests/container_lifecycle.rs`

```rust
/// Test that `run` automatically pulls an image if not present locally.
#[tokio::test]
#[ignore = "requires VM resources and network"]
async fn test_container_run_auto_pull() {
    if skip_if_missing_resources() { return; }

    let mut harness = TestHarness::with_defaults().expect("failed to create harness");
    harness.setup_full_environment().await.expect("failed to setup");

    // Ensure image is NOT present locally
    let _ = harness.run_command(&["rmi", images::BUSYBOX]);

    // Verify image is not present
    let list_before = harness.run_command_success(&["images"]).expect("failed to list");
    assert!(!list_before.contains("busybox"), "Image should not exist before test");

    // Run WITHOUT pre-pulling - should auto-pull
    let output = harness
        .run_command(&["run", "--rm", images::BUSYBOX, "echo", "auto-pull-works"])
        .expect("failed to run");

    assert!(output.status.success(), "Run with auto-pull should succeed");

    // Image should now be present locally
    let list_after = harness.run_command_success(&["images"]).expect("failed to list");
    assert!(list_after.contains("busybox"), "Image should exist after auto-pull");
}
```

### Test Naming Convention
- Unit tests: `test_<component>_<behavior>`
- E2E tests: `test_<action>_<scenario>`

---

## Skill 3: Create GitHub Actions E2E Workflow

### Structure

```yaml
name: E2E Tests

on:
  push:
    branches: [main, develop]
    paths: ['crates/**', 'guest/**', 'tests/e2e/**']
  pull_request:
    branches: [main, develop]
  workflow_dispatch:
    inputs:
      run_vm_tests:
        description: 'Run VM-based E2E tests'
        type: boolean
        default: 'false'

jobs:
  # Job 1: Unit tests (always run, no VM needed)
  unit-tests:
    runs-on: macos-14
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-action@stable
      - run: cargo test --workspace --exclude arcbox-e2e

  # Job 2: Build artifacts
  build:
    runs-on: macos-14
    steps:
      - name: Build arcbox
        run: cargo build --release -p arcbox-cli
      - name: Cross-compile agent
        run: cargo build --release -p arcbox-agent --target aarch64-unknown-linux-musl
      - name: Sign binary
        run: codesign --entitlements bundle/arcbox.entitlements --force -s - target/release/abctl
      - name: Upload artifacts
        uses: actions/upload-artifact@v4

  # Job 3: E2E tests (conditional, needs VM)
  e2e-vm-tests:
    needs: build
    runs-on: macos-14
    if: github.ref == 'refs/heads/main' || github.event.inputs.run_vm_tests == 'true'
    continue-on-error: true  # VM may not be available on GitHub runners
    steps:
      - run: cargo test -p arcbox-e2e -- --ignored --nocapture

  # Job 4: Self-hosted runner (full VM support)
  e2e-self-hosted:
    needs: build
    runs-on: [self-hosted, macOS, ARM64, virtualization]
    continue-on-error: true  # Skip if no self-hosted runner
```

### Key Patterns
- **Layered testing**: Unit tests always run, E2E tests conditional
- **Artifact sharing**: Build once, test in multiple jobs
- **Graceful degradation**: `continue-on-error: true` for VM tests on public runners
- **Self-hosted support**: Separate job for full VM testing

---

## Skill 4: E2E TLS EOF Debugging Playbook (Darwin Socket Proxy)

### Scope
Use this workflow when E2E traffic reaches remote services but TLS handshakes fail with EOF or protocol errors.

### Step 1: Reproduce with deterministic logs

```bash
# Start daemon with debug logging
RUST_LOG=debug ./target/debug/abctl daemon start --foreground

# Optional: include byte-level ingress->host write verification
RUST_LOG=debug ARCBOX_TCP_BYTE_TRACE=1 ./target/debug/abctl daemon start --foreground
```

Run the failing E2E workload in another terminal (for example image pulls or repeated HTTPS requests).

### Step 2: Triage by log signatures

If traffic is flowing but TLS still fails, classify quickly:

- `TCP data channel full` appears frequently: sender backpressure path is active
- `TCP relay write error` appears: host socket write path failed
- no retransmit/backpressure/write errors, but TLS still EOF: investigate byte-stream integrity and TCP sequencing semantics

### Step 3: Verify byte-stream integrity first

Enable `ARCBOX_TCP_BYTE_TRACE=1` and inspect:

- `TCP byte trace mismatch`: first segment-level divergence between guest ingress payload and host `write_all`
- `TCP byte trace final mismatch`: connection-level byte/hash mismatch at close
- `TCP byte trace matched`: proxy preserved guest->host byte stream for that flow

Interpretation:

- any `mismatch` means corruption/drop/duplication happened inside proxy path
- only `matched` but still TLS EOF means root cause is likely outside guest->host payload mutation (for example remote behavior, proxy chain interaction, or other protocol semantics)

### Step 4: Check known high-impact failure classes

1. Payload extraction boundary:
   - Always slice TCP payload by IPv4 `total_length`, never by raw frame length (to avoid Ethernet padding leakage).
2. Connection state transitions:
   - Third handshake ACK carrying payload must be forwarded (do not drop piggybacked data in `SynReceived`).
   - `FIN+payload` must forward payload before close signal.
3. ACK/SEQ correctness:
   - Out-of-order/retransmit handling must preserve `expected_seq` semantics.
   - Inbound relay host->guest data frames must not use fixed `ack=0`; ACK should track guest sequence progress.

### Step 5: Run focused regression tests before full E2E rerun

```bash
cargo test -p arcbox-net test_tcp_ack_padding_is_not_forwarded_as_payload -- --nocapture
cargo test -p arcbox-net inbound_ack_padding_is_not_forwarded_as_payload -- --nocapture
cargo test -p arcbox-net test_syn_received_ack_with_payload_is_forwarded -- --nocapture
cargo test -p arcbox-net test_fin_with_payload_is_forwarded_before_close -- --nocapture
cargo check -p arcbox-net
```

### Step 6: E2E rerun protocol

1. Run failing E2E scenario without byte trace and confirm failure signature is stable.
2. Re-run with `ARCBOX_TCP_BYTE_TRACE=1`.
3. Capture first `TCP byte trace mismatch` (or confirm all `matched`).
4. Fix only the first proven divergence point.
5. Re-run focused tests, then full E2E.

### Guardrails

- Do not start with broad refactors for EOF-only incidents.
- Prioritize minimal fixes that restore byte-stream correctness.
- Keep UDP/DNS/ICMP unchanged unless logs prove they are involved.

---

## Skill 5: Translate Chinese to English in Codebase

### Detection Method

```bash
# Find files with actual CJK characters (not box-drawing)
python3 -c "
import os, re
pattern = re.compile(r'[\u4e00-\u9fff]')
for root, dirs, files in os.walk('.'):
    dirs[:] = [d for d in dirs if d not in ['target', '.git']]
    for f in files:
        if f.endswith(('.rs', '.md')):
            path = os.path.join(root, f)
            with open(path, 'r') as fp:
                for i, line in enumerate(fp, 1):
                    if pattern.search(line):
                        print(f'{path}:{i}: {line.rstrip()[:60]}')
"
```

### Classification
| Type | Action |
|------|--------|
| Comments/Docs | Translate to English |
| Test data (Unicode testing) | Keep as-is |
| Box-drawing chars (ASCII art) | Keep as-is |

### Test Data Examples (Keep)
```rust
// These test Unicode handling, keep Chinese:
let utf8 = "你好世界";  // Tests UTF-8 processing
let err = ErrorResponse::new(400, "错误: 无效的请求");  // Tests Unicode in errors
```

---

## Prompt Iteration History

### User Prompts (Evolution)

1. **Initial**: "为什么不在镜像本地没有拉取的时候直接自动拉取呢？"
   - Identified the missing Docker-like UX feature

2. **Implementation**: "请你添加"
   - Direct instruction to implement

3. **Testing**: "添加测试套件"
   - Requested comprehensive test coverage

4. **CI/CD**: "请你尝试为 E2E 构建 GitHub Actions"
   - Extended to CI/CD automation

5. **Quality**: "请你确保所有 docs 和 comment 均为英文"
   - Code quality and i18n compliance

6. **Scope expansion**: "请你查看整个项目"
   - Full codebase audit

7. **Documentation**: "把对话学到的东西整理一下...存成一个Skill"
   - Knowledge preservation

### Key Learnings

1. **Incremental development**: Start with core feature, add tests, then CI/CD
2. **Parallel processing**: Use Task tool for batch operations (file translations)
3. **Verification**: Always verify changes with compilation and grep
4. **Classification**: Distinguish between code to change vs. intentional test data

---

## Quick Reference Commands

```bash
# Run unit tests for a crate
cargo test -p arcbox-image -- test_name

# Run E2E tests (requires VM)
cargo test -p arcbox-e2e -- --ignored --nocapture

# Start daemon with debug logging
RUST_LOG=debug ./target/debug/abctl daemon start --foreground

# Start daemon with TCP byte-stream verification
RUST_LOG=debug ARCBOX_TCP_BYTE_TRACE=1 ./target/debug/abctl daemon start --foreground

# Focused TCP/TLS regression tests
cargo test -p arcbox-net test_tcp_ack_padding_is_not_forwarded_as_payload -- --nocapture
cargo test -p arcbox-net inbound_ack_padding_is_not_forwarded_as_payload -- --nocapture
cargo test -p arcbox-net test_syn_received_ack_with_payload_is_forwarded -- --nocapture
cargo test -p arcbox-net test_fin_with_payload_is_forwarded_before_close -- --nocapture
cargo check -p arcbox-net

# Find Chinese characters in codebase
grep -rn '[\u4e00-\u9fff]' --include="*.rs" .

# Check for compilation errors
cargo check -p arcbox-core

# Sign macOS binary for VM testing
codesign --entitlements bundle/arcbox.entitlements --force -s - <binary>
```

---

## Files Modified in This Session

| File | Change |
|------|--------|
| `crates/arcbox-core/src/runtime.rs` | Added auto-pull logic |
| `crates/arcbox-image/src/extract.rs` | Added unit tests |
| `tests/e2e/tests/container_lifecycle.rs` | Added E2E tests |
| `.github/workflows/e2e-tests.yml` | New CI workflow |
| `docs/boot-assets.md` | Translated to English |
| `CLAUDE.md` | Translated to English |
