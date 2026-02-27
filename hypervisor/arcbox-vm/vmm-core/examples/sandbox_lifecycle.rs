//! Demonstrates direct `SandboxManager` usage without the gRPC layer.
//!
//! Covers: create → wait-ready → inspect → checkpoint → restore → remove.
//!
//! Prerequisites:
//!   - `firecracker` binary in PATH (or configured in `VmmConfig`)
//!   - kernel image and rootfs image configured in `VmmConfig::default()`
//!   - `CAP_NET_ADMIN` for TAP interface creation
//!
//! Run:
//!   cargo run --example sandbox_lifecycle

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use vmm_core::{
    SandboxManager, SandboxSpec, SandboxState, VmmConfig,
    sandbox::RestoreSandboxSpec,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("vmm_core=debug,info")
        .init();

    let config = VmmConfig::default();
    let manager = Arc::new(SandboxManager::new(config)?);

    // ── 1. Create ────────────────────────────────────────────────────────────
    println!("\n=== Create sandbox ===");
    let spec = SandboxSpec {
        vcpus: 1,
        memory_mib: 512,
        ..Default::default()
    };
    let (id, ip) = manager.create_sandbox(spec).await?;
    println!("ID: {id}  IP: {ip}");

    // ── 2. Wait for ready ────────────────────────────────────────────────────
    println!("\n=== Waiting for ready ===");
    let mut attempts = 0u32;
    loop {
        let info = manager.inspect_sandbox(&id)?;
        println!("  state = {}", info.state);
        if info.state == SandboxState::Ready {
            break;
        }
        if info.state == SandboxState::Failed {
            let err = info.error.unwrap_or_default();
            anyhow::bail!("sandbox failed to boot: {err}");
        }
        attempts += 1;
        if attempts > 60 {
            anyhow::bail!("timed out waiting for ready");
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // ── 3. Inspect ───────────────────────────────────────────────────────────
    println!("\n=== Inspect ===");
    let info = manager.inspect_sandbox(&id)?;
    println!("  ID:      {}", info.id);
    println!("  State:   {}", info.state);
    println!("  vCPUs:   {}", info.vcpus);
    println!("  Memory:  {} MiB", info.memory_mib);
    if let Some(net) = &info.network {
        println!("  IP:      {}", net.ip_address);
        println!("  Gateway: {}", net.gateway);
        println!("  TAP:     {}", net.tap_name);
    }

    // ── 4. List ───────────────────────────────────────────────────────────────
    println!("\n=== List ===");
    let sandboxes = manager.list_sandboxes(None, &HashMap::new());
    for s in &sandboxes {
        println!("  {} | {} | {}", s.id, s.state, s.ip_address);
    }

    // ── 5. Checkpoint ────────────────────────────────────────────────────────
    println!("\n=== Checkpoint ===");
    let snap = manager
        .checkpoint_sandbox(&id, "example-snapshot".to_string())
        .await?;
    println!("  Snapshot ID: {}", snap.snapshot_id);
    println!("  Directory:   {}", snap.snapshot_dir);

    // ── 6. Remove original ───────────────────────────────────────────────────
    println!("\n=== Remove original sandbox ===");
    manager.remove_sandbox(&id, true).await?;
    println!("  Removed: {id}");

    // ── 7. Restore ───────────────────────────────────────────────────────────
    println!("\n=== Restore from snapshot ===");
    let restore_spec = RestoreSandboxSpec {
        snapshot_id: snap.snapshot_id.clone(),
        network_override: true,
        ttl_seconds: 0,
        ..Default::default()
    };
    let (restored_id, restored_ip) = manager.restore_sandbox(restore_spec).await?;
    println!("  Restored sandbox: {restored_id}  IP: {restored_ip}");

    // ── 8. Cleanup ───────────────────────────────────────────────────────────
    println!("\n=== Cleanup ===");
    manager.remove_sandbox(&restored_id, true).await?;
    println!("  Removed restored sandbox.");

    println!("\nDone.");
    Ok(())
}
