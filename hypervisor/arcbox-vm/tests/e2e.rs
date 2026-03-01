//! End-to-end tests for the full sandbox lifecycle.
//!
//! ## Prerequisites
//!
//! All tests are `#[ignore]` and require three environment variables:
//!
//! | Variable    | Description                                       |
//! |-------------|---------------------------------------------------|
//! | `FC_BINARY` | Path to the `firecracker` binary                  |
//! | `FC_KERNEL` | Path to the kernel image (`vmlinux`)              |
//! | `FC_ROOTFS` | Path to the root filesystem image (`*.ext4`)      |
//!
//! `FC_ROOTFS` must have the `vm-agent` binary at `/sbin/vm-agent`; the
//! default `boot_args` use `init=/sbin/vm-agent` so the agent runs as PID 1.
//!
//! ## Running
//!
//! ```bash
//! sudo -E cargo test --test e2e -p arcbox-vm -- --include-ignored --test-threads=1
//! ```
//!
//! `--test-threads=1` prevents concurrent TAP interface names from colliding.
//!
//! ## KVM
//!
//! All tests require `/dev/kvm`.  On GitHub Actions (ubuntu-22.04):
//! ```bash
//! sudo chmod 666 /dev/kvm
//! ```

mod common;

use std::collections::HashMap;
use std::time::Duration;

use arcbox_vm::{
    DefaultVmConfig, FirecrackerConfig, GrpcConfig, NetworkConfig, SandboxEvent, SandboxManager,
    SandboxNetworkSpec, SandboxSpec, SandboxState, VmmConfig,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a VmmConfig from env vars. Returns `None` to skip the test.
fn try_config(data_dir: &str) -> Option<VmmConfig> {
    let binary = std::env::var("FC_BINARY").ok()?;
    let kernel = std::env::var("FC_KERNEL").ok()?;
    let rootfs = std::env::var("FC_ROOTFS").ok()?;
    Some(VmmConfig {
        firecracker: FirecrackerConfig {
            binary,
            jailer: None,
            data_dir: data_dir.to_owned(),
            log_level: Some("Error".into()),
            no_seccomp: true,
            seccomp_filter: None,
            http_api_max_payload_size: None,
            mmds_size_limit: None,
            socket_timeout_secs: Some(15),
        },
        network: NetworkConfig {
            bridge: String::new(),
            cidr: "172.99.0.0/24".into(),
            gateway: "172.99.0.1".into(),
            dns: vec![],
        },
        grpc: GrpcConfig {
            unix_socket: "/dev/null".into(),
            tcp_addr: String::new(),
        },
        defaults: DefaultVmConfig {
            vcpus: 1,
            memory_mib: 256,
            kernel,
            rootfs,
            boot_args: "console=ttyS0 reboot=k panic=1 pci=off init=/sbin/vm-agent".into(),
        },
    })
}

/// Return a SandboxSpec with networking disabled (no TAP, no root required).
fn no_tap() -> SandboxSpec {
    SandboxSpec {
        network: SandboxNetworkSpec { mode: "none".into() },
        ..Default::default()
    }
}

/// Drain the broadcast channel until the specified `action` arrives for `id`,
/// or until a `"failed"` event for `id` is received, or a 30-second timeout
/// expires.  Returns `true` on success.
async fn wait_for_event(
    rx: &mut tokio::sync::broadcast::Receiver<SandboxEvent>,
    id: &str,
    action: &str,
) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Ok(ev)) if ev.sandbox_id == id => {
                if ev.action == action {
                    return true;
                }
                if ev.action == "failed" {
                    eprintln!("sandbox {id} failed: {:?}", ev.attributes);
                    return false;
                }
            }
            // Event for a different sandbox — keep waiting.
            Ok(Ok(_)) => {}
            // Receiver fell behind; messages were dropped but the channel is
            // still open.  Continue draining.
            Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => {}
            // Channel closed or 30-second timeout.
            _ => return false,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Create a sandbox, wait for it to become ready, stop it, then remove it.
/// Uses network mode `"none"` so no TAP interface is required.
#[tokio::test]
#[ignore]
async fn e2e_sandbox_basic_lifecycle() {
    let dir = tempfile::tempdir().unwrap();
    let Some(cfg) = try_config(dir.path().to_str().unwrap()) else {
        eprintln!("SKIP e2e_sandbox_basic_lifecycle — FC_BINARY/FC_KERNEL/FC_ROOTFS not set");
        return;
    };

    let mgr = SandboxManager::new(cfg).unwrap();
    let mut events = mgr.subscribe_events();

    let (id, _ip) = mgr.create_sandbox(no_tap()).await.unwrap();
    assert!(
        wait_for_event(&mut events, &id, "ready").await,
        "sandbox did not reach ready state"
    );

    let info = mgr.inspect_sandbox(&id).unwrap();
    assert_eq!(info.state, SandboxState::Ready);

    mgr.stop_sandbox(&id, 5).await.unwrap();
    let info = mgr.inspect_sandbox(&id).unwrap();
    assert_eq!(info.state, SandboxState::Stopped);

    mgr.remove_sandbox(&id, true).await.unwrap();
    assert!(
        mgr.inspect_sandbox(&id).is_err(),
        "sandbox should be gone after remove"
    );
}

/// Subscribe to events, create a sandbox, and verify the `"ready"` event
/// arrives on the broadcast channel.
#[tokio::test]
#[ignore]
async fn e2e_event_broadcast_ready() {
    let dir = tempfile::tempdir().unwrap();
    let Some(cfg) = try_config(dir.path().to_str().unwrap()) else {
        eprintln!("SKIP e2e_event_broadcast_ready — FC_BINARY/FC_KERNEL/FC_ROOTFS not set");
        return;
    };

    let mgr = SandboxManager::new(cfg).unwrap();
    let mut events = mgr.subscribe_events();

    let (id, _) = mgr.create_sandbox(no_tap()).await.unwrap();
    assert!(
        wait_for_event(&mut events, &id, "ready").await,
        "expected ready event for sandbox {id}"
    );

    mgr.remove_sandbox(&id, true).await.unwrap();
}

/// Create two sandboxes with TAP networking and verify they receive distinct
/// IP addresses.  Requires root for TAP interface creation.
#[tokio::test]
#[ignore]
async fn e2e_two_sandboxes_distinct_ips() {
    #[cfg(target_os = "linux")]
    if !common::is_root() {
        eprintln!("SKIP e2e_two_sandboxes_distinct_ips — requires root");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let Some(cfg) = try_config(dir.path().to_str().unwrap()) else {
        eprintln!("SKIP e2e_two_sandboxes_distinct_ips — FC_BINARY/FC_KERNEL/FC_ROOTFS not set");
        return;
    };

    let mgr = SandboxManager::new(cfg).unwrap();

    // Subscribe twice so that waiting for id1 does not consume id2's events.
    let mut ev1 = mgr.subscribe_events();
    let mut ev2 = mgr.subscribe_events();

    let (id1, ip1) = mgr.create_sandbox(Default::default()).await.unwrap();
    let (id2, ip2) = mgr.create_sandbox(Default::default()).await.unwrap();

    assert_ne!(ip1, ip2, "sandboxes must receive distinct IP addresses");

    assert!(
        wait_for_event(&mut ev1, &id1, "ready").await,
        "sandbox 1 did not reach ready"
    );
    assert!(
        wait_for_event(&mut ev2, &id2, "ready").await,
        "sandbox 2 did not reach ready"
    );

    mgr.remove_sandbox(&id1, true).await.unwrap();
    mgr.remove_sandbox(&id2, true).await.unwrap();
}

/// Create a sandbox with TAP networking, verify the TAP interface exists while
/// it is running, then verify it is removed after `remove_sandbox`.
/// Requires root.
#[tokio::test]
#[ignore]
async fn e2e_sandbox_with_tap_network() {
    #[cfg(target_os = "linux")]
    if !common::is_root() {
        eprintln!("SKIP e2e_sandbox_with_tap_network — requires root");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let Some(cfg) = try_config(dir.path().to_str().unwrap()) else {
        eprintln!("SKIP e2e_sandbox_with_tap_network — FC_BINARY/FC_KERNEL/FC_ROOTFS not set");
        return;
    };

    let mgr = SandboxManager::new(cfg).unwrap();
    let mut events = mgr.subscribe_events();

    let (id, ip) = mgr.create_sandbox(Default::default()).await.unwrap();
    assert!(!ip.is_empty(), "tap mode should assign an IP address");
    assert!(
        wait_for_event(&mut events, &id, "ready").await,
        "sandbox did not reach ready"
    );

    #[cfg(target_os = "linux")]
    let tap_name = {
        let info = mgr.inspect_sandbox(&id).unwrap();
        let net = info.network.expect("tap mode should populate network info");
        assert!(
            common::iface_exists(&net.tap_name),
            "TAP {} should exist while sandbox is running",
            net.tap_name
        );
        net.tap_name
    };

    mgr.remove_sandbox(&id, true).await.unwrap();

    #[cfg(target_os = "linux")]
    assert!(
        !common::iface_exists(&tap_name),
        "TAP {tap_name} should be removed after sandbox is removed"
    );
}

/// Boot a sandbox, run `echo hello` inside it via the vsock guest agent, and
/// verify the output and exit code.
///
/// Requires the rootfs to have `vm-agent` at `/sbin/vm-agent`.
#[tokio::test]
#[ignore]
async fn e2e_run_command() {
    let dir = tempfile::tempdir().unwrap();
    let Some(cfg) = try_config(dir.path().to_str().unwrap()) else {
        eprintln!("SKIP e2e_run_command — FC_BINARY/FC_KERNEL/FC_ROOTFS not set");
        return;
    };

    let mgr = SandboxManager::new(cfg).unwrap();
    let mut events = mgr.subscribe_events();

    let (id, _) = mgr.create_sandbox(no_tap()).await.unwrap();
    assert!(
        wait_for_event(&mut events, &id, "ready").await,
        "sandbox did not reach ready"
    );

    let mut rx = mgr
        .run_in_sandbox(
            &id,
            vec!["echo".into(), "hello from vm".into()],
            HashMap::new(),
            "/".into(),
            "root".into(),
            false,
            None,
            10,
        )
        .await
        .unwrap();

    let mut stdout = String::new();
    let mut exit_code: i32 = -1;
    while let Some(result) = rx.recv().await {
        let chunk = result.unwrap();
        match chunk.stream.as_str() {
            "stdout" => stdout.push_str(&String::from_utf8_lossy(&chunk.data)),
            "exit" => exit_code = chunk.exit_code,
            _ => {}
        }
    }

    assert!(
        stdout.contains("hello from vm"),
        "expected 'hello from vm' in stdout, got: {stdout:?}"
    );
    assert_eq!(exit_code, 0, "echo should exit with code 0");

    mgr.remove_sandbox(&id, true).await.unwrap();
}
