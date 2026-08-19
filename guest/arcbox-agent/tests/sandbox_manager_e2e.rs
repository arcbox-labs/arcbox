//! End-to-end tests for the full sandbox lifecycle, over the environment
//! this crate composes for the System VM.
//!
//! The manager is built through [`arcbox_agent::sandbox::node_environment`],
//! the same function `SandboxService::new` uses, so what boots here is the
//! production composition — a real Firecracker driver, a real TAP network,
//! the vm-proto agent client and a real copy-on-write rootfs manager.
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
//! sudo -E cargo test --test sandbox_manager_e2e -p arcbox-agent -- --include-ignored --test-threads=1
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

// The composition root this suite drives is Linux-only, as is everything
// it boots.
#![cfg(target_os = "linux")]

mod common;

use std::collections::HashMap;
use std::time::Duration;

use arcbox_agent::config::{AdapterConfig, GuestConfig};
use arcbox_agent::sandbox::{block_tools, node_environment};
use arcbox_computer_runtime::{
    ComputerNetworkSpec, ComputerSpec, DefaultVmConfig, FirecrackerConfig, GrpcConfig,
    NetworkConfig, RuntimeConfig, SandboxEvent, SandboxManager, SandboxState,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a GuestConfig from env vars. Returns `None` to skip the test.
fn try_config(data_dir: &str) -> Option<GuestConfig> {
    let binary = std::env::var("FC_BINARY").ok()?;
    let kernel = std::env::var("FC_KERNEL").ok()?;
    let rootfs = std::env::var("FC_ROOTFS").ok()?;
    let runtime = RuntimeConfig {
        firecracker: FirecrackerConfig {
            jailer: None,
            data_dir: data_dir.to_owned(),
            // Direct mode cannot restore (and so never pools); keep the
            // e2e run free of background pre-warm spawns regardless.
            pool_size: 0,
            // Direct mode is warm-ineligible anyway; keep it explicit.
            warm_create: false,
            // The stock-distro search list, i.e. the library's own default.
            dmsetup_candidates: None,
        },
        network: NetworkConfig {
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
    };
    Some(GuestConfig {
        runtime,
        adapters: AdapterConfig {
            binary,
            jailer: None,
            log_level: Some("Error".into()),
            no_seccomp: true,
            seccomp_filter: None,
            http_api_max_payload_size: None,
            mmds_size_limit: None,
            socket_timeout_secs: Some(15),
            sandbox_datapath: arcbox_tap_net::Datapath::default(),
        },
    })
}

/// Return a ComputerSpec with networking disabled (no TAP, no root required).
fn no_tap() -> ComputerSpec {
    ComputerSpec {
        network: ComputerNetworkSpec {
            mode: "none".into(),
        },
        ..Default::default()
    }
}

/// A manager over the environment `SandboxService::new` composes: this
/// suite exercises the real composition rather than one of its own.
fn manager(cfg: GuestConfig) -> SandboxManager {
    let environment = node_environment(&cfg, block_tools()).unwrap();
    SandboxManager::new(cfg.runtime, environment).unwrap()
}

/// Complete the startup cleanup handshake for a manager backed by a fresh
/// test directory, where no stale host resources exist.
async fn finalize_startup_cleanup(mgr: &SandboxManager) {
    let token = mgr
        .startup_cleanup_token()
        .await
        .unwrap()
        .expect("a new sandbox manager should require startup cleanup");
    mgr.finalize_startup_cleanup(&token).await.unwrap();
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
#[ignore = "requires FC_BINARY/FC_KERNEL/FC_ROOTFS environment variables"]
async fn e2e_sandbox_basic_lifecycle() {
    let dir = tempfile::tempdir().unwrap();
    let Some(cfg) = try_config(dir.path().to_str().unwrap()) else {
        eprintln!("SKIP e2e_sandbox_basic_lifecycle — FC_BINARY/FC_KERNEL/FC_ROOTFS not set");
        return;
    };

    let mgr = manager(cfg);
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
#[ignore = "requires FC_BINARY/FC_KERNEL/FC_ROOTFS environment variables"]
async fn e2e_event_broadcast_ready() {
    let dir = tempfile::tempdir().unwrap();
    let Some(cfg) = try_config(dir.path().to_str().unwrap()) else {
        eprintln!("SKIP e2e_event_broadcast_ready — FC_BINARY/FC_KERNEL/FC_ROOTFS not set");
        return;
    };

    let mgr = manager(cfg);
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
#[ignore = "requires FC_BINARY/FC_KERNEL/FC_ROOTFS environment variables and root"]
async fn e2e_two_sandboxes_distinct_ips() {
    if !common::is_root() {
        eprintln!("SKIP e2e_two_sandboxes_distinct_ips — requires root");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let Some(cfg) = try_config(dir.path().to_str().unwrap()) else {
        eprintln!("SKIP e2e_two_sandboxes_distinct_ips — FC_BINARY/FC_KERNEL/FC_ROOTFS not set");
        return;
    };

    let mgr = manager(cfg);
    finalize_startup_cleanup(&mgr).await;

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
#[ignore = "requires FC_BINARY/FC_KERNEL/FC_ROOTFS environment variables and root"]
async fn e2e_sandbox_with_tap_network() {
    if !common::is_root() {
        eprintln!("SKIP e2e_sandbox_with_tap_network — requires root");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let Some(cfg) = try_config(dir.path().to_str().unwrap()) else {
        eprintln!("SKIP e2e_sandbox_with_tap_network — FC_BINARY/FC_KERNEL/FC_ROOTFS not set");
        return;
    };

    let mgr = manager(cfg);
    finalize_startup_cleanup(&mgr).await;
    let mut events = mgr.subscribe_events();

    let (id, ip) = mgr.create_sandbox(Default::default()).await.unwrap();
    assert!(!ip.is_empty(), "tap mode should assign an IP address");
    assert!(
        wait_for_event(&mut events, &id, "ready").await,
        "sandbox did not reach ready"
    );

    let tap_name = {
        let info = mgr.inspect_sandbox(&id).unwrap();
        let net = info.network.expect("tap mode should populate network info");
        // The host interface is deliberately not part of the sandbox API
        // (CORE-54); this test owns the host, so it derives the name the
        // TAP network gives a pool address.
        let octets = net
            .ip_address
            .parse::<std::net::Ipv4Addr>()
            .expect("a pool address")
            .octets();
        let tap_name = format!("vmtap{}-{}", octets[2], octets[3]);
        assert!(
            common::iface_exists(&tap_name),
            "TAP {tap_name} should exist while sandbox is running"
        );
        tap_name
    };

    mgr.remove_sandbox(&id, true).await.unwrap();

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
#[ignore = "requires FC_BINARY/FC_KERNEL/FC_ROOTFS environment variables and vm-agent in rootfs"]
async fn e2e_run_command() {
    let dir = tempfile::tempdir().unwrap();
    let Some(cfg) = try_config(dir.path().to_str().unwrap()) else {
        eprintln!("SKIP e2e_run_command — FC_BINARY/FC_KERNEL/FC_ROOTFS not set");
        return;
    };

    let mgr = manager(cfg);
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
        match chunk {
            arcbox_computer_runtime::OutputChunk::Stdout(data) => {
                stdout.push_str(&String::from_utf8_lossy(&data));
            }
            arcbox_computer_runtime::OutputChunk::Exit(status) => {
                exit_code = status.conventional_code();
            }
            arcbox_computer_runtime::OutputChunk::Stderr(_) => {}
        }
    }

    assert!(
        stdout.contains("hello from vm"),
        "expected 'hello from vm' in stdout, got: {stdout:?}"
    );
    assert_eq!(exit_code, 0, "echo should exit with code 0");

    mgr.remove_sandbox(&id, true).await.unwrap();
}

/// The VMM pid the sandbox's crash journal names, so the test can prove a
/// process outlived its manager — and, later, that Remove reaped it.
fn journaled_pid(data_dir: &std::path::Path, id: &str) -> i32 {
    let journal = data_dir.join("sandboxes").join(id).join("state.json");
    let bytes = std::fs::read(&journal)
        .unwrap_or_else(|error| panic!("read {}: {error}", journal.display()));
    serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["pid"]
        .as_i64()
        .expect("a journaled vmm pid") as i32
}

/// Whether `pid` is still a live Firecracker, rather than a pid the kernel
/// handed to something else since — or a zombie.
///
/// Both managers in this test run in one process, so nothing `waitpid()`s a
/// VMM that Remove killed and it lingers unreaped, still named
/// "firecracker". The state letter is what says it is gone, exactly as the
/// driver's own liveness probe reads it.
fn firecracker_alive(pid: i32) -> bool {
    // `/proc/<pid>/stat` is "<pid> (<comm>) <state> ...", and comm may itself
    // contain spaces or parens — split at the LAST ')'.
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return false;
    };
    let Some((named, rest)) = stat.rsplit_once(')') else {
        return false;
    };
    let is_firecracker = named
        .split_once('(')
        .is_some_and(|(_, comm)| comm.starts_with("firecracker"));
    let is_live = rest
        .split_whitespace()
        .next()
        .is_some_and(|state| state != "Z" && state != "X");
    is_firecracker && is_live
}

/// CORE-135's acceptance test: a sandbox survives the process that booted
/// it. Boot one, hand its VM over the way a graceful shutdown does, drop the
/// manager, and build a fresh one over the same data directory — the sandbox
/// is still running, its host-side datapath is still in place, an exec still
/// works through it, and removing it still leaves no Firecracker behind.
///
/// Requires root: the reclaimed resource this proves is a real TAP interface,
/// and only a real one proves adoption.
///
/// The reclaimed *dm-snapshot* is not covered here. `CowManager` reaches
/// losetup through `BusyboxBlockTools`, which needs `/bin/busybox`; this
/// suite's runner does not install it (the `integration` job does), so the
/// boot falls back to using the rootfs directly and `CowManager::adopt` is
/// never called. Installing busybox in this job would extend the test to
/// that half — and would put every other test in this file on dm-snapshot
/// too, which is why it is a change of its own rather than a line here.
#[tokio::test]
#[ignore = "requires FC_BINARY/FC_KERNEL/FC_ROOTFS environment variables, root, and vm-agent in rootfs"]
async fn e2e_sandbox_outlives_its_manager_and_is_adopted() {
    if !common::is_root() {
        eprintln!("SKIP e2e_sandbox_outlives_its_manager_and_is_adopted — requires root");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().to_owned();
    let Some(cfg) = try_config(data_dir.to_str().unwrap()) else {
        eprintln!(
            "SKIP e2e_sandbox_outlives_its_manager_and_is_adopted — FC_BINARY/FC_KERNEL/FC_ROOTFS not set"
        );
        return;
    };

    let (id, ip) = {
        let mgr = manager(cfg);
        finalize_startup_cleanup(&mgr).await;
        let mut events = mgr.subscribe_events();
        let (id, ip) = mgr.create_sandbox(ComputerSpec::default()).await.unwrap();
        assert!(
            wait_for_event(&mut events, &id, "ready").await,
            "sandbox did not reach ready"
        );
        // What a graceful shutdown owes the next process: without this the
        // manager's handles kill their VMs as they unwind, and there is
        // nothing left to adopt.
        mgr.detach_all().await.unwrap();
        (id, ip)
    };

    let pid = journaled_pid(&data_dir, &id);
    let tap_name = {
        let octets = ip
            .parse::<std::net::Ipv4Addr>()
            .expect("tap mode assigns a pool address")
            .octets();
        format!("vmtap{}-{}", octets[2], octets[3])
    };
    assert!(
        firecracker_alive(pid),
        "the vmm outlives the manager that booted it"
    );

    // The next process: same data directory, nothing else carried over.
    let cfg = try_config(data_dir.to_str().unwrap()).unwrap();
    let mgr = manager(cfg);
    // Awaits the startup sweep, which is where adoption happens.
    if let Some(token) = mgr.startup_cleanup_token().await.unwrap() {
        mgr.finalize_startup_cleanup(&token).await.unwrap();
    }

    let info = mgr.inspect_sandbox(&id).unwrap();
    assert_eq!(
        info.state,
        SandboxState::Ready,
        "the sandbox is usable again, not failed"
    );
    assert_eq!(
        info.network.as_ref().map(|net| net.ip_address.clone()),
        Some(ip),
        "it kept the address its guest is configured with"
    );
    assert!(
        common::iface_exists(&tap_name),
        "TAP {tap_name} survived the restart rather than being swept"
    );
    assert!(firecracker_alive(pid), "the guest was never restarted");

    // An exec proves the vsock path was re-established, not just that the
    // process is alive: this agent was built from the adopted handle.
    let mut rx = mgr
        .run_in_sandbox(
            &id,
            vec!["echo".into(), "still here".into()],
            HashMap::new(),
            "/".into(),
            "root".into(),
            false,
            None,
            30,
        )
        .await
        .unwrap();
    let mut stdout = String::new();
    let mut exit_code: i32 = -1;
    while let Some(result) = rx.recv().await {
        match result.unwrap() {
            arcbox_computer_runtime::OutputChunk::Stdout(data) => {
                stdout.push_str(&String::from_utf8_lossy(&data));
            }
            arcbox_computer_runtime::OutputChunk::Exit(status) => {
                exit_code = status.conventional_code();
            }
            arcbox_computer_runtime::OutputChunk::Stderr(_) => {}
        }
    }
    assert!(
        stdout.contains("still here"),
        "expected 'still here' in stdout, got: {stdout:?}"
    );
    assert_eq!(exit_code, 0);

    // And the adopted sandbox is still removable — through the handle, since
    // no PreparedVm crosses a restart.
    mgr.remove_sandbox(&id, true).await.unwrap();
    assert!(mgr.inspect_sandbox(&id).is_err());
    {
        assert!(!firecracker_alive(pid), "remove left a firecracker behind");
        assert!(
            !common::iface_exists(&tap_name),
            "TAP {tap_name} survived the removal"
        );
    }
}
