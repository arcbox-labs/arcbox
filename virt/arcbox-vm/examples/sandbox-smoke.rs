//! End-to-end smoke test for [`SandboxManager`].
//!
//! ## Usage
//!
//! ```bash
//! # Phase 1 + N only (core lifecycle + network — no guest agent required):
//! ARCBOX_CONFIG=/etc/arcbox-vm/config.toml \
//!   cargo run -p arcbox-vm --example sandbox-smoke
//!
//! # Also run commands + guest-side network checks (Phase 2):
//! ARCBOX_SMOKE_RUN=1 ARCBOX_CONFIG=... \
//!   cargo run -p arcbox-vm --example sandbox-smoke
//!
//! # Also checkpoint + restore (Phase 3):
//! ARCBOX_SMOKE_CHECKPOINT=1 ARCBOX_CONFIG=... \
//!   cargo run -p arcbox-vm --example sandbox-smoke
//! ```
//!
//! | Phase | Env var                     | Extra requirement              |
//! |-------|-----------------------------|--------------------------------|
//! | 1     | (always)                    | Firecracker + kernel + rootfs  |
//! | N     | (always)                    | same as Phase 1                |
//! | 2     | `ARCBOX_SMOKE_RUN=1`        | guest agent in rootfs + vsock  |
//! | 3     | `ARCBOX_SMOKE_CHECKPOINT=1` | KVM snapshot support           |

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::time::Instant;

use anyhow::{bail, Context};
use arcbox_vm::{
    config::VmmConfig, RestoreSandboxSpec, SandboxEvent, SandboxManager, SandboxSpec, SandboxState,
};
use tokio::sync::broadcast;
use tokio::time::timeout;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "arcbox_vm=info".parse().unwrap()),
        )
        .init();

    let config_path = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("ARCBOX_CONFIG").ok())
        .unwrap_or_else(|| "config.toml".into());

    let run_phase2 = std::env::var("ARCBOX_SMOKE_RUN").map_or(false, |v| v == "1");
    let run_phase3 = std::env::var("ARCBOX_SMOKE_CHECKPOINT").map_or(false, |v| v == "1");

    let config = VmmConfig::from_file(&config_path)
        .with_context(|| format!("load config from {config_path}"))?;

    // Save network config before consuming config.
    let net_cidr = config.network.cidr.clone();
    let net_gateway = config.network.gateway.clone();

    let manager = SandboxManager::new(config).context("SandboxManager::new")?;

    // =========================================================================
    // Phase 1 — Core lifecycle
    // =========================================================================
    println!("\n=== Phase 1: Core lifecycle ===");

    let mut events = manager.subscribe_events();

    let t0 = Instant::now();
    let (id, ip) = manager
        .create_sandbox(SandboxSpec {
            id: Some("smoke-1".into()),
            ..Default::default()
        })
        .await
        .context("create_sandbox")?;
    println!("  [create]  id={id} ip={ip}");

    wait_for_ready(&manager, &id, &mut events, 60).await?;
    println!("  [ready]   boot={}ms", t0.elapsed().as_millis());

    let info = manager.inspect_sandbox(&id).context("inspect_sandbox")?;
    println!(
        "  [inspect] state={} vcpus={} mem={}MiB ip={}",
        info.state,
        info.vcpus,
        info.memory_mib,
        info.network
            .as_ref()
            .map(|n| n.ip_address.as_str())
            .unwrap_or("-"),
    );

    let list = manager.list_sandboxes(None, &HashMap::new());
    println!("  [list]    {} sandbox(es):", list.len());
    for s in &list {
        println!("            - {} state={} ip={}", s.id, s.state, s.ip_address);
    }

    // =========================================================================
    // Phase N — Network verification (always, no guest agent required)
    //
    // Checks:
    //   N.1  Assigned IP is within the configured CIDR subnet.
    //   N.2  TAP interface appears on the host after create.
    //   N.3  A second sandbox receives a different IP (pool uniqueness).
    //   N.4  TAP interface disappears from the host after remove.
    // =========================================================================
    println!("\n=== Phase N: Network verification ===");

    // N.1 — IP must be within the configured CIDR.
    let net = info.network.as_ref().context("no network allocation on smoke-1")?;
    println!(
        "  [net.1]  tap={} ip={} gw={}",
        net.tap_name, net.ip_address, net.gateway
    );
    check_ip_in_cidr(&net.ip_address, &net_cidr)
        .with_context(|| format!("IP {} not in subnet {}", net.ip_address, net_cidr))?;
    println!("  [net.1]  {} is within {net_cidr} ✓", net.ip_address);

    // N.2 — TAP interface visible on host.
    if tap_exists(&net.tap_name) {
        println!("  [net.2]  TAP {} visible on host ✓", net.tap_name);
    } else {
        bail!("TAP {} not found on host after create", net.tap_name);
    }

    // N.3 — Second sandbox must receive a distinct IP.
    {
        let mut events_n = manager.subscribe_events();
        let (id2, ip2) = manager
            .create_sandbox(SandboxSpec {
                id: Some("smoke-net-2".into()),
                ..Default::default()
            })
            .await
            .context("create smoke-net-2")?;
        println!("  [net.3]  smoke-net-2 ip={ip2}");

        if ip == ip2 {
            // Clean up before bailing.
            let _ = manager.remove_sandbox(&id2, true).await;
            bail!("duplicate IP {ip2} assigned to two concurrent sandboxes");
        }
        println!("  [net.3]  IPs are distinct ({ip} ≠ {ip2}) ✓");

        wait_for_ready(&manager, &id2, &mut events_n, 60).await?;

        // Capture TAP name before destroying the sandbox.
        let tap2 = manager
            .inspect_sandbox(&id2)
            .ok()
            .and_then(|i| i.network)
            .map(|n| n.tap_name);

        manager.stop_sandbox(&id2, 10).await.context("stop smoke-net-2")?;
        manager.remove_sandbox(&id2, false).await.context("remove smoke-net-2")?;
        println!("  [net.3]  smoke-net-2 removed");

        // N.4 — TAP must be gone after remove.
        if let Some(tap) = tap2 {
            if !tap_exists(&tap) {
                println!("  [net.4]  TAP {tap} cleaned up after remove ✓");
            } else {
                bail!("TAP {tap} still visible on host after remove");
            }
        }
    }

    // =========================================================================
    // Phase 2 — Command execution + guest-side network checks
    //           (requires guest agent + vsock in rootfs)
    // =========================================================================
    if run_phase2 {
        println!("\n=== Phase 2: Command execution ===");

        // Basic commands.
        for cmd in [
            vec!["echo", "hello from arcbox-vm"],
            vec!["uname", "-a"],
        ] {
            run_cmd(&manager, &id, &cmd, 10).await?;
        }

        // Guest-side network: verify assigned IP appears on eth0.
        println!("\n  --- guest network checks ---");
        let addr_out = run_cmd(&manager, &id, &["ip", "addr", "show", "eth0"], 5).await?;
        if addr_out.contains(&net.ip_address) {
            println!("  [net.guest.1]  guest eth0 has IP {} ✓", net.ip_address);
        } else {
            bail!(
                "guest eth0 does not show IP {}; output: {addr_out:?}",
                net.ip_address
            );
        }

        // Host→guest ping: guest has its IP configured, so host can now reach it.
        {
            let status = std::process::Command::new("ping")
                .args(["-c", "1", "-W", "2", &net.ip_address.to_string()])
                .status()
                .context("spawn ping")?;
            if status.success() {
                println!("  [net.guest.5]  host→sandbox ping {} ✓", net.ip_address);
            } else {
                bail!("host cannot reach sandbox IP {}", net.ip_address);
            }
        }

        // Guest-side network: ping the gateway (one packet, 2 s timeout).
        let ping_out =
            run_cmd(&manager, &id, &["ping", "-c", "1", "-W", "2", &net_gateway], 10).await?;
        if ping_out.contains("1 received") || ping_out.contains("1 packets received") {
            println!("  [net.guest.2]  ping {net_gateway} from guest succeeded ✓");
        } else {
            bail!("ping {net_gateway} failed; output: {ping_out:?}");
        }

        // Guest-side network: reach external IP (proves NAT/masquerade is configured).
        // Uses 223.5.5.5 (Alibaba AliDNS) — reliably reachable from mainland China.
        let ext_ping =
            run_cmd(&manager, &id, &["ping", "-c", "1", "-W", "5", "223.5.5.5"], 15).await?;
        if ext_ping.contains("1 received") || ext_ping.contains("1 packets received") {
            println!("  [net.guest.3]  ping 223.5.5.5 from guest succeeded ✓");
        } else {
            bail!("external ping 223.5.5.5 failed; output: {ext_ping:?}");
        }

        // Guest-side network: DNS resolution (proves /etc/resolv.conf + forwarding work).
        let dns_out = run_cmd(&manager, &id, &["getent", "hosts", "baidu.com"], 10).await?;
        if !dns_out.trim().is_empty() {
            println!("  [net.guest.4]  DNS resolution (baidu.com) succeeded ✓");
        } else {
            bail!("DNS resolution returned empty output; output: {dns_out:?}");
        }
    }

    // =========================================================================
    // Phase 3 — Checkpoint
    // =========================================================================
    let mut snapshot_id_opt: Option<String> = None;
    if run_phase3 {
        println!("\n=== Phase 3: Checkpoint ===");
        let ck = manager
            .checkpoint_sandbox(&id, "smoke-test".into())
            .await
            .context("checkpoint_sandbox")?;
        println!("  [checkpoint] snapshot_id={}", ck.snapshot_id);
        println!("               dir={}", ck.snapshot_dir);
        snapshot_id_opt = Some(ck.snapshot_id);
    }

    // =========================================================================
    // Phase 1 cleanup
    // =========================================================================
    manager.stop_sandbox(&id, 30).await.context("stop_sandbox")?;
    println!("\n  [stop]   done");
    manager
        .remove_sandbox(&id, false)
        .await
        .context("remove_sandbox")?;
    println!("  [remove] done");

    // =========================================================================
    // Phase 3 (cont) — Restore
    // =========================================================================
    if let Some(snapshot_id) = snapshot_id_opt {
        println!("\n=== Phase 3 (cont): Restore ===");

        let mut events2 = manager.subscribe_events();
        let (rid, rip) = manager
            .restore_sandbox(RestoreSandboxSpec {
                id: Some("smoke-restored".into()),
                snapshot_id,
                labels: HashMap::new(),
                network_override: true,
                ttl_seconds: 0,
            })
            .await
            .context("restore_sandbox")?;
        println!("  [restore] id={rid} ip={rip}");

        wait_for_ready(&manager, &rid, &mut events2, 30).await?;

        let rinfo = manager.inspect_sandbox(&rid).context("inspect restored")?;
        println!(
            "  [inspect] state={} ip={}",
            rinfo.state,
            rinfo.network
                .as_ref()
                .map(|n| n.ip_address.as_str())
                .unwrap_or("-"),
        );

        manager.stop_sandbox(&rid, 30).await.context("stop restored")?;
        manager
            .remove_sandbox(&rid, false)
            .await
            .context("remove restored")?;
        println!("  [cleanup] restored sandbox removed");
    }

    println!("\nSmoke test passed.");
    Ok(())
}

// =============================================================================
// Helpers
// =============================================================================

/// Run a command inside a sandbox and return its stdout as a `String`.
///
/// Prints a one-line summary with exit code and trimmed output.
async fn run_cmd(
    manager: &SandboxManager,
    id: &str,
    cmd: &[&str],
    timeout_secs: u32,
) -> anyhow::Result<String> {
    let label = cmd.join(" ");
    let mut rx = manager
        .run_in_sandbox(
            &id.to_owned(),
            cmd.iter().map(|s| s.to_string()).collect(),
            HashMap::new(),
            "/".into(),
            "root".into(),
            false,
            None,
            timeout_secs,
        )
        .await
        .with_context(|| format!("run_in_sandbox: {label}"))?;

    let mut stdout = Vec::new();
    let mut exit_code = 0;
    while let Some(chunk) = rx.recv().await {
        let chunk = chunk.context("output chunk")?;
        match chunk.stream.as_str() {
            "stdout" => stdout.extend_from_slice(&chunk.data),
            "stderr" => eprint!("{}", String::from_utf8_lossy(&chunk.data)),
            "exit" => exit_code = chunk.exit_code,
            _ => {}
        }
    }

    let out = String::from_utf8_lossy(&stdout).into_owned();
    println!("  [{label}] exit={exit_code} output={:?}", out.trim());
    if exit_code != 0 {
        bail!("`{label}` exited {exit_code}");
    }
    Ok(out)
}

/// Wait for a sandbox to enter `Ready` state.
///
/// Checks current state first (fast path for snapshot restores that complete
/// synchronously), then falls back to watching the event broadcast channel.
async fn wait_for_ready(
    manager: &SandboxManager,
    id: &str,
    events: &mut broadcast::Receiver<SandboxEvent>,
    timeout_secs: u64,
) -> anyhow::Result<()> {
    if let Ok(info) = manager.inspect_sandbox(&id.to_string()) {
        match info.state {
            SandboxState::Ready => return Ok(()),
            SandboxState::Failed => bail!(
                "sandbox {id} failed: {}",
                info.error.unwrap_or_else(|| "unknown".into())
            ),
            _ => {}
        }
    }

    let id = id.to_owned();
    timeout(
        std::time::Duration::from_secs(timeout_secs),
        async {
            loop {
                match events.recv().await {
                    Ok(ev) if ev.sandbox_id == id && ev.action == "ready" => return Ok(()),
                    Ok(ev) if ev.sandbox_id == id && ev.action == "failed" => {
                        let err = ev
                            .attributes
                            .get("error")
                            .cloned()
                            .unwrap_or_else(|| "unknown".into());
                        return Err(anyhow::anyhow!("sandbox {id} failed: {err}"));
                    }
                    Ok(_) => {}
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(e) => return Err(anyhow::anyhow!("event channel: {e}")),
                }
            }
        },
    )
    .await
    .with_context(|| format!("timed out after {timeout_secs}s waiting for {id} to be ready"))?
}

/// Verify that `ip` lies within the subnet described by `cidr` (`a.b.c.d/n`).
fn check_ip_in_cidr(ip: &str, cidr: &str) -> anyhow::Result<()> {
    let mut parts = cidr.splitn(2, '/');
    let base_str = parts.next().context("CIDR missing address")?;
    let prefix: u32 = parts
        .next()
        .context("CIDR missing prefix length")?
        .parse()
        .context("CIDR prefix not a number")?;

    let base = u32::from(Ipv4Addr::from_str(base_str).context("CIDR base address invalid")?);
    let addr = u32::from(Ipv4Addr::from_str(ip).context("IP address invalid")?);
    let mask = if prefix == 0 { 0 } else { !((1u32 << (32 - prefix)) - 1) };

    if (addr & mask) == (base & mask) {
        Ok(())
    } else {
        bail!("{ip} is not in {cidr}")
    }
}

/// Return `true` if the named TAP interface exists on the host.
fn tap_exists(tap_name: &str) -> bool {
    std::process::Command::new("ip")
        .args(["link", "show", tap_name])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}
