//! System health diagnostics.
//!
//! `abctl doctor` runs a series of checks to diagnose common issues with the
//! ArcBox runtime: daemon connectivity, VM health, networking, DNS, and
//! (on macOS) L3 container routing.

use anyhow::Result;
use std::process::Command;

/// Runs all diagnostic checks and prints a report.
pub async fn execute() -> Result<()> {
    println!("ArcBox Doctor\n");

    let mut passed = 0u32;
    let mut warned = 0u32;
    let mut failed = 0u32;

    macro_rules! check {
        ($name:expr, $result:expr) => {
            match $result {
                CheckResult::Pass(msg) => {
                    println!("  [PASS] {}: {}", $name, msg);
                    passed += 1;
                }
                CheckResult::Warn(msg) => {
                    println!("  [WARN] {}: {}", $name, msg);
                    warned += 1;
                }
                CheckResult::Fail(msg) => {
                    println!("  [FAIL] {}: {}", $name, msg);
                    failed += 1;
                }
            }
        };
    }

    // -- Core checks --
    check!("Daemon", check_daemon().await);
    check!("VM", check_vm().await);
    check!("Docker API", check_docker_api().await);
    check!("DNS resolver", check_dns_resolver());

    // -- macOS networking checks --
    #[cfg(target_os = "macos")]
    {
        check!("Bridge NIC", check_bridge_nic());
        check!("Container route", check_container_route());
        check!("ArcBoxHelper", check_helper().await);
    }

    // -- Summary --
    println!();
    if failed > 0 {
        println!("{passed} passed, {warned} warnings, {failed} failed");
        std::process::exit(1);
    } else if warned > 0 {
        println!("{passed} passed, {warned} warnings");
    } else {
        println!("All {passed} checks passed");
    }
    Ok(())
}

enum CheckResult {
    Pass(String),
    Warn(String),
    Fail(String),
}

// ---------------------------------------------------------------------------
// Individual checks
// ---------------------------------------------------------------------------

/// Check if daemon is reachable via docker.sock.
async fn check_daemon() -> CheckResult {
    let sock = daemon_socket();
    if !sock.exists() {
        return CheckResult::Fail(format!("socket not found at {}", sock.display()));
    }
    // Try /_ping
    match tokio::process::Command::new("curl")
        .args([
            "-s",
            "--unix-socket",
            &sock.to_string_lossy(),
            "http://localhost/_ping",
        ])
        .output()
        .await
    {
        Ok(out) if out.status.success() => {
            let body = String::from_utf8_lossy(&out.stdout);
            if body.trim() == "OK" {
                CheckResult::Pass("responding".into())
            } else {
                CheckResult::Warn(format!("unexpected response: {}", body.trim()))
            }
        }
        _ => CheckResult::Fail("socket exists but not responding".into()),
    }
}

/// Check if the default VM is running by querying the Docker API.
async fn check_vm() -> CheckResult {
    let sock = daemon_socket();
    // /info includes the VM's kernel version — if it responds, the VM is up.
    match tokio::process::Command::new("curl")
        .args([
            "-s",
            "--max-time",
            "3",
            "--unix-socket",
            &sock.to_string_lossy(),
            "http://localhost/info",
        ])
        .output()
        .await
    {
        Ok(out) if out.status.success() => {
            let body = String::from_utf8_lossy(&out.stdout);
            if body.contains("KernelVersion") {
                CheckResult::Pass("running".into())
            } else {
                CheckResult::Warn("daemon responded but VM may not be ready".into())
            }
        }
        _ => CheckResult::Fail("VM not responding (Docker /info failed)".into()),
    }
}

/// Check Docker API proxy is responding.
async fn check_docker_api() -> CheckResult {
    let sock = daemon_socket();
    match tokio::process::Command::new("curl")
        .args([
            "-s",
            "--unix-socket",
            &sock.to_string_lossy(),
            "http://localhost/version",
        ])
        .output()
        .await
    {
        Ok(out) if out.status.success() => {
            let body = String::from_utf8_lossy(&out.stdout);
            if body.contains("ApiVersion") {
                CheckResult::Pass("Docker Engine API reachable".into())
            } else {
                CheckResult::Warn("unexpected /version response".into())
            }
        }
        _ => CheckResult::Fail("Docker API not responding".into()),
    }
}

/// Check if DNS resolver file is installed.
fn check_dns_resolver() -> CheckResult {
    let resolver = std::path::Path::new("/etc/resolver/arcbox.local");
    if resolver.exists() {
        match std::fs::read_to_string(resolver) {
            Ok(content) if content.contains("nameserver") => {
                CheckResult::Pass(format!("{}", resolver.display()))
            }
            _ => CheckResult::Warn("file exists but looks invalid".into()),
        }
    } else {
        CheckResult::Warn(
            "not installed — run 'sudo abctl dns install' for *.arcbox.local resolution".into(),
        )
    }
}

/// Check if a vmnet bridge interface exists with a VM member.
#[cfg(target_os = "macos")]
fn check_bridge_nic() -> CheckResult {
    match arcbox_core::bridge_discovery::find_bridge_with_vmenet() {
        Some((bridge, member)) => CheckResult::Pass(format!("{bridge} with {member} member")),
        None => CheckResult::Fail("no bridge interface with vmenet member found".into()),
    }
}

/// Check if the container subnet route is installed correctly.
#[cfg(target_os = "macos")]
fn check_container_route() -> CheckResult {
    let Ok(output) = Command::new("route")
        .args(["-n", "get", "172.16.0.0"])
        .output()
    else {
        return CheckResult::Fail("route command failed".into());
    };
    let text = String::from_utf8_lossy(&output.stdout);

    let mut iface = None;
    let mut gateway = None;
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(val) = trimmed.strip_prefix("interface:") {
            iface = Some(val.trim().to_string());
        } else if let Some(val) = trimmed.strip_prefix("gateway:") {
            gateway = Some(val.trim().to_string());
        }
    }

    match iface.as_deref() {
        Some(i) if i.starts_with("bridge") => CheckResult::Pass(format!("172.16.0.0/12 → {i}")),
        Some(i) => CheckResult::Fail(format!(
            "172.16.0.0/12 → {i} (expected bridge*, got wrong interface; gateway={:?})",
            gateway
        )),
        None => CheckResult::Fail("no route for 172.16.0.0/12".into()),
    }
}

/// Check if arcbox-helper is reachable through launchd socket activation.
#[cfg(target_os = "macos")]
async fn check_helper() -> CheckResult {
    let min = arcbox_constants::helper::MIN_HELPER_VERSION;
    match arcbox_helper::client::Client::connect().await {
        Ok(client) => match client.version().await {
            Ok(version) => match arcbox_constants::helper::parse_helper_version(&version) {
                Some(installed) => {
                    let Some(minimum) = arcbox_constants::helper::parse_semver_triple(min) else {
                        return CheckResult::Fail(format!(
                            "invalid MIN_HELPER_VERSION constant {min:?}"
                        ));
                    };
                    if arcbox_constants::helper::helper_version_satisfies(installed, minimum) {
                        CheckResult::Pass(format!("reachable ({version})"))
                    } else {
                        CheckResult::Fail(format!(
                            "{version} is older than required {min}; run 'sudo abctl _install --no-daemon --no-shell'"
                        ))
                    }
                }
                None => CheckResult::Fail(format!(
                    "unrecognized version {version:?}; run 'sudo abctl _install --no-daemon --no-shell'"
                )),
            },
            Err(e) => CheckResult::Fail(format!("version check failed: {e}")),
        },
        Err(e) => CheckResult::Fail(format!("not reachable via launchd socket: {e}")),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn daemon_socket() -> std::path::PathBuf {
    if let Ok(val) = std::env::var("ARCBOX_SOCKET") {
        return std::path::PathBuf::from(val);
    }
    arcbox_constants::paths::HostLayout::from_env_or_default().docker_socket
}
