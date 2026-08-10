//! End-to-end health checks for the paths users actually invoke.

use std::fmt::Write as _;
use std::path::Path;
use std::time::Duration;

use anyhow::{Result, bail};
use serde::Serialize;
use tokio::process::Command;

use super::OutputFormat;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum CheckState {
    Pass,
    Fail,
    /// The check could not be run. Reported, but never counted as a failure —
    /// see `ComponentStatus::Unknown` in the setup status module.
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
struct HealthCheck {
    name: &'static str,
    status: CheckState,
    detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    repair: Option<&'static str>,
}

impl HealthCheck {
    fn pass(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            status: CheckState::Pass,
            detail: detail.into(),
            repair: None,
        }
    }

    fn fail(name: &'static str, detail: impl Into<String>, repair: &'static str) -> Self {
        Self {
            name,
            status: CheckState::Fail,
            detail: detail.into(),
            repair: Some(repair),
        }
    }

    fn unknown(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            status: CheckState::Unknown,
            detail: detail.into(),
            repair: None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct Summary {
    passed: usize,
    failed: usize,
    unknown: usize,
}

#[derive(Debug, Clone, Serialize)]
struct DoctorReport {
    healthy: bool,
    checks: Vec<HealthCheck>,
    summary: Summary,
}

impl DoctorReport {
    fn new(checks: Vec<HealthCheck>) -> Self {
        let count = |state: CheckState| checks.iter().filter(|c| c.status == state).count();
        let (passed, failed, unknown) = (
            count(CheckState::Pass),
            count(CheckState::Fail),
            count(CheckState::Unknown),
        );
        Self {
            healthy: failed == 0,
            checks,
            summary: Summary {
                passed,
                failed,
                unknown,
            },
        }
    }

    fn table(&self) -> String {
        let mut output = String::from("ArcBox Doctor\n\n");
        for check in &self.checks {
            let state = match check.status {
                CheckState::Pass => "PASS",
                CheckState::Fail => "FAIL",
                CheckState::Unknown => "UNKN",
            };
            writeln!(output, "  [{state}] {}: {}", check.name, check.detail)
                .expect("writing to a String cannot fail");
            if let Some(repair) = check.repair {
                writeln!(output, "         Repair: {repair}")
                    .expect("writing to a String cannot fail");
            }
        }
        write!(
            output,
            "\n{} passed, {} failed",
            self.summary.passed, self.summary.failed
        )
        .expect("writing to a String cannot fail");
        if self.summary.unknown > 0 {
            write!(output, ", {} unknown", self.summary.unknown)
                .expect("writing to a String cannot fail");
        }
        output
    }
}

/// Runs all diagnostic checks and prints one coherent report.
pub async fn execute(format: OutputFormat) -> Result<()> {
    let report = inspect().await;
    match format {
        OutputFormat::Table => println!("{}", report.table()),
        OutputFormat::Json => println!("{}", serde_json::to_string(&report)?),
        OutputFormat::Quiet => bail!("quiet output is not supported for doctor"),
    }
    if !report.healthy {
        bail!("ArcBox health checks failed");
    }
    Ok(())
}

async fn inspect() -> DoctorReport {
    let layout = arcbox_constants::paths::HostLayout::from_env_or_default();
    let mut checks = Vec::new();
    if let Err(error) = arcbox_core::Config::load() {
        checks.push(HealthCheck::fail(
            "Configuration",
            format!("{error:#}"),
            "Fix the active ArcBox configuration, then rerun doctor.",
        ));
    }
    let expected_socket = super::resolve_docker_socket_path();
    checks.push(check_daemon(&layout, &expected_socket));
    checks.push(check_docker_context(&expected_socket).await);
    checks.push(check_docker_cli().await);

    let shell = super::setup::shell_integration_status().await;
    checks.push(shell_check(
        "CLI symlink",
        &shell.bin_symlink,
        || {
            shell
                .bin_symlink
                .path
                .clone()
                .unwrap_or_else(|| "ArcBox abctl".to_owned())
        },
        || {
            shell.bin_symlink.path.clone().map_or_else(
                || "ArcBox abctl symlink is missing".to_owned(),
                |path| format!("missing {path}"),
            )
        },
        "Run `abctl setup install`.",
    ));
    checks.push(shell_check(
        "Shell profile",
        &shell.profile,
        || {
            shell
                .profile
                .path
                .clone()
                .unwrap_or_else(|| shell.shell.clone())
        },
        || {
            shell
                .profile
                .path
                .clone()
                .unwrap_or_else(|| "profile not detected".to_owned())
        },
        "Run `abctl setup install`.",
    ));
    checks.push(shell_check(
        "Shell PATH",
        &shell.login_path,
        || "login shell resolves ArcBox abctl".to_owned(),
        || "login shell does not resolve ArcBox abctl".to_owned(),
        "Run `abctl setup install`, then restart the shell.",
    ));
    checks.push(shell_check(
        "Shell completion",
        &shell.completions,
        || "discoverable in the login shell".to_owned(),
        || "completion is not discoverable".to_owned(),
        "Run `abctl setup install`, then restart the shell.",
    ));

    #[cfg(target_os = "macos")]
    add_macos_checks(&mut checks).await;

    DoctorReport::new(checks)
}

/// Maps a shell-integration component onto a doctor check.
///
/// A component whose check could not run stays `Unknown` here too: reporting
/// it as a failure would tell the user to repair an install that may be
/// perfectly healthy, and would fail `doctor` on a probe's own bad day.
fn shell_check(
    name: &'static str,
    component: &super::setup::ComponentStatus,
    passed: impl FnOnce() -> String,
    failed: impl FnOnce() -> String,
    repair: &'static str,
) -> HealthCheck {
    if component.is_ok() {
        HealthCheck::pass(name, passed())
    } else if component.is_failed() {
        HealthCheck::fail(
            name,
            component.detail.clone().unwrap_or_else(failed),
            repair,
        )
    } else {
        HealthCheck::unknown(
            name,
            component
                .detail
                .clone()
                .unwrap_or_else(|| format!("{name} could not be checked")),
        )
    }
}

fn check_daemon(layout: &arcbox_constants::paths::HostLayout, socket: &Path) -> HealthCheck {
    if !super::daemon::daemon_is_alive(&layout.lock_file) {
        return HealthCheck::fail(
            "Daemon",
            "daemon lock is not held",
            "Start the ArcBox daemon.",
        );
    }
    if !socket.exists() {
        return HealthCheck::fail(
            "Daemon",
            format!("Docker socket is missing at {}", socket.display()),
            "Restart the ArcBox daemon.",
        );
    }
    HealthCheck::pass("Daemon", format!("running ({})", socket.display()))
}

async fn check_docker_context(expected: &Path) -> HealthCheck {
    let output = match run_docker(&[
        "context",
        "inspect",
        "--format",
        "{{.Endpoints.docker.Host}}",
    ])
    .await
    {
        Ok(output) => output,
        Err(error) => {
            return HealthCheck::fail("Docker context", error, "Run `abctl docker setup`.");
        }
    };
    let endpoint = output.trim();
    match endpoint_matches_socket(endpoint, expected) {
        Ok(true) => HealthCheck::pass("Docker context", endpoint),
        Ok(false) => HealthCheck::fail(
            "Docker context",
            format!("{endpoint} does not select unix://{}", expected.display()),
            "Run `abctl docker setup` or select the ArcBox Docker context.",
        ),
        Err(error) => HealthCheck::fail(
            "Docker context",
            error,
            "Select a Docker context backed by the ArcBox Unix socket.",
        ),
    }
}

async fn check_docker_cli() -> HealthCheck {
    match run_docker(&["ps", "--format", "{{.ID}}"]).await {
        Ok(_) => HealthCheck::pass("Docker CLI", "`docker ps` completed"),
        Err(error) => HealthCheck::fail(
            "Docker CLI",
            error,
            "Fix the selected Docker context, then restart ArcBox if needed.",
        ),
    }
}

async fn run_docker(arguments: &[&str]) -> std::result::Result<String, String> {
    let mut command = Command::new("docker");
    command.args(arguments).kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_secs(5), command.output())
        .await
        .map_err(|_| format!("docker {} timed out", arguments.join(" ")))?
        .map_err(|error| format!("could not execute docker: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "docker {} failed: {}",
            arguments.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout).map_err(|_| "docker output was not UTF-8".to_owned())
}

fn endpoint_matches_socket(endpoint: &str, expected: &Path) -> Result<bool, String> {
    let path = endpoint
        .strip_prefix("unix://")
        .ok_or_else(|| format!("Docker endpoint is not a Unix socket: {endpoint}"))?;
    let actual = Path::new(path);
    if actual == expected {
        return Ok(true);
    }
    let actual = std::fs::canonicalize(actual)
        .map_err(|error| format!("could not resolve Docker endpoint {endpoint}: {error}"))?;
    let expected = std::fs::canonicalize(expected).map_err(|error| {
        format!(
            "could not resolve expected Docker socket {}: {error}",
            expected.display()
        )
    })?;
    Ok(actual == expected)
}

#[cfg(target_os = "macos")]
async fn add_macos_checks(checks: &mut Vec<HealthCheck>) {
    let dns = super::dns::inspect_status().await;
    checks.push(if dns.resolver_installed {
        HealthCheck::pass("DNS resolver", dns.resolver_path)
    } else {
        HealthCheck::fail(
            "DNS resolver",
            dns.resolver_error
                .unwrap_or_else(|| format!("missing {}", dns.resolver_path)),
            "Run `sudo abctl dns install`.",
        )
    });
    checks.push(match &dns.health {
        super::dns::DnsHealth::Healthy => HealthCheck::pass(
            "DNS service",
            format!("{} answered {}", dns.server_address, dns.query_name),
        ),
        super::dns::DnsHealth::DaemonDown => HealthCheck::fail(
            "DNS service",
            "ArcBox daemon is not running",
            "Start the ArcBox daemon.",
        ),
        super::dns::DnsHealth::Negative {
            response_code,
            description,
        } => HealthCheck::fail(
            "DNS service",
            format!("negative response {response_code}: {description}"),
            "Check the ArcBox daemon logs and DNS listener configuration.",
        ),
        super::dns::DnsHealth::ListenerAbsent => HealthCheck::fail(
            "DNS service",
            format!("no UDP listener at {}", dns.server_address),
            "Check the ArcBox daemon logs and DNS listener configuration.",
        ),
        super::dns::DnsHealth::TimedOut => HealthCheck::fail(
            "DNS service",
            format!("UDP query to {} timed out", dns.server_address),
            "Check the ArcBox daemon logs and DNS listener configuration.",
        ),
        super::dns::DnsHealth::Malformed { error } => HealthCheck::fail(
            "DNS service",
            format!("malformed response: {error}"),
            "Check the ArcBox daemon logs and DNS listener configuration.",
        ),
        super::dns::DnsHealth::Io { error } => HealthCheck::fail(
            "DNS service",
            format!("UDP probe failed: {error}"),
            "Check the ArcBox daemon logs and DNS listener configuration.",
        ),
    });
    checks.push(match &dns.system_resolver {
        super::dns::SystemResolverHealth::Healthy => HealthCheck::pass(
            "DNS system lookup",
            format!("{} resolved through macOS", dns.query_name),
        ),
        super::dns::SystemResolverHealth::TimedOut => HealthCheck::fail(
            "DNS system lookup",
            format!("resolving {} timed out", dns.query_name),
            "Check the macOS resolver configuration with `abctl dns status`.",
        ),
        super::dns::SystemResolverHealth::LookupFailed { error } => HealthCheck::fail(
            "DNS system lookup",
            format!("could not resolve {}: {error}", dns.query_name),
            "Check the macOS resolver configuration with `abctl dns status`.",
        ),
    });

    checks.push(
        match arcbox_core::bridge_discovery::find_bridge_with_vmenet() {
            Some((bridge, member)) => {
                HealthCheck::pass("Bridge NIC", format!("{bridge} with {member} member"))
            }
            None => HealthCheck::fail(
                "Bridge NIC",
                "no bridge interface with a vmenet member",
                "Restart the ArcBox daemon.",
            ),
        },
    );

    checks.push(check_container_route().await);
    checks.push(check_helper().await);
}

#[cfg(target_os = "macos")]
async fn check_container_route() -> HealthCheck {
    let Some((bridge, _)) = arcbox_core::bridge_discovery::find_bridge_with_vmenet() else {
        return HealthCheck::fail(
            "Container route",
            "cannot identify the ArcBox bridge",
            "Repair the bridge before checking its route.",
        );
    };
    match arcbox_core::route_reconciler::container_route_mode(&bridge).await {
        Ok(Some(arcbox_core::route_reconciler::RouteMode::Preferred)) => {
            HealthCheck::pass("Container route", format!("172.16.0.0/12 -> {bridge}"))
        }
        Ok(Some(arcbox_core::route_reconciler::RouteMode::SplitFallback)) => {
            HealthCheck::pass("Container route", format!("split /13 routes -> {bridge}"))
        }
        Ok(None) => HealthCheck::fail(
            "Container route",
            format!("container routes do not point to {bridge}"),
            "Restart the ArcBox daemon to reconcile networking.",
        ),
        Err(error) => HealthCheck::fail(
            "Container route",
            error.to_string(),
            "Check route permissions and the ArcBox daemon logs.",
        ),
    }
}

#[cfg(target_os = "macos")]
async fn check_helper() -> HealthCheck {
    let minimum = arcbox_constants::helper::MIN_HELPER_VERSION;
    match arcbox_helper::client::Client::probe_version().await {
        Ok(version) => match (
            arcbox_constants::helper::parse_helper_version(&version),
            arcbox_constants::helper::parse_semver_triple(minimum),
        ) {
            (Some(installed), Some(required))
                if arcbox_constants::helper::helper_version_satisfies(installed, required) =>
            {
                HealthCheck::pass("ArcBoxHelper", format!("reachable ({version})"))
            }
            _ => HealthCheck::fail(
                "ArcBoxHelper",
                format!("installed {version}, required {minimum}"),
                "Run `sudo abctl _install --no-daemon --no-shell`.",
            ),
        },
        Err(error) => HealthCheck::fail(
            "ArcBoxHelper",
            error.to_string(),
            "Run `sudo abctl _install --no-daemon --no-shell`.",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_report_is_unhealthy_in_both_formats() {
        let report = DoctorReport::new(vec![
            HealthCheck::pass("Docker CLI", "ok"),
            HealthCheck::fail("DNS service", "timed out", "check logs"),
        ]);

        assert!(!report.healthy);
        assert_eq!(report.summary.passed, 1);
        assert_eq!(report.summary.failed, 1);
        assert!(report.table().contains("[FAIL] DNS service"));
        let json = serde_json::to_value(report).unwrap();
        assert_eq!(json["healthy"], false);
        assert_eq!(json["checks"][1]["status"], "fail");
    }

    #[test]
    fn docker_context_must_select_the_expected_unix_socket() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("docker.sock");
        std::fs::write(&socket, []).unwrap();
        let alias = directory.path().join("alias.sock");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&socket, &alias).unwrap();

        assert_eq!(
            endpoint_matches_socket(&format!("unix://{}", alias.display()), &socket),
            Ok(true)
        );
        assert_eq!(
            endpoint_matches_socket("tcp://127.0.0.1:2375", &socket),
            Err("Docker endpoint is not a Unix socket: tcp://127.0.0.1:2375".to_owned())
        );
        assert!(
            endpoint_matches_socket(
                &format!("unix://{}", directory.path().join("missing.sock").display()),
                &socket
            )
            .unwrap_err()
            .contains("could not resolve Docker endpoint")
        );
    }
}
