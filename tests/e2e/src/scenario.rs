//! Shared daemon-boot scaffolding for datapath scenario tests.
//!
//! Used by `egress_throughput`, `network_fault`, and `network_workload`:
//! build the release daemon, stage boot assets into an isolated data dir,
//! spawn a VZ daemon on a free DNS port, run the scenario with metrics, and
//! preserve the data dir on failure (or always with `KEEP_TEST_DIR`).

use std::path::Path;
use std::sync::Once;

use anyhow::Result;

use crate::boot_assets::{resolve_boot_version, stage_dev_boot_assets};
use crate::daemon::{DaemonConfig, DaemonHandle};
use crate::metrics::RunMetrics;

static TRACING: Once = Once::new();

pub fn init_tracing() {
    TRACING.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
            )
            .try_init();
    });
}

pub fn run_vz_scenario(
    name: &str,
    scenario: impl FnOnce(&mut DaemonHandle, &Path, &mut RunMetrics) -> Result<()>,
) -> Result<()> {
    // Per-SYN datapath tracing: stall forensics need the gated-SYN,
    // handshake-retransmit, and RST decisions, which log at debug.
    run_vz_scenario_with_log(name, "info,arcbox_net=debug,splicetcp=debug", scenario)
}

/// [`run_vz_scenario`] with an explicit daemon `RUST_LOG`.
///
/// Workload tests pass a quieter filter: `splicetcp=debug` logs every
/// classified frame, and at dup-ACK-storm rates the logging itself distorts
/// the datapath under measurement (~6k lines/s observed).
pub fn run_vz_scenario_with_log(
    name: &str,
    rust_log: &str,
    scenario: impl FnOnce(&mut DaemonHandle, &Path, &mut RunMetrics) -> Result<()>,
) -> Result<()> {
    init_tracing();
    // Diagnostic override for the daemon under test, e.g.
    // ARCBOX_E2E_DAEMON_LOG="info,splicetcp::tcp_bridge=debug".
    let rust_log = std::env::var("ARCBOX_E2E_DAEMON_LOG").unwrap_or_else(|_| rust_log.to_owned());

    let root = crate::repo_root();
    if !crate::env_flag("SKIP_BUILD") {
        let shell = xshell::Shell::new()?;
        shell.change_dir(&root);
        xshell::cmd!(shell, "cargo build --release -p arcbox-daemon").run()?;
    }

    let version = resolve_boot_version(&root)?;
    let data_dir = tempfile::Builder::new()
        .prefix(&format!("arcbox-{name}-"))
        .tempdir()?;
    stage_dev_boot_assets(&root, data_dir.path(), &version)?;

    let mut daemon = DaemonHandle::spawn(DaemonConfig {
        binary: root.join("target/release/arcbox-daemon"),
        data_dir: data_dir.path().to_owned(),
        args: vec![],
        env: vec![
            ("ARCBOX_BOOT_ASSET_VERSION".to_owned(), version),
            ("ARCBOX_VM_BACKEND".to_owned(), "vz".to_owned()),
            ("RUST_LOG".to_owned(), rust_log),
        ],
    })?;

    let mut metrics = RunMetrics::new(name, Some("vz"));
    let result = scenario(&mut daemon, data_dir.path(), &mut metrics);
    metrics.passed = result.is_ok();
    if let Err(error) = metrics.write(Some(data_dir.path())) {
        tracing::warn!("writing run metrics failed: {error:#}");
    }
    if result.is_err() || crate::env_flag("KEEP_TEST_DIR") {
        let kept = data_dir.keep();
        tracing::warn!(path = %kept.display(), "preserving test directory");
    }
    result
}
