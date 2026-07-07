//! Verifies the harness fail-fast path end to end: a daemon pointed at a
//! nonexistent boot-asset version must publish FAILED on the
//! `WatchSetupStatus` stream (or exit), and `DaemonHandle::wait_ready`
//! must surface that as an error instead of hanging until the timeout.

use std::sync::Once;
use std::time::Duration;

use anyhow::Result;
use arcbox_e2e::daemon::{DaemonConfig, DaemonHandle};
use tracing_subscriber::EnvFilter;

static TRACING: Once = Once::new();

#[test]
#[ignore = "spawns a signed daemon; requires macOS codesign"]
fn daemon_reports_startup_failure() -> Result<()> {
    init_tracing();

    let root = arcbox_e2e::repo_root();
    if !arcbox_e2e::env_flag("SKIP_BUILD") {
        let shell = xshell::Shell::new()?;
        shell.change_dir(&root);
        xshell::cmd!(shell, "cargo build -p arcbox-daemon").run()?;
    }

    let data_dir = tempfile::Builder::new()
        .prefix("arcbox-fail-test-")
        .tempdir()?;

    let mut daemon = DaemonHandle::spawn(DaemonConfig {
        binary: root.join("target/debug/arcbox-daemon"),
        data_dir: data_dir.path().to_owned(),
        args: Vec::new(),
        // No bundle and no downloadable asset under this version: startup
        // must fail in asset preparation.
        env: vec![(
            "ARCBOX_BOOT_ASSET_VERSION".to_owned(),
            "0.0.0-e2e-nonexistent".to_owned(),
        )],
    })?;

    let error = daemon
        .wait_ready_blocking(Duration::from_secs(60))
        .expect_err("daemon with a nonexistent asset version must not become ready");
    let text = format!("{error:#}");
    tracing::info!(%text, "harness surfaced the startup failure");
    assert!(
        text.contains("daemon startup failed") || text.contains("exited with"),
        "error should carry the FAILED phase or the exit status, got: {text}"
    );
    Ok(())
}

fn init_tracing() {
    TRACING.call_once(|| {
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_target(false)
            .compact()
            .init();
    });
}
