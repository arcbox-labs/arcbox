//! Wrapper for the VMM-layer HV probe (`src/bin/hv_e2e.rs`): builds the
//! probe, signs it with the virtualization entitlements, runs it, and
//! asserts a clean exit. The probe drives the HV backend directly (no
//! daemon): boot, vsock agent RPC, DAX, supervision, pause/resume, stop.

use std::process::Command;
use std::sync::Once;

use anyhow::{Context, Result, bail};
use tracing_subscriber::EnvFilter;

static TRACING: Once = Once::new();

#[test]
#[ignore = "boots an HV VM; needs Apple Silicon, dev boot assets, and a built guest agent"]
fn hv_vmm() -> Result<()> {
    init_tracing();

    let root = arcbox_e2e::repo_root();
    if !arcbox_e2e::env_flag("SKIP_BUILD") {
        tracing::info!("building hv_e2e probe (release)");
        let shell = xshell::Shell::new()?;
        shell.change_dir(&root);
        xshell::cmd!(shell, "cargo build --release -p arcbox-e2e --bin hv_e2e").run()?;
    }

    let binary = root.join("target/release/hv_e2e");
    arcbox_e2e::signing::ensure_signed(&binary)?;

    // The probe resolves boot-assets/dev paths relative to the repo root.
    let status = Command::new(&binary)
        .current_dir(&root)
        .status()
        .context("running hv_e2e probe")?;
    if !status.success() {
        bail!("hv_e2e probe failed with {status}");
    }
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
