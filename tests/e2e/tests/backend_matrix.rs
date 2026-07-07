//! Dual-backend comparison matrix: the same daemon-level Docker
//! lifecycle scenario runs once per System VM backend, VZ first.
//!
//! VZ (Apple's managed Virtualization.framework) acts as the oracle for
//! the custom HV backend: a failure on HV alone points at the HV
//! implementation, while a failure on both points above the hypervisor
//! layer. The verdict line at the end of the log encodes that reading.

use std::sync::Once;

use anyhow::{Result, bail};
use arcbox_e2e::boot_assets::{BootAssetsConfig, build_release_binaries};
use arcbox_vmm::VmBackend;
use tracing_subscriber::EnvFilter;

static TRACING: Once = Once::new();

#[test]
#[ignore = "boots a VM per backend and runs Docker lifecycle checks"]
fn backend_matrix() -> Result<()> {
    init_tracing();

    if !arcbox_e2e::env_flag("SKIP_BUILD") {
        build_release_binaries()?;
    }

    let mut failures = Vec::new();
    for backend in [VmBackend::Vz, VmBackend::Hv] {
        tracing::info!(backend = backend.as_str(), "=== matrix run ===");
        let config = BootAssetsConfig {
            // Binaries were built once above.
            skip_build: true,
            backend: Some(backend),
            ..BootAssetsConfig::from_env()?
        };
        match arcbox_e2e::boot_assets::run(config) {
            Ok(()) => tracing::info!(backend = backend.as_str(), "matrix run passed"),
            Err(error) => {
                tracing::error!(backend = backend.as_str(), "matrix run failed: {error:#}");
                failures.push((backend, error));
            }
        }
    }

    match failures.as_slice() {
        [] => Ok(()),
        [(VmBackend::Hv, error)] => {
            bail!("HV failed while VZ passed — points at the HV backend implementation: {error:#}")
        }
        [(VmBackend::Vz, error)] => bail!(
            "VZ failed while HV passed — suspect the scenario or shared layers, not HV: {error:#}"
        ),
        _ => bail!(
            "both backends failed — suspect layers above the hypervisor: {:?}",
            failures
                .iter()
                .map(|(backend, error)| format!("{}: {error:#}", backend.as_str()))
                .collect::<Vec<_>>()
        ),
    }
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
