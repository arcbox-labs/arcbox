use std::sync::Once;

use anyhow::Result;
use tracing_subscriber::EnvFilter;

static TRACING: Once = Once::new();

#[test]
#[ignore = "boots a VM and runs Docker lifecycle checks"]
fn boot_assets() -> Result<()> {
    init_tracing();
    arcbox_e2e::boot_assets::run(arcbox_e2e::boot_assets::BootAssetsConfig::from_env()?)
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
