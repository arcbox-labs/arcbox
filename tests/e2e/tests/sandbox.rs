//! Sandbox smoke test: full stack over the real gRPC surface.
//!
//! Requires nested virtualization (VZ backend, Apple Silicon M3+ with
//! macOS 15+), staged boot assets, and a signable daemon binary. Run:
//!
//! ```console
//! cargo test -p arcbox-e2e --test sandbox -- --ignored --nocapture
//! ```

use arcbox_e2e::sandbox::{SandboxSmokeConfig, run};

#[test]
#[ignore = "requires nested virtualization (VZ on M3+), boot assets, and a signed daemon"]
fn sandbox_smoke() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_test_writer()
        .init();

    run(SandboxSmokeConfig::from_env()).expect("sandbox smoke failed");
}
