//! Python SDK hello-world e2e: `sdk/python/tests/test_e2e.py`
//! against an isolated daemon (CORE-58 phase 1 acceptance).
//!
//! Requires nested virtualization (VZ backend, Apple Silicon M3+ with
//! macOS 15+), staged boot assets, a signable daemon binary, and uv. Run:
//!
//! ```console
//! cargo test -p arcbox-e2e --test sdk_py -- --ignored --nocapture
//! ```

use arcbox_e2e::sdk_py::{SdkPyConfig, run};

#[test]
#[ignore = "requires nested virtualization (VZ on M3+), boot assets, a signed daemon, and uv"]
fn sdk_python_hello_world() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_test_writer()
        .init();

    run(SdkPyConfig::from_env()).expect("Python SDK e2e failed");
}
