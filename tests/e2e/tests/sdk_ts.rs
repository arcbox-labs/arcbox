//! TypeScript SDK hello-world e2e: `sdk/typescript/test/e2e.test.ts`
//! against an isolated daemon (CORE-58 phase 1 acceptance).
//!
//! Requires nested virtualization (VZ backend, Apple Silicon M3+ with
//! macOS 15+), staged boot assets, a signable daemon binary, and npm. Run:
//!
//! ```console
//! cargo test -p arcbox-e2e --test sdk_ts -- --ignored --nocapture
//! ```

use arcbox_e2e::sdk_ts::{SdkTsConfig, run};

#[test]
#[ignore = "requires nested virtualization (VZ on M3+), boot assets, a signed daemon, and npm"]
fn sdk_typescript_hello_world() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_test_writer()
        .init();

    run(SdkTsConfig::from_env()).expect("TypeScript SDK e2e failed");
}
