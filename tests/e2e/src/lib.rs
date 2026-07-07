use std::path::PathBuf;

pub mod boot_assets;
pub mod daemon;
pub mod docker;
pub mod metrics;
pub mod sandbox;
pub mod signing;

pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("tests/e2e lives two levels below the repository root")
        .to_owned()
}

/// True when the environment variable is set to a truthy value (or set
/// but empty), e.g. `SKIP_BUILD=1` / `KEEP_TEST_DIR=yes`.
pub fn env_flag(name: &str) -> bool {
    std::env::var(name).is_ok_and(|value| {
        value.is_empty()
            || matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
    })
}
