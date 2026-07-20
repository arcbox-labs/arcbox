//! Integration tests for connection handling and version reporting.

mod common;

use std::process::Command;

use arcbox_helper::client::{Client, ClientError};

#[test]
fn version_flag_reports_the_helper_version_on_stdout() {
    let output = Command::new(env!("CARGO_BIN_EXE_arcbox-helper"))
        .arg("--version")
        .output()
        .unwrap();

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!("arcbox-helper {}\n", env!("CARGO_PKG_VERSION"))
    );
    assert!(output.stderr.is_empty());
}

#[tokio::test]
async fn version_returns_helper_crate_version() {
    let (client, _dir) = common::setup().await;
    let version = client.version().await.unwrap();
    assert_eq!(
        version,
        format!("arcbox-helper {}", env!("CARGO_PKG_VERSION"))
    );
    assert_eq!(
        arcbox_constants::helper::parse_helper_version(&version),
        arcbox_constants::helper::parse_semver_triple(env!("CARGO_PKG_VERSION"))
    );
}

/// Package version, workspace path-dep pin, and MIN_HELPER_VERSION must move
/// together. Catches "bumped Cargo.toml but forgot MIN" before release.
#[test]
fn helper_version_pins_are_aligned() {
    let pkg = env!("CARGO_PKG_VERSION");
    let min = arcbox_constants::helper::MIN_HELPER_VERSION;
    assert_eq!(
        pkg, min,
        "arcbox-helper Cargo.toml version ({pkg}) must equal \
         arcbox_constants::helper::MIN_HELPER_VERSION ({min}); bump both \
         (and the workspace path-dep pin) together"
    );

    // Workspace path-dep pin in the root Cargo.toml.
    let root_toml = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.toml"));
    let needle = format!("arcbox-helper = {{ version = \"{pkg}\"");
    assert!(
        root_toml.contains(&needle),
        "root Cargo.toml must pin arcbox-helper = {{ version = \"{pkg}\", ... }}"
    );

    // Independent of workspace package version (0.4.x).
    assert_eq!(pkg, "1.0.0");
}

#[tokio::test]
async fn connection_refused_when_no_server() {
    let err = Client::connect_to("/tmp/arcbox-helper-nonexistent.sock").await;
    assert!(matches!(err, Err(ClientError::Connection(_))));
}
