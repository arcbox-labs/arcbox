//! Integration tests for connection handling and version reporting.

mod common;

use arcbox_helper::client::{Client, ClientError};

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
    // Independent of workspace package version (0.4.x).
    assert_eq!(env!("CARGO_PKG_VERSION"), "1.0.0");
}

#[tokio::test]
async fn connection_refused_when_no_server() {
    let err = Client::connect_to("/tmp/arcbox-helper-nonexistent.sock").await;
    assert!(matches!(err, Err(ClientError::Connection(_))));
}
