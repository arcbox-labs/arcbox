//! Integration tests for DNS-related RPC methods.

mod common;

use arcbox_helper::HelperError;
use arcbox_helper::client::ClientError;

#[tokio::test]
async fn dns_install_valid() {
    let (client, _dir) = common::setup().await;
    client.dns_install("arcbox.local", 5553).await.unwrap();
}

#[tokio::test]
async fn dns_install_rejects_privileged_port() {
    let (client, _dir) = common::setup().await;
    let err = client.dns_install("arcbox.local", 53).await;
    match err {
        Err(ClientError::Helper(HelperError::Validation(msg))) => {
            assert!(msg.contains("1024"), "{msg}");
        }
        other => panic!("expected Validation, got {other:?}"),
    }
}

#[tokio::test]
async fn dns_install_rejects_invalid_domain() {
    let (client, _dir) = common::setup().await;
    let err = client.dns_install("UPPER.CASE", 5553).await;
    match err {
        Err(ClientError::Helper(HelperError::Validation(msg))) => {
            assert!(msg.contains("invalid characters"), "{msg}");
        }
        other => panic!("expected Validation, got {other:?}"),
    }
}

#[tokio::test]
async fn dns_status_valid() {
    let (client, _dir) = common::setup().await;
    let installed = client.dns_status("arcbox.local").await.unwrap();
    assert!(!installed);
}
