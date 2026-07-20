//! Integration tests for socket-related RPC methods.

mod common;

use arcbox_helper::HelperError;
use arcbox_helper::client::ClientError;

#[tokio::test]
async fn socket_link_valid() {
    let (client, _dir) = common::setup().await;
    client
        .socket_link("/Users/test/.arcbox/run/docker.sock")
        .await
        .unwrap();
}

#[tokio::test]
async fn socket_link_rejects_bad_path() {
    let (client, _dir) = common::setup().await;
    let err = client.socket_link("/tmp/docker.sock").await;
    match err {
        Err(ClientError::Helper(HelperError::Validation(msg))) => {
            assert!(msg.contains("/Users/"), "{msg}");
        }
        other => panic!("expected Validation, got {other:?}"),
    }
}

#[tokio::test]
async fn socket_unlink_valid() {
    let (client, _dir) = common::setup().await;
    client.socket_unlink().await.unwrap();
}

#[tokio::test]
async fn cli_link_valid() {
    let (client, _dir) = common::setup().await;
    client
        .cli_link(
            "docker",
            "/Applications/ArcBox.app/Contents/MacOS/xbin/docker",
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn cli_link_rejects_bad_name() {
    let (client, _dir) = common::setup().await;
    let err = client
        .cli_link("rm", "/Applications/ArcBox.app/Contents/MacOS/xbin/rm")
        .await;
    assert!(matches!(
        err,
        Err(ClientError::Helper(HelperError::Validation(_)))
    ));
}

#[tokio::test]
async fn cli_link_rejects_bad_target() {
    let (client, _dir) = common::setup().await;
    let err = client.cli_link("docker", "/tmp/docker").await;
    assert!(matches!(
        err,
        Err(ClientError::Helper(HelperError::Validation(_)))
    ));
}
