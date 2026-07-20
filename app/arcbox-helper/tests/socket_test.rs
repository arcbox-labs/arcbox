//! Integration tests for socket-related RPC methods.

mod common;

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
    assert!(matches!(err, Err(ClientError::Helper(msg)) if msg.contains("/Users/")));
}

#[tokio::test]
async fn socket_unlink_valid() {
    let (client, _dir) = common::setup().await;
    client.socket_unlink().await.unwrap();
}

// cli_* live next to socket in the wire API; keep validation coverage here
// until a dedicated cli_test.rs is warranted.

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
    assert!(matches!(err, Err(ClientError::Helper(_))));
}

#[tokio::test]
async fn cli_link_rejects_bad_target() {
    let (client, _dir) = common::setup().await;
    let err = client.cli_link("docker", "/tmp/docker").await;
    assert!(matches!(err, Err(ClientError::Helper(_))));
}
