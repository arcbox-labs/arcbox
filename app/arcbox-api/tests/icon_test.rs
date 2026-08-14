//! Icon resolution against the live registries.
//!
//! Exercises `IconServiceImpl::resolve` rather than the RPC method: the
//! behaviour under test is the lookup, and going through the method would
//! only add a request envelope to build.

use arcbox_api::IconServiceImpl;

#[tokio::test]
async fn get_icon_for_official_image() {
    let svc = IconServiceImpl::new();
    let resp = svc.resolve("nginx").await.unwrap();

    assert!(!resp.url.is_empty(), "expected icon URL for nginx");
    assert_eq!(resp.source, "docker_official_image");
}

#[tokio::test]
async fn get_icon_for_dockerhub_org() {
    let svc = IconServiceImpl::new();
    let resp = svc.resolve("localstack/localstack").await.unwrap();

    assert!(!resp.url.is_empty(), "expected icon URL for localstack");
    assert!(
        resp.source == "docker_hub_logo" || resp.source == "docker_hub_org_gravatar",
        "unexpected source: {}",
        resp.source
    );
}

#[tokio::test]
async fn get_icon_for_ghcr() {
    let svc = IconServiceImpl::new();
    let resp = svc.resolve("ghcr.io/astral-sh/uv").await.unwrap();

    assert!(!resp.url.is_empty(), "expected icon URL for ghcr image");
    assert_eq!(resp.source, "ghcr_avatar");
}

#[tokio::test]
async fn get_icon_not_found() {
    let svc = IconServiceImpl::new();
    let resp = svc
        .resolve("registry.example.com/nonexistent/image")
        .await
        .unwrap();

    assert!(resp.url.is_empty());
    assert_eq!(resp.source, "not_found");
}
