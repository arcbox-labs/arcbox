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

/// Ignored: the two upstream paths dimicon falls back to for a Docker Hub
/// org image are both gone from CI runner IPs — `hub.docker.com/api/`
/// `media/repos_logo` is Cloudflare-gated per-IP (429 is excluded: dimicon
/// maps it to an error, which would fail at the unwrap, not the assert),
/// and `hub.docker.com/v2/orgs/localstack/` now returns an empty
/// `gravatar_url` where the gravatar the second accepted source anticipated
/// used to be. The same test passes from unblocked IPs on the same tree.
#[ignore = "Docker Hub's repos_logo API 403s from GitHub runner IPs and the org gravatar_url is now empty upstream, so resolution is Ok(None) there; restore when either answers from CI again"]
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
