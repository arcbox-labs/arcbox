use std::sync::LazyLock;

const LOCK_TOML: &str = include_str!("../../../../assets.lock");

#[derive(Debug, serde::Deserialize)]
struct AssetsLock {
    boot: BootSection,
}

#[derive(Debug, serde::Deserialize)]
struct BootSection {
    version: String,
    cdn: Option<String>,
    manifest_sha256: Option<String>,
}

static LOCK: LazyLock<AssetsLock> =
    LazyLock::new(|| toml::from_str(LOCK_TOML).expect("invalid assets.lock"));

const DEFAULT_CDN_BASE_URL: &str = "https://boot.arcboxcdn.com";

#[must_use]
pub fn boot_asset_version() -> &'static str {
    &LOCK.boot.version
}

#[must_use]
pub fn boot_asset_cdn() -> &'static str {
    LOCK.boot.cdn.as_deref().unwrap_or(DEFAULT_CDN_BASE_URL)
}

pub(super) fn boot_asset_manifest_sha256() -> Option<&'static str> {
    LOCK.boot
        .manifest_sha256
        .as_deref()
        .filter(|s| !s.is_empty())
}
