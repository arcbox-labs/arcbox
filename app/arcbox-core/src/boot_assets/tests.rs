use super::*;
use arcbox_constants::env::BOOT_ASSET_VERSION as BOOT_ASSET_VERSION_ENV;
use std::path::PathBuf;
use std::sync::Mutex;

static ENV_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn test_default_config() {
    let config = BootAssetConfig::default();
    assert!(!config.cdn_base_url.is_empty());
    assert!(!config.version.is_empty());
    assert!(!config.arch.is_empty());
}

#[test]
fn test_default_config_uses_boot_asset_version() {
    let _guard = ENV_LOCK.lock().unwrap();
    let original = std::env::var(BOOT_ASSET_VERSION_ENV).ok();
    // SAFETY: Test code running under ENV_LOCK mutex.
    unsafe { std::env::remove_var(BOOT_ASSET_VERSION_ENV) };

    let config = BootAssetConfig::default();
    assert_eq!(config.version, boot_asset_version());

    restore_env(original);
}

#[test]
fn test_default_config_env_override() {
    let _guard = ENV_LOCK.lock().unwrap();
    let original = std::env::var(BOOT_ASSET_VERSION_ENV).ok();
    // SAFETY: Test code running under ENV_LOCK mutex.
    unsafe { std::env::set_var(BOOT_ASSET_VERSION_ENV, "9.9.9") };

    let config = BootAssetConfig::default();
    assert_eq!(config.version, "9.9.9");

    restore_env(original);
}

#[test]
fn test_version_cache_dir() {
    let config = BootAssetConfig {
        version: "1.0.0".to_string(),
        cache_dir: PathBuf::from("/tmp/boot"),
        ..Default::default()
    };
    assert_eq!(config.version_cache_dir(), PathBuf::from("/tmp/boot/1.0.0"));
}

#[test]
fn test_is_cached_requires_all_assets() {
    let temp = tempfile::tempdir().unwrap();
    let cache_dir = temp.path().to_path_buf();
    let version = "1.0.0".to_string();
    let version_dir = cache_dir.join(&version);
    std::fs::create_dir_all(&version_dir).unwrap();

    let config = BootAssetConfig {
        version,
        cache_dir,
        ..Default::default()
    };
    let provider = BootAssetProvider::with_config(config).unwrap();

    assert!(!provider.is_cached());

    std::fs::write(version_dir.join("manifest.json"), b"{}").unwrap();
    assert!(!provider.is_cached());

    std::fs::write(version_dir.join("kernel"), b"vmlinux").unwrap();
    assert!(!provider.is_cached());

    std::fs::write(version_dir.join("rootfs.erofs"), b"erofs").unwrap();
    assert!(provider.is_cached());
}

#[tokio::test]
async fn cached_versions_use_semver_order_before_invalid_names() {
    let temp = tempfile::tempdir().unwrap();
    for version in [
        "invalid-z",
        "0.6.13",
        "1.0.0",
        "1.0.0+z",
        "0.5.13",
        "1.0.0-alpha.10",
        "1.0.0+a",
        "invalid-a",
        "0.6.2",
        "1.0.0-alpha.2",
        "0.5.5",
    ] {
        let version_dir = temp.path().join(version);
        std::fs::create_dir(&version_dir).unwrap();
        std::fs::write(version_dir.join("manifest.json"), b"{}").unwrap();
    }

    let provider = BootAssetProvider::with_config(BootAssetConfig {
        cache_dir: temp.path().to_path_buf(),
        ..Default::default()
    })
    .unwrap();

    assert_eq!(
        provider.list_cached_versions().await.unwrap(),
        [
            "0.5.5",
            "0.5.13",
            "0.6.2",
            "0.6.13",
            "1.0.0-alpha.2",
            "1.0.0-alpha.10",
            "1.0.0",
            "1.0.0+a",
            "1.0.0+z",
            "invalid-a",
            "invalid-z",
        ]
    );
}

#[test]
fn only_development_config_accepts_a_locally_generated_manifest() {
    let temp = tempfile::tempdir().unwrap();
    let version = "1.0.0";
    let version_dir = temp.path().join(version);
    std::fs::create_dir_all(&version_dir).unwrap();
    std::fs::write(
        version_dir.join("manifest.json"),
        serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "asset_version": version,
            "built_at": "now",
            "targets": {},
            "binaries": [{
                "name": "FEX",
                "version": "1",
                "targets": {
                    "arm64": {
                        "path": "FEX",
                        "sha256": "0".repeat(64)
                    }
                }
            }]
        }))
        .unwrap(),
    )
    .unwrap();

    let production = BootAssetProvider::with_config(BootAssetConfig {
        version: version.to_string(),
        cache_dir: temp.path().to_path_buf(),
        arch: "arm64".to_string(),
        ..Default::default()
    })
    .unwrap();
    assert!(production.cached_manifest_has_binary("FEX").is_err());

    let development = BootAssetProvider::with_config(BootAssetConfig {
        version: version.to_string(),
        cache_dir: temp.path().to_path_buf(),
        arch: "arm64".to_string(),
        allow_unpinned_manifest: true,
        ..Default::default()
    })
    .unwrap();
    assert!(development.cached_manifest_has_binary("FEX").unwrap());
}

fn restore_env(original: Option<String>) {
    // SAFETY: Test code running under ENV_LOCK mutex.
    unsafe {
        match original {
            Some(value) => std::env::set_var(BOOT_ASSET_VERSION_ENV, value),
            None => std::env::remove_var(BOOT_ASSET_VERSION_ENV),
        }
    }
}
