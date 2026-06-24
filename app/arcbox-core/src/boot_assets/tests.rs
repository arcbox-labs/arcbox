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

fn restore_env(original: Option<String>) {
    // SAFETY: Test code running under ENV_LOCK mutex.
    unsafe {
        match original {
            Some(value) => std::env::set_var(BOOT_ASSET_VERSION_ENV, value),
            None => std::env::remove_var(BOOT_ASSET_VERSION_ENV),
        }
    }
}
