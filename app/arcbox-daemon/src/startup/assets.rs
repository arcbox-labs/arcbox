//! App bundle detection, seeding, and boot asset provisioning.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use arcbox_api::{SetupPhase, SetupState};
use arcbox_core::BootAssetProvider;
use tracing::info;

/// Returns the `Contents/` directory if the daemon is running inside an app bundle.
///
/// Finds the main app bundle's `Contents/` directory by walking up from the
/// daemon executable. Handles both legacy (`Contents/Helpers/`) and current
/// (`Contents/Frameworks/daemon.app/Contents/MacOS/`) layouts.
pub fn find_bundle_contents() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    // Walk up from the daemon executable to find the main app's Contents/.
    // Two possible layouts:
    //   Legacy:  .app/Contents/Helpers/com.arcboxlabs.desktop.daemon
    //   Current: .app/Contents/Frameworks/daemon.app/Contents/MacOS/daemon
    let mut dir = exe.parent()?;
    loop {
        let contents = dir;
        if contents.join("Resources").is_dir() && contents.join("Info.plist").exists() {
            // Make sure this is the *main* app's Contents, not the daemon
            // bundle's own Contents (which has no Resources/assets/).
            if contents.join("MacOS").join("ArcBox").exists() {
                return Some(contents.to_path_buf());
            }
        }
        dir = contents.parent()?;
    }
}

/// Seeds all assets from the app bundle to `~/.arcbox/` if available.
///
/// Copies boot assets, runtime binaries, and the agent binary from the
/// bundle so the daemon can start without network on first launch. Files are
/// refreshed whenever the bundle's copy differs (see [`copy_if_changed`]), so a
/// staged binary can't go stale across an app update.
///
/// Bundle layout:
/// ```text
/// Contents/Resources/assets/{version}/  → ~/.arcbox/boot/{version}/
/// Contents/Resources/runtime/           → ~/.arcbox/runtime/
/// Contents/Resources/bin/arcbox-agent   → ~/.arcbox/bin/arcbox-agent
/// ```
pub(super) fn seed_from_bundle(data_dir: &Path) {
    let Some(contents) = find_bundle_contents() else {
        return;
    };
    tracing::info!("App bundle detected: {}", contents.display());

    // 1. Boot assets: kernel, rootfs, manifest.
    let version = arcbox_core::boot_asset_version();
    let boot_dst = data_dir.join(format!("boot/{version}"));
    let boot_src = contents.join(format!("Resources/assets/{version}"));
    if boot_src.join("manifest.json").exists() {
        seed_dir_files(
            &boot_src,
            &boot_dst,
            &["manifest.json", "kernel", "rootfs.erofs"],
            "boot assets",
        );
    }

    // 2. Runtime binaries: dockerd, containerd, runc, etc.
    let runtime_src = contents.join("Resources/runtime");
    let runtime_dst = data_dir.join("runtime");
    if runtime_src.is_dir() {
        seed_dir_recursive(&runtime_src, &runtime_dst, "runtime binaries");
    }

    // 3. Agent binary.
    let agent_src = contents.join("Resources/bin/arcbox-agent");
    let agent_dst = data_dir.join("bin/arcbox-agent");
    if agent_src.exists() {
        match copy_if_changed(&agent_src, &agent_dst) {
            Ok(true) => tracing::info!("Seeded arcbox-agent from bundle"),
            Ok(false) => tracing::debug!("arcbox-agent already up to date"),
            Err(e) => tracing::warn!("Failed to seed agent from bundle: {e}"),
        }
    }
}

/// Copies `src` to `dst` when `dst` is missing or differs from `src` by size or
/// modification time, returning whether a copy occurred.
///
/// The source mtime is mirrored onto the destination so a subsequent run can
/// recognise an up-to-date copy with a cheap `stat` instead of reading file
/// contents — important because the runtime tree is hundreds of MB and seeding
/// runs on every daemon start. `std::fs::copy` carries over the source's
/// permission bits (including the executable bit), so binaries stay runnable.
fn copy_if_changed(src: &Path, dst: &Path) -> std::io::Result<bool> {
    let src_meta = std::fs::metadata(src)?;
    let src_mtime = filetime::FileTime::from_last_modification_time(&src_meta);
    if let Ok(dst_meta) = std::fs::metadata(dst) {
        if dst_meta.len() == src_meta.len()
            && filetime::FileTime::from_last_modification_time(&dst_meta) == src_mtime
        {
            return Ok(false);
        }
    }
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::copy(src, dst)?;
    filetime::set_file_mtime(dst, src_mtime)?;
    Ok(true)
}

/// Copies specific files from `src` to `dst`, refreshing any that changed.
fn seed_dir_files(src: &Path, dst: &Path, files: &[&str], label: &str) {
    if let Err(e) = (|| -> std::io::Result<()> {
        std::fs::create_dir_all(dst)?;
        for name in files {
            let s = src.join(name);
            if s.exists() {
                copy_if_changed(&s, &dst.join(name))?;
            }
        }
        Ok(())
    })() {
        tracing::warn!("Failed to seed {label} from bundle: {e}");
    } else {
        tracing::info!("Seeded {label} from bundle");
    }
}

/// Recursively copies a directory tree, refreshing any files that changed.
fn seed_dir_recursive(src: &Path, dst: &Path, label: &str) {
    let result = (|| -> std::io::Result<u32> {
        let mut count = 0u32;
        for entry in walkdir(src) {
            let (rel, is_dir) = entry?;
            let d = dst.join(&rel);
            if is_dir {
                std::fs::create_dir_all(&d)?;
            } else if copy_if_changed(&src.join(&rel), &d)? {
                count += 1;
            }
        }
        Ok(count)
    })();

    match result {
        Ok(0) => tracing::debug!("{label}: already up to date"),
        Ok(n) => tracing::info!("Seeded {n} {label} from bundle"),
        Err(e) => tracing::warn!("Failed to seed {label} from bundle: {e}"),
    }
}

/// Simple recursive directory walker yielding `(relative_path, is_dir)`.
fn walkdir(root: &Path) -> impl Iterator<Item = std::io::Result<(PathBuf, bool)>> {
    let mut stack = vec![PathBuf::new()];
    let root = root.to_path_buf();
    std::iter::from_fn(move || {
        while let Some(rel) = stack.pop() {
            let abs = root.join(&rel);
            let Ok(meta) = std::fs::metadata(&abs) else {
                continue;
            };
            if meta.is_dir() {
                match std::fs::read_dir(&abs) {
                    Ok(entries) => {
                        for entry in entries.flatten() {
                            if let Ok(name) = entry.file_name().into_string() {
                                stack.push(rel.join(name));
                            }
                        }
                    }
                    Err(e) => return Some(Err(e)),
                }
                if !rel.as_os_str().is_empty() {
                    return Some(Ok((rel, true)));
                }
            } else {
                return Some(Ok((rel, false)));
            }
        }
        None
    })
}

/// Downloads kernel and rootfs if not already cached. Sets the setup phase to
/// `DownloadingAssets` while the download is in progress.
pub(super) async fn ensure_boot_assets(
    data_dir: &Path,
    setup_state: &Arc<SetupState>,
) -> Result<()> {
    let cache_dir = data_dir.join("boot");
    let provider =
        BootAssetProvider::new(cache_dir).context("Failed to create boot asset provider")?;

    if provider.is_cached() {
        tracing::debug!("Boot assets already cached");
        return Ok(());
    }

    setup_state.set_phase(SetupPhase::DownloadingAssets, "Downloading boot assets...");
    provider
        .get_assets_with_progress(Some(Box::new(|p| {
            tracing::info!(
                name = %p.name,
                current = p.current,
                total = p.total,
                "Boot asset progress: {:?}",
                p.phase
            );
        })))
        .await
        .context("Failed to download boot assets")?;

    info!("Boot assets downloaded");
    Ok(())
}

/// Installs the arcbox-agent binary from the downloaded boot cache, refreshing
/// it if the cached copy differs. This is the fallback path for non-bundle
/// installs; bundle installs are handled by [`seed_from_bundle`].
pub(super) fn ensure_agent_binary(data_dir: &Path) -> Result<()> {
    let agent_dest = data_dir.join("bin/arcbox-agent");

    let version = arcbox_core::boot_asset_version();
    let agent_src = data_dir.join(format!("boot/{version}/arcbox-agent"));
    if !agent_src.exists() {
        tracing::debug!(
            "Agent binary not found in boot cache at {}",
            agent_src.display()
        );
        return Ok(());
    }

    if copy_if_changed(&agent_src, &agent_dest).context("Failed to install agent binary")? {
        info!("Agent binary installed from boot cache");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::copy_if_changed;
    use std::fs;

    #[test]
    fn copies_when_missing_then_skips_when_identical() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        let dst = dir.path().join("nested/dst");
        fs::write(&src, b"v1").unwrap();

        // Destination missing → copied.
        assert!(copy_if_changed(&src, &dst).unwrap());
        assert_eq!(fs::read(&dst).unwrap(), b"v1");

        // Unchanged source → skipped (mtime mirrored on the first copy).
        assert!(!copy_if_changed(&src, &dst).unwrap());
    }

    #[test]
    fn recopies_when_source_content_changes() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        let dst = dir.path().join("dst");
        fs::write(&src, b"v1").unwrap();
        assert!(copy_if_changed(&src, &dst).unwrap());

        // A different build differs in size and/or mtime → refreshed.
        fs::write(&src, b"v2-larger").unwrap();
        let newer = filetime::FileTime::from_unix_time(
            filetime::FileTime::from_last_modification_time(&fs::metadata(&src).unwrap())
                .unix_seconds()
                + 5,
            0,
        );
        filetime::set_file_mtime(&src, newer).unwrap();
        assert!(copy_if_changed(&src, &dst).unwrap());
        assert_eq!(fs::read(&dst).unwrap(), b"v2-larger");
    }

    #[cfg(unix)]
    #[test]
    fn preserves_executable_bit() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("bin");
        let dst = dir.path().join("bin-copy");
        fs::write(&src, b"#!/bin/sh\n").unwrap();
        fs::set_permissions(&src, fs::Permissions::from_mode(0o755)).unwrap();

        copy_if_changed(&src, &dst).unwrap();

        let mode = fs::metadata(&dst).unwrap().permissions().mode();
        assert_ne!(mode & 0o111, 0, "executable bit should be preserved");
    }
}
