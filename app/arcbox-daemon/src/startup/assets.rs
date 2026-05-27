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
/// bundle so the daemon can start without network on first launch.
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
    if agent_src.exists() && !agent_dst.exists() {
        if let Err(e) = (|| -> std::io::Result<()> {
            std::fs::create_dir_all(agent_dst.parent().unwrap())?;
            std::fs::copy(&agent_src, &agent_dst)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&agent_dst, std::fs::Permissions::from_mode(0o755))?;
            }
            Ok(())
        })() {
            tracing::warn!("Failed to seed agent from bundle: {e}");
        } else {
            tracing::info!("Seeded arcbox-agent from bundle");
        }
    }
}

/// Copies specific files from `src` to `dst`, skipping those already present.
fn seed_dir_files(src: &Path, dst: &Path, files: &[&str], label: &str) {
    if let Err(e) = (|| -> std::io::Result<()> {
        std::fs::create_dir_all(dst)?;
        for name in files {
            let s = src.join(name);
            let d = dst.join(name);
            if s.exists() && !d.exists() {
                std::fs::copy(&s, &d)?;
            }
        }
        Ok(())
    })() {
        tracing::warn!("Failed to seed {label} from bundle: {e}");
    } else {
        tracing::info!("Seeded {label} from bundle");
    }
}

/// Recursively copies a directory tree, skipping files already present.
fn seed_dir_recursive(src: &Path, dst: &Path, label: &str) {
    let result = (|| -> std::io::Result<u32> {
        let mut count = 0u32;
        for entry in walkdir(src) {
            let (rel, is_dir) = entry?;
            let d = dst.join(&rel);
            if is_dir {
                std::fs::create_dir_all(&d)?;
            } else if !d.exists() {
                if let Some(parent) = d.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::copy(src.join(&rel), &d)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    // Preserve source executable bits without broadening.
                    let src_mode = std::fs::metadata(src.join(&rel))?.permissions().mode();
                    if src_mode & 0o111 != 0 {
                        let dst_mode = std::fs::metadata(&d)?.permissions().mode();
                        let new_mode = (dst_mode & !0o111) | (src_mode & 0o111);
                        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(new_mode))?;
                    }
                }
                count += 1;
            }
        }
        Ok(count)
    })();

    match result {
        Ok(0) => tracing::debug!("{label}: already seeded"),
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

/// Copies the arcbox-agent binary from the boot asset cache to the daemon's
/// bin directory if it is not already present.
pub(super) fn ensure_agent_binary(data_dir: &Path) -> Result<()> {
    let agent_dest = data_dir.join("bin/arcbox-agent");
    if agent_dest.exists() {
        return Ok(());
    }

    let version = arcbox_core::boot_asset_version();
    let agent_src = data_dir.join(format!("boot/{version}/arcbox-agent"));
    if !agent_src.exists() {
        tracing::debug!(
            "Agent binary not found in boot cache at {}",
            agent_src.display()
        );
        return Ok(());
    }

    std::fs::create_dir_all(agent_dest.parent().unwrap())
        .context("Failed to create agent bin directory")?;
    std::fs::copy(&agent_src, &agent_dest).context("Failed to copy agent binary")?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&agent_dest, std::fs::Permissions::from_mode(0o755))
            .context("Failed to set agent binary permissions")?;
    }

    info!("Agent binary installed from boot cache");
    Ok(())
}
