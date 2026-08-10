//! App bundle detection, seeding, and boot asset provisioning.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use arcbox_api::{SetupPhase, SetupState};
use arcbox_core::{BootAssetProvider, Config};
use tracing::info;

/// Assets reconciled into the daemon data directory for this startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PreparedAssets {
    agent: PreparedAgent,
}

impl PreparedAssets {
    /// Returns where the staged `arcbox-agent` came from.
    pub(super) fn agent(self) -> PreparedAgent {
        self.agent
    }
}

/// Source of the staged `~/.arcbox/bin/arcbox-agent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PreparedAgent {
    /// The launched app bundle provided the staged agent.
    Bundle,
    /// The boot asset cache provided the staged agent because no bundle agent existed.
    BootCache,
    /// No agent was available from either source.
    Unavailable,
}

/// Reconciles all startup assets into `data_dir`.
///
/// Bundle contents are seeded first so Sparkle app updates refresh staged
/// binaries. Network/download fallback then fills any missing boot assets, and
/// the boot-cache agent is staged only if the bundle did not provide one.
pub(super) async fn prepare(
    config: &Config,
    setup_state: &Arc<SetupState>,
) -> Result<PreparedAssets> {
    let data_dir = &config.data_dir;
    let seed_data_dir = data_dir.clone();
    let bundle_seed = tokio::task::spawn_blocking(move || seed_from_bundle(&seed_data_dir))
        .await
        .context("bundle seed task panicked")?
        .context("bundle seed failed")?;

    ensure_boot_assets(config, setup_state).await?;

    let fallback_data_dir = data_dir.clone();
    let agent = tokio::task::spawn_blocking(move || {
        ensure_agent_binary_fallback(&fallback_data_dir, bundle_seed)
    })
    .await
    .context("agent fallback task panicked")?
    .context("agent fallback failed")?;

    Ok(PreparedAssets { agent })
}

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
///   bin/                                → host Docker CLI tools
///   {version}/{bin,kernel}/             → guest runtime transport source
/// Contents/Resources/bin/arcbox-agent   → ~/.arcbox/bin/arcbox-agent
/// Contents/Resources/bin/vm-agent      → ~/.arcbox/bin/vm-agent
/// ```
pub(super) fn seed_from_bundle(data_dir: &Path) -> Result<BundleSeed> {
    let Some(contents) = find_bundle_contents() else {
        return Ok(BundleSeed::default());
    };
    tracing::info!("App bundle detected: {}", contents.display());
    let mut seed = BundleSeed::default();

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
    if agent_src.exists() {
        seed.agent = seed_agent_from_bundle(&agent_src, data_dir)
            .context("Failed to seed arcbox-agent from bundle")?;
    }

    // 4. Sandbox microVM init (optional — sandboxes degrade without it).
    // The guest resolves it at /arcbox/bin/vm-agent via the VirtioFS
    // data-dir mount.
    let vm_agent_src = contents.join("Resources/bin/vm-agent");
    if vm_agent_src.exists() {
        seed_dir_files(
            &contents.join("Resources/bin"),
            &data_dir.join("bin"),
            &["vm-agent"],
            "sandbox vm-agent",
        );
    }

    Ok(seed)
}

/// Result of copying bundle-provided assets into the runtime data directory.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct BundleSeed {
    /// Whether the app bundle provided and successfully synced `arcbox-agent`.
    agent: AgentSeed,
}

impl BundleSeed {
    /// Returns whether the boot cache may be used to stage `arcbox-agent`.
    ///
    /// A bundle-provided agent is authoritative because it ships with the app
    /// version that just launched. Falling back after that would let an older
    /// boot cache overwrite the freshly staged bundle agent.
    pub(super) fn needs_agent_fallback(self) -> bool {
        self.agent == AgentSeed::Missing
    }
}

/// Source state for the staged `~/.arcbox/bin/arcbox-agent`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum AgentSeed {
    /// No bundle agent was available; the boot cache may be used as fallback.
    #[default]
    Missing,
    /// The bundle agent is the staged copy's authoritative source.
    Bundle,
}

fn seed_agent_from_bundle(agent_src: &Path, data_dir: &Path) -> Result<AgentSeed> {
    let agent_dst = data_dir.join("bin/arcbox-agent");
    match copy_if_changed(agent_src, &agent_dst) {
        Ok(true) => tracing::info!("Seeded arcbox-agent from bundle"),
        Ok(false) => tracing::debug!("arcbox-agent already up to date"),
        Err(e) => return Err(e).context("failed to copy bundle arcbox-agent"),
    }
    Ok(AgentSeed::Bundle)
}

/// Copies `src` to `dst` when `dst` is missing or differs from `src` by size or
/// modification time, returning whether a copy occurred.
///
/// The source mtime is mirrored onto the destination so a subsequent run can
/// recognise an up-to-date copy with a cheap `stat` instead of reading file
/// contents — important because the runtime tree is hundreds of MB and seeding
/// runs on every daemon start. Replacements are written to a temporary file in
/// the destination directory and then atomically renamed into place, so a killed
/// daemon cannot leave a partially-written staged binary at `dst`.
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
    copy_atomic(src, dst, src_mtime)?;
    Ok(true)
}

fn copy_atomic(src: &Path, dst: &Path, src_mtime: filetime::FileTime) -> std::io::Result<()> {
    let parent = dst.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;

    let tmp = temp_path_for(dst);
    let result = (|| -> std::io::Result<()> {
        std::fs::copy(src, &tmp)?;
        filetime::set_file_mtime(&tmp, src_mtime)?;
        std::fs::rename(&tmp, dst)?;
        Ok(())
    })();

    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

fn temp_path_for(dst: &Path) -> PathBuf {
    let parent = dst.parent().unwrap_or_else(|| Path::new("."));
    let file_name = dst
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("copy");
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    parent.join(format!(".{file_name}.{}.{}.tmp", std::process::id(), nonce))
}

/// Copies specific files from `src` to `dst`, refreshing any that changed.
fn seed_dir_files(src: &Path, dst: &Path, files: &[&str], label: &str) {
    let result = (|| -> std::io::Result<u32> {
        let mut count = 0u32;
        std::fs::create_dir_all(dst)?;
        for name in files {
            let s = src.join(name);
            if s.exists() && copy_if_changed(&s, &dst.join(name))? {
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
    config: &Config,
    setup_state: &Arc<SetupState>,
) -> Result<()> {
    let provider = BootAssetProvider::with_config(config.boot_asset_config())
        .context("Failed to create boot asset provider")?;

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

/// Installs the boot-cache agent only when bundle seeding did not provide one.
///
/// This fallback path is only used when the daemon is not running from an app
/// bundle or the bundle does not contain an agent. Bundle-provided agents are
/// authoritative and must not be overwritten by a possibly older boot cache.
pub(super) fn ensure_agent_binary_fallback(
    data_dir: &Path,
    bundle_seed: BundleSeed,
) -> Result<PreparedAgent> {
    if !bundle_seed.needs_agent_fallback() {
        return Ok(PreparedAgent::Bundle);
    }

    if ensure_agent_binary(data_dir)? {
        Ok(PreparedAgent::BootCache)
    } else {
        Ok(PreparedAgent::Unavailable)
    }
}

/// Installs the arcbox-agent binary from the downloaded boot cache.
///
/// Call [`ensure_agent_binary_fallback`] from startup code so bundle-provided
/// agents keep precedence over the boot cache.
pub(super) fn ensure_agent_binary(data_dir: &Path) -> Result<bool> {
    let agent_dest = data_dir.join("bin/arcbox-agent");

    let version = arcbox_core::boot_asset_version();
    let agent_src = data_dir.join(format!("boot/{version}/arcbox-agent"));
    if !agent_src.exists() {
        tracing::debug!(
            "Agent binary not found in boot cache at {}",
            agent_src.display()
        );
        return Ok(false);
    }

    if copy_if_changed(&agent_src, &agent_dest).context("Failed to install agent binary")? {
        info!("Agent binary installed from boot cache");
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::{
        AgentSeed, BundleSeed, PreparedAgent, copy_if_changed, ensure_agent_binary_fallback,
        seed_agent_from_bundle,
    };
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

    #[test]
    fn boot_cache_installs_agent_when_bundle_agent_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let cached_agent = dir.path().join(format!(
            "boot/{}/arcbox-agent",
            arcbox_core::boot_asset_version()
        ));
        fs::create_dir_all(cached_agent.parent().unwrap()).unwrap();
        fs::write(&cached_agent, b"boot-cache-agent").unwrap();

        let agent = ensure_agent_binary_fallback(dir.path(), BundleSeed::default()).unwrap();
        assert_eq!(agent, PreparedAgent::BootCache);

        let staged_agent = dir.path().join("bin/arcbox-agent");
        assert_eq!(fs::read(staged_agent).unwrap(), b"boot-cache-agent");
    }

    #[test]
    fn boot_cache_does_not_overwrite_bundle_agent() {
        let dir = tempfile::tempdir().unwrap();
        let bundle_agent = dir.path().join("bundle-agent");
        fs::write(&bundle_agent, b"bundle-agent").unwrap();
        let agent = seed_agent_from_bundle(&bundle_agent, dir.path()).unwrap();
        assert_eq!(agent, AgentSeed::Bundle);

        let cached_agent = dir.path().join(format!(
            "boot/{}/arcbox-agent",
            arcbox_core::boot_asset_version()
        ));
        fs::create_dir_all(cached_agent.parent().unwrap()).unwrap();
        fs::write(&cached_agent, b"older-boot-cache-agent").unwrap();

        let agent = ensure_agent_binary_fallback(
            dir.path(),
            BundleSeed {
                agent: AgentSeed::Bundle,
            },
        )
        .unwrap();
        assert_eq!(agent, PreparedAgent::Bundle);

        let staged_agent = dir.path().join("bin/arcbox-agent");
        assert_eq!(fs::read(staged_agent).unwrap(), b"bundle-agent");
    }
}
