//! Atomic materialization of guest runtime assets onto persistent storage.

#![allow(
    clippy::redundant_pub_crate,
    reason = "the materializer is shared inside the crate but is not public API"
)]

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context as _, Result, bail};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

const COMPLETE_MARKER: &str = ".manifest.sha256";
const COPY_BUFFER_SIZE: usize = 256 * 1024;

/// Inputs for materializing one immutable runtime generation.
pub(crate) struct MaterializeRequest<'a> {
    /// Verified boot manifest naming the source assets.
    pub manifest_path: &'a Path,
    /// VirtioFS source root containing `bin/` and `kernel/`.
    pub source_root: &'a Path,
    /// Raw Btrfs mount under which generations are stored.
    pub data_root: &'a Path,
    /// Stable symlink consumers execute through.
    pub stable_root: &'a Path,
    /// Immutable boot-asset generation.
    pub generation: &'a str,
    /// Manifest architecture key (`arm64` or `x86_64`).
    pub arch: &'a str,
}

/// Published local runtime generation.
#[derive(Debug)]
pub(crate) struct MaterializedRuntime {
    /// Generation-specific Btrfs directory.
    pub root: PathBuf,
    /// Whether an already-complete generation was reused.
    pub reused: bool,
    /// Number of current-architecture assets in the generation.
    pub asset_count: usize,
}

#[derive(Deserialize)]
struct RuntimeManifest {
    asset_version: String,
    #[serde(default)]
    binaries: Vec<ManifestBinary>,
}

#[derive(Deserialize)]
struct ManifestBinary {
    name: String,
    targets: std::collections::BTreeMap<String, ManifestTarget>,
    install_dir: Option<String>,
}

#[derive(Deserialize)]
struct ManifestTarget {
    sha256: String,
}

struct PlannedAsset {
    source: PathBuf,
    destination: PathBuf,
    sha256: String,
}

/// Copies the manifest's current-architecture assets to Btrfs and atomically
/// publishes the completed generation through `stable_root`.
pub(crate) fn materialize_runtime(request: &MaterializeRequest<'_>) -> Result<MaterializedRuntime> {
    validate_generation(request.generation)?;

    let manifest_bytes = fs::read(request.manifest_path)
        .with_context(|| format!("read runtime manifest {}", request.manifest_path.display()))?;
    let manifest: RuntimeManifest = serde_json::from_slice(&manifest_bytes)
        .with_context(|| format!("parse runtime manifest {}", request.manifest_path.display()))?;
    if manifest.asset_version != request.generation {
        bail!(
            "runtime manifest version {} does not match generation {}",
            manifest.asset_version,
            request.generation
        );
    }

    let manifest_sha256 = format!("{:x}", Sha256::digest(&manifest_bytes));
    let assets = plan_assets(&manifest, request.source_root, request.arch)?;
    let generations_root = request.data_root.join("runtime");
    let generation_root = generations_root.join(request.generation);

    fs::create_dir_all(&generations_root)
        .with_context(|| format!("create runtime cache {}", generations_root.display()))?;
    sync_directory(request.data_root)?;

    if generation_complete(&generation_root, &manifest_sha256, &assets) {
        publish_stable_link(request.stable_root, &generation_root)?;
        remove_old_generations(&generations_root, &generation_root)?;
        return Ok(MaterializedRuntime {
            root: generation_root,
            reused: true,
            asset_count: assets.len(),
        });
    }

    let temporary_root = create_staging_directory(&generations_root, request.generation)?;

    let staged = stage_generation(&temporary_root, &assets, &manifest_sha256);
    if let Err(error) = staged {
        let _ = remove_path(&temporary_root);
        return Err(error);
    }

    if let Err(error) = publish_generation(&temporary_root, &generation_root) {
        let _ = remove_path(&temporary_root);
        return Err(error);
    }
    sync_directory(&generations_root)?;
    publish_stable_link(request.stable_root, &generation_root)?;
    remove_old_generations(&generations_root, &generation_root)?;

    Ok(MaterializedRuntime {
        root: generation_root,
        reused: false,
        asset_count: assets.len(),
    })
}

fn plan_assets(
    manifest: &RuntimeManifest,
    source_root: &Path,
    arch: &str,
) -> Result<Vec<PlannedAsset>> {
    let mut destinations = HashSet::new();
    let mut assets = Vec::new();

    for binary in &manifest.binaries {
        let Some(target) = binary.targets.get(arch) else {
            continue;
        };
        validate_path_component(&binary.name, "runtime asset name")?;
        validate_sha256(&target.sha256, &binary.name)?;

        let install_dir = binary.install_dir.as_deref().unwrap_or("bin");
        validate_relative_path(install_dir, "runtime install directory")?;
        let relative = Path::new(install_dir).join(&binary.name);
        if !destinations.insert(relative.clone()) {
            bail!("duplicate runtime asset destination {}", relative.display());
        }
        assets.push(PlannedAsset {
            source: source_root.join(&relative),
            destination: relative,
            sha256: target.sha256.to_ascii_lowercase(),
        });
    }

    if assets.is_empty() {
        bail!("runtime manifest has no assets for architecture {arch}");
    }
    Ok(assets)
}

fn create_staging_directory(generations_root: &Path, generation: &str) -> Result<PathBuf> {
    static NEXT_STAGING_ID: AtomicU64 = AtomicU64::new(0);

    loop {
        let staging_id = NEXT_STAGING_ID.fetch_add(1, Ordering::Relaxed);
        let path = generations_root.join(format!(
            ".{generation}.{}.{}.tmp",
            std::process::id(),
            staging_id
        ));
        match fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("create runtime staging {}", path.display()));
            }
        }
    }
}

fn stage_generation(
    temporary_root: &Path,
    assets: &[PlannedAsset],
    manifest_sha256: &str,
) -> Result<()> {
    let mut asset_directories = HashSet::new();
    for asset in assets {
        let destination = temporary_root.join(&asset.destination);
        let parent = destination
            .parent()
            .context("runtime asset destination has no parent")?;
        fs::create_dir_all(parent)
            .with_context(|| format!("create runtime asset directory {}", parent.display()))?;
        let mut directory = parent;
        while directory != temporary_root {
            asset_directories.insert(directory.to_path_buf());
            directory = directory
                .parent()
                .context("runtime asset directory escaped staging root")?;
        }
        copy_verified(&asset.source, &destination, &asset.sha256)?;
    }
    let mut asset_directories = asset_directories.into_iter().collect::<Vec<_>>();
    asset_directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for directory in asset_directories {
        sync_directory(&directory)?;
    }

    let marker = temporary_root.join(COMPLETE_MARKER);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&marker)
        .with_context(|| format!("create runtime marker {}", marker.display()))?;
    writeln!(file, "{manifest_sha256}")?;
    file.sync_all()
        .with_context(|| format!("sync runtime marker {}", marker.display()))?;
    sync_directory(temporary_root)
}

fn copy_verified(source: &Path, destination: &Path, expected_sha256: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(source)
        .with_context(|| format!("inspect runtime source {}", source.display()))?;
    if !metadata.file_type().is_file() {
        bail!("runtime source is not a regular file: {}", source.display());
    }
    if metadata.permissions().mode() & 0o111 == 0 {
        bail!("runtime source is not executable: {}", source.display());
    }

    let mut input =
        File::open(source).with_context(|| format!("open runtime source {}", source.display()))?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .with_context(|| format!("create runtime asset {}", destination.display()))?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; COPY_BUFFER_SIZE];

    loop {
        let read = input
            .read(&mut buffer)
            .with_context(|| format!("read runtime source {}", source.display()))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
        output
            .write_all(&buffer[..read])
            .with_context(|| format!("write runtime asset {}", destination.display()))?;
    }

    let actual_sha256 = format!("{:x}", digest.finalize());
    if actual_sha256 != expected_sha256 {
        bail!(
            "runtime asset SHA-256 mismatch for {}: expected {}, got {}",
            source.display(),
            expected_sha256,
            actual_sha256
        );
    }

    output
        .set_permissions(metadata.permissions())
        .with_context(|| format!("set runtime permissions {}", destination.display()))?;
    output
        .sync_all()
        .with_context(|| format!("sync runtime asset {}", destination.display()))
}

fn generation_complete(
    generation_root: &Path,
    manifest_sha256: &str,
    assets: &[PlannedAsset],
) -> bool {
    let marker_matches = fs::read_to_string(generation_root.join(COMPLETE_MARKER))
        .is_ok_and(|marker| marker.trim() == manifest_sha256);
    marker_matches
        && assets.iter().all(|asset| {
            let path = generation_root.join(&asset.destination);
            fs::symlink_metadata(&path).is_ok_and(|metadata| {
                metadata.file_type().is_file()
                    && metadata.permissions().mode() & 0o111 != 0
                    && sha256_file(&path).is_ok_and(|digest| digest == asset.sha256)
            })
        })
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file =
        File::open(path).with_context(|| format!("open runtime asset {}", path.display()))?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; COPY_BUFFER_SIZE];
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("read runtime asset {}", path.display()))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn publish_generation(temporary_root: &Path, generation_root: &Path) -> Result<()> {
    match fs::symlink_metadata(generation_root) {
        Ok(_) => replace_generation(temporary_root, generation_root),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::rename(temporary_root, generation_root).with_context(|| {
                format!(
                    "publish runtime generation {} -> {}",
                    temporary_root.display(),
                    generation_root.display()
                )
            })
        }
        Err(error) => Err(error).with_context(|| {
            format!(
                "inspect runtime generation before publish {}",
                generation_root.display()
            )
        }),
    }
}

#[cfg(target_os = "linux")]
fn replace_generation(temporary_root: &Path, generation_root: &Path) -> Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt as _;

    let temporary = CString::new(temporary_root.as_os_str().as_bytes())
        .context("runtime staging path contains NUL")?;
    let generation = CString::new(generation_root.as_os_str().as_bytes())
        .context("runtime generation path contains NUL")?;
    // SAFETY: both C strings are NUL-terminated and remain alive for the
    // syscall. `SYS_renameat2(RENAME_EXCHANGE)` atomically swaps two existing
    // paths on the same Btrfs mount; the kernel does not retain either pointer.
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            temporary.as_ptr(),
            libc::AT_FDCWD,
            generation.as_ptr(),
            libc::RENAME_EXCHANGE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error()).with_context(|| {
            format!(
                "atomically replace runtime generation {} with {}",
                generation_root.display(),
                temporary_root.display()
            )
        })
    }
}

#[cfg(not(target_os = "linux"))]
fn replace_generation(temporary_root: &Path, generation_root: &Path) -> Result<()> {
    let retired_root = temporary_root.with_extension("old");
    fs::rename(generation_root, &retired_root).with_context(|| {
        format!(
            "retire runtime generation {} -> {}",
            generation_root.display(),
            retired_root.display()
        )
    })?;
    if let Err(publish_error) = fs::rename(temporary_root, generation_root) {
        if let Err(restore_error) = fs::rename(&retired_root, generation_root) {
            bail!(
                "publish replacement runtime generation failed: {publish_error}; \
                 restoring previous generation also failed: {restore_error}"
            );
        }
        return Err(publish_error).context("publish replacement runtime generation");
    }
    remove_path(&retired_root)
}

fn publish_stable_link(stable_root: &Path, generation_root: &Path) -> Result<()> {
    let parent = stable_root
        .parent()
        .context("stable runtime path has no parent")?;
    fs::create_dir_all(parent)
        .with_context(|| format!("create stable runtime parent {}", parent.display()))?;

    if let Ok(metadata) = fs::symlink_metadata(stable_root) {
        if !metadata.file_type().is_symlink() {
            bail!(
                "stable runtime path is not a symlink: {}",
                stable_root.display()
            );
        }
        if fs::read_link(stable_root).is_ok_and(|target| target == generation_root) {
            return Ok(());
        }
    }

    let temporary_link = parent.join(format!(".runtime-link.{}.tmp", std::process::id()));
    if fs::symlink_metadata(&temporary_link).is_ok() {
        fs::remove_file(&temporary_link)
            .with_context(|| format!("remove stale runtime link {}", temporary_link.display()))?;
    }
    symlink(generation_root, &temporary_link).with_context(|| {
        format!(
            "create runtime link {} -> {}",
            temporary_link.display(),
            generation_root.display()
        )
    })?;
    fs::rename(&temporary_link, stable_root).with_context(|| {
        format!(
            "publish runtime link {} -> {}",
            stable_root.display(),
            generation_root.display()
        )
    })?;
    sync_directory(parent)
}

fn remove_old_generations(generations_root: &Path, current: &Path) -> Result<()> {
    for entry in fs::read_dir(generations_root)
        .with_context(|| format!("list runtime generations {}", generations_root.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path == current {
            continue;
        }
        remove_path(&path)
            .with_context(|| format!("remove old runtime generation {}", path.display()))?;
    }
    sync_directory(generations_root)
}

fn remove_path(path: &Path) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| format!("inspect runtime path {}", path.display()));
        }
    };
    if metadata.file_type().is_dir() {
        fs::remove_dir_all(path)
            .with_context(|| format!("remove runtime directory {}", path.display()))
    } else {
        fs::remove_file(path).with_context(|| format!("remove runtime path {}", path.display()))
    }
}

fn validate_generation(value: &str) -> Result<()> {
    let valid = value != "."
        && value != ".."
        && !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'));
    if !valid {
        bail!("runtime generation is invalid: {value:?}");
    }
    Ok(())
}

fn validate_path_component(value: &str, label: &str) -> Result<()> {
    let mut components = Path::new(value).components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        bail!("{label} must be one relative path component: {value:?}");
    }
    Ok(())
}

fn validate_relative_path(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || Path::new(value)
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        bail!("{label} must be a safe relative path: {value:?}");
    }
    Ok(())
}

fn validate_sha256(value: &str, name: &str) -> Result<()> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("runtime asset {name} has an invalid SHA-256 digest");
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .with_context(|| format!("open directory for sync {}", path.display()))?
        .sync_all()
        .with_context(|| format!("sync directory {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn write_executable(path: &Path, bytes: &[u8]) -> String {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
        let mut permissions = fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).unwrap();
        format!("{:x}", Sha256::digest(bytes))
    }

    fn write_manifest(path: &Path, generation: &str, dockerd_sha: &str, kernel_sha: &str) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let manifest = json!({
            "asset_version": generation,
            "binaries": [
                {
                    "name": "dockerd",
                    "version": "1",
                    "targets": { "arm64": { "path": "unused", "sha256": dockerd_sha } }
                },
                {
                    "name": "vmlinux",
                    "version": "1",
                    "install_dir": "kernel",
                    "targets": { "arm64": { "path": "unused", "sha256": kernel_sha } }
                },
                {
                    "name": "x86-only",
                    "version": "1",
                    "targets": {
                        "x86_64": {
                            "path": "unused",
                            "sha256": "0".repeat(64)
                        }
                    }
                }
            ]
        });
        fs::write(path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    }

    #[test]
    fn materializes_only_current_arch_and_atomically_switches_generation() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let data = temp.path().join("data");
        let stable = temp.path().join("run/runtime");
        let dockerd_sha = write_executable(&source.join("bin/dockerd"), b"dockerd");
        let kernel_sha = write_executable(&source.join("kernel/vmlinux"), b"kernel");

        for generation in ["0.6.13", "0.6.14"] {
            let manifest = temp.path().join(format!("boot/{generation}/manifest.json"));
            write_manifest(&manifest, generation, &dockerd_sha, &kernel_sha);
            let result = materialize_runtime(&MaterializeRequest {
                manifest_path: &manifest,
                source_root: &source,
                data_root: &data,
                stable_root: &stable,
                generation,
                arch: "arm64",
            })
            .unwrap();

            assert_eq!(result.asset_count, 2);
            assert!(result.root.join("bin/dockerd").is_file());
            assert!(result.root.join("kernel/vmlinux").is_file());
            assert!(!result.root.join("bin/x86-only").exists());
            assert_eq!(fs::read_link(&stable).unwrap(), result.root);
            if generation == "0.6.13" {
                fs::create_dir_all(data.join("runtime/.crashed.tmp")).unwrap();
            }
            if generation == "0.6.14" {
                assert!(!data.join("runtime/0.6.13").exists());
                assert!(!data.join("runtime/.crashed.tmp").exists());
            }
        }
        let entries = fs::read_dir(data.join("runtime"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert_eq!(entries, [std::ffi::OsString::from("0.6.14")]);
    }

    #[test]
    fn reuses_complete_generation_after_sources_are_removed() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let data = temp.path().join("data");
        let stable = temp.path().join("run/runtime");
        let dockerd_sha = write_executable(&source.join("bin/dockerd"), b"dockerd");
        let kernel_sha = write_executable(&source.join("kernel/vmlinux"), b"kernel");
        let manifest = temp.path().join("boot/0.6.13/manifest.json");
        write_manifest(&manifest, "0.6.13", &dockerd_sha, &kernel_sha);
        let request = MaterializeRequest {
            manifest_path: &manifest,
            source_root: &source,
            data_root: &data,
            stable_root: &stable,
            generation: "0.6.13",
            arch: "arm64",
        };

        assert!(!materialize_runtime(&request).unwrap().reused);
        fs::remove_dir_all(&source).unwrap();
        let reused = materialize_runtime(&request).unwrap();

        assert!(reused.reused);
        assert!(reused.root.join("bin/dockerd").is_file());
        assert_eq!(fs::read_link(&stable).unwrap(), reused.root);
    }

    #[test]
    fn repairs_a_locally_tampered_generation_from_verified_sources() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let data = temp.path().join("data");
        let stable = temp.path().join("run/runtime");
        let dockerd_sha = write_executable(&source.join("bin/dockerd"), b"dockerd");
        let kernel_sha = write_executable(&source.join("kernel/vmlinux"), b"kernel");
        let manifest = temp.path().join("boot/0.6.13/manifest.json");
        write_manifest(&manifest, "0.6.13", &dockerd_sha, &kernel_sha);
        let request = MaterializeRequest {
            manifest_path: &manifest,
            source_root: &source,
            data_root: &data,
            stable_root: &stable,
            generation: "0.6.13",
            arch: "arm64",
        };

        let initial = materialize_runtime(&request).unwrap();
        fs::write(initial.root.join("bin/dockerd"), b"locally tampered").unwrap();
        let repaired = materialize_runtime(&request).unwrap();

        assert!(!repaired.reused);
        assert_eq!(
            fs::read(repaired.root.join("bin/dockerd")).unwrap(),
            b"dockerd"
        );
        assert_eq!(fs::read_link(&stable).unwrap(), repaired.root);
    }

    #[test]
    fn failed_same_generation_replacement_preserves_previous_runtime() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let data = temp.path().join("data");
        let stable = temp.path().join("run/runtime");
        let dockerd_sha = write_executable(&source.join("bin/dockerd"), b"dockerd-v1");
        let kernel_sha = write_executable(&source.join("kernel/vmlinux"), b"kernel");
        let manifest = temp.path().join("boot/0.6.13/manifest.json");
        write_manifest(&manifest, "0.6.13", &dockerd_sha, &kernel_sha);
        let request = MaterializeRequest {
            manifest_path: &manifest,
            source_root: &source,
            data_root: &data,
            stable_root: &stable,
            generation: "0.6.13",
            arch: "arm64",
        };

        let initial = materialize_runtime(&request).unwrap();
        write_executable(&source.join("bin/dockerd"), b"incomplete-v2");
        let expected_v2 = format!("{:x}", Sha256::digest(b"dockerd-v2"));
        write_manifest(&manifest, "0.6.13", &expected_v2, &kernel_sha);

        let error = materialize_runtime(&request).unwrap_err();

        assert!(error.to_string().contains("SHA-256 mismatch"));
        assert_eq!(
            fs::read(initial.root.join("bin/dockerd")).unwrap(),
            b"dockerd-v1"
        );
        assert_eq!(fs::read_link(&stable).unwrap(), initial.root);
    }

    #[test]
    fn checksum_failure_publishes_neither_generation_nor_link() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let data = temp.path().join("data");
        let stable = temp.path().join("run/runtime");
        let kernel_sha = write_executable(&source.join("kernel/vmlinux"), b"kernel");
        write_executable(&source.join("bin/dockerd"), b"tampered");
        let manifest = temp.path().join("boot/0.6.13/manifest.json");
        write_manifest(&manifest, "0.6.13", &"0".repeat(64), &kernel_sha);

        let error = materialize_runtime(&MaterializeRequest {
            manifest_path: &manifest,
            source_root: &source,
            data_root: &data,
            stable_root: &stable,
            generation: "0.6.13",
            arch: "arm64",
        })
        .unwrap_err();

        assert!(error.to_string().contains("SHA-256 mismatch"));
        assert!(!data.join("runtime/0.6.13").exists());
        assert_eq!(fs::read_dir(data.join("runtime")).unwrap().count(), 0);
        assert!(!stable.exists());
    }
}
