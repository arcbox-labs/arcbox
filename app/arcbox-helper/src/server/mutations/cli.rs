//! CLI tool symlink management in `/usr/local/bin/`.
//!
//! Creates symlinks like `/usr/local/bin/docker` → `.app/Contents/MacOS/xbin/docker`
//! so Docker CLI tools from the app bundle are available system-wide.

use std::fs;
use std::os::unix::fs as unix_fs;
use std::path::Path;

use arcbox_constants::paths::is_arcbox_owned;
use arcbox_helper::validate::{CliName, CliTarget};

use crate::server::fs_root;

/// Default install prefix for system-wide CLI symlinks.
const CLI_BIN_DIR: &str = "/usr/local/bin";

/// Creates `/usr/local/bin/{name}` → `target`.
///
/// Idempotent: if the symlink already points to `target`, this is a no-op.
/// Only replaces existing symlinks that point into an ArcBox bundle.
/// Refuses to overwrite regular files or non-ArcBox symlinks.
///
/// `target` must be a **regular file** (not a symlink). Following a
/// user-writable symlink under `…/xbin/` would let `/usr/local/bin/docker`
/// resolve to an arbitrary path.
pub fn link(name: &CliName, target: &CliTarget) -> Result<(), String> {
    link_at(&fs_root::resolve(CLI_BIN_DIR), name, target)
}

/// Removes `/usr/local/bin/{name}` if it is a symlink pointing inside an ArcBox bundle.
///
/// Idempotent: returns Ok if already absent or not an ArcBox-owned symlink.
pub fn unlink(name: &CliName) -> Result<(), String> {
    unlink_at(&fs_root::resolve(CLI_BIN_DIR), name)
}

/// Testable implementation: operate under `bin_dir` instead of `/usr/local/bin`.
fn link_at(bin_dir: &Path, name: &CliName, target: &CliTarget) -> Result<(), String> {
    let link_path = bin_dir.join(name.as_str());
    let target_path = Path::new(target.as_str());

    ensure_safe_cli_target(target_path, target)?;

    match fs::symlink_metadata(&link_path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            let existing = fs::read_link(&link_path)
                .map_err(|e| format!("failed to read symlink {}: {e}", link_path.display()))?;
            if existing == target_path {
                return Ok(());
            }
            if !is_arcbox_owned(&existing) {
                return Err(format!(
                    "{} is a symlink to {} (not ArcBox-owned, not replacing)",
                    link_path.display(),
                    existing.display()
                ));
            }
            fs::remove_file(&link_path)
                .map_err(|e| format!("failed to remove {}: {e}", link_path.display()))?;
        }
        Ok(_) => {
            return Err(format!(
                "{} exists and is not a symlink (not replacing)",
                link_path.display()
            ));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(format!("failed to stat {}: {e}", link_path.display()));
        }
    }

    fs::create_dir_all(bin_dir)
        .map_err(|e| format!("failed to create {}: {e}", bin_dir.display()))?;

    unix_fs::symlink(target_path, &link_path).map_err(|e| {
        format!(
            "failed to create symlink {} -> {target}: {e}",
            link_path.display()
        )
    })
}

fn unlink_at(bin_dir: &Path, name: &CliName) -> Result<(), String> {
    let link_path = bin_dir.join(name.as_str());

    match fs::symlink_metadata(&link_path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            let target = fs::read_link(&link_path)
                .map_err(|e| format!("failed to read symlink {}: {e}", link_path.display()))?;
            if is_arcbox_owned(&target) {
                fs::remove_file(&link_path)
                    .map_err(|e| format!("failed to remove {}: {e}", link_path.display()))?;
            }
            Ok(())
        }
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("failed to stat {}: {e}", link_path.display())),
    }
}

/// Ensures `target_path` exists, is a regular file (not a symlink/dir), and —
/// after canonicalize — still lives under an ArcBox xbin path.
fn ensure_safe_cli_target(target_path: &Path, display: &CliTarget) -> Result<(), String> {
    let meta = fs::symlink_metadata(target_path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            format!("CLI target does not exist: {display}")
        } else {
            format!("failed to stat CLI target {display}: {e}")
        }
    })?;

    if meta.file_type().is_symlink() {
        return Err(format!(
            "CLI target '{display}' is a symlink (refusing to link through it)"
        ));
    }
    if !meta.file_type().is_file() {
        return Err(format!("CLI target '{display}' is not a regular file"));
    }

    // Re-check ownership on the canonical path so a cleverly named intermediate
    // component cannot slip past the string-level CliTarget / is_arcbox_owned
    // checks after resolution (e.g. bind mounts). Canonicalize requires the
    // final component to exist — we already verified that above.
    let canonical = fs::canonicalize(target_path)
        .map_err(|e| format!("failed to canonicalize CLI target {display}: {e}"))?;
    if !is_arcbox_owned(&canonical) {
        return Err(format!(
            "CLI target '{display}' resolves to {} which is not an ArcBox xbin path",
            canonical.display()
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{ensure_safe_cli_target, link_at, unlink_at};
    use arcbox_helper::validate::{CliName, CliTarget};
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::{Path, PathBuf};

    fn home_xbin_root(label: &str) -> Option<PathBuf> {
        let home = std::env::var_os("HOME")?;
        let root = PathBuf::from(home).join(format!(".arcbox-helper-test-{label}"));
        let _ = fs::remove_dir_all(&root);
        Some(root)
    }

    fn write_xbin_docker(root: &Path) -> CliTarget {
        let xbin = root.join("Apps/ArcBox.app/Contents/MacOS/xbin");
        fs::create_dir_all(&xbin).unwrap();
        let file = xbin.join("docker");
        fs::write(&file, b"#!/bin/sh\n").unwrap();
        format!(
            "{}/Apps/ArcBox.app/Contents/MacOS/xbin/docker",
            root.display()
        )
        .parse()
        .unwrap()
    }

    #[test]
    fn rejects_missing_target() {
        // Use a path that cannot exist on this machine (unique UUID segment).
        let display =
            "/Users/nobody/.arcbox-helper-missing-9f3c2a1b/Apps/ArcBox.app/Contents/MacOS/xbin/docker"
                .parse::<CliTarget>()
                .unwrap();
        let err = ensure_safe_cli_target(Path::new(display.as_str()), &display).unwrap_err();
        assert!(err.contains("does not exist"), "{err}");
    }

    #[test]
    fn rejects_symlink_target() {
        let dir = tempfile::tempdir().unwrap();
        let xbin = dir.path().join("ArcBox.app/Contents/MacOS/xbin");
        fs::create_dir_all(&xbin).unwrap();
        let real = dir.path().join("evil-bin");
        fs::write(&real, b"#!/bin/sh\n").unwrap();
        let link = xbin.join("docker");
        symlink(&real, &link).unwrap();

        let fake_display = "/Applications/ArcBox.app/Contents/MacOS/xbin/docker"
            .parse::<CliTarget>()
            .unwrap();
        let err = ensure_safe_cli_target(&link, &fake_display).unwrap_err();
        assert!(err.contains("symlink"), "{err}");
    }

    #[test]
    fn accepts_regular_file_under_arcbox_xbin_shape() {
        let Some(root) = home_xbin_root("cli-accept") else {
            return;
        };
        let target = write_xbin_docker(&root);
        ensure_safe_cli_target(Path::new(target.as_str()), &target).unwrap();
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn link_replaces_only_arcbox_owned_symlink() {
        let Some(root) = home_xbin_root("cli-link") else {
            return;
        };
        let target = write_xbin_docker(&root);
        let name = "docker".parse::<CliName>().unwrap();

        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bin");
        fs::create_dir_all(&bin).unwrap();

        // Existing foreign symlink — must not be replaced.
        symlink("/usr/local/bin/real-docker", bin.join("docker")).unwrap();
        let err = link_at(&bin, &name, &target).unwrap_err();
        assert!(err.contains("not ArcBox-owned"), "{err}");
        assert_eq!(
            fs::read_link(bin.join("docker")).unwrap(),
            PathBuf::from("/usr/local/bin/real-docker")
        );

        // Replace ArcBox-owned existing link.
        fs::remove_file(bin.join("docker")).unwrap();
        symlink(
            "/Applications/Old.app/Contents/MacOS/xbin/docker",
            bin.join("docker"),
        )
        .unwrap();
        link_at(&bin, &name, &target).unwrap();
        assert_eq!(
            fs::read_link(bin.join("docker")).unwrap(),
            Path::new(target.as_str())
        );

        // unlink removes ArcBox-owned only.
        unlink_at(&bin, &name).unwrap();
        assert!(!bin.join("docker").exists());

        // Foreign unlink is a no-op.
        symlink("/usr/local/bin/real-docker", bin.join("docker")).unwrap();
        unlink_at(&bin, &name).unwrap();
        assert!(
            bin.join("docker")
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink()
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn link_refuses_regular_file_at_destination() {
        let Some(root) = home_xbin_root("cli-reg") else {
            return;
        };
        let target = write_xbin_docker(&root);
        let name = "docker".parse::<CliName>().unwrap();

        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bin");
        fs::create_dir_all(&bin).unwrap();
        fs::write(bin.join("docker"), b"not a link").unwrap();

        let err = link_at(&bin, &name, &target).unwrap_err();
        assert!(err.contains("not a symlink"), "{err}");

        let _ = fs::remove_dir_all(&root);
    }
}
