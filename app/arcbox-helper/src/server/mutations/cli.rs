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

fn link_at(bin_dir: &Path, name: &CliName, target: &CliTarget) -> Result<(), String> {
    let link_path = bin_dir.join(name.as_str());
    let target_path = Path::new(target.as_str());

    ensure_safe_cli_target(target_path, target)?;
    if prepare_symlink_slot(&link_path, target_path, is_arcbox_owned)? == Slot::AlreadyCorrect {
        return Ok(());
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
    remove_owned_symlink(&bin_dir.join(name.as_str()), is_arcbox_owned)
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

    // Re-check ownership on the canonical path so resolution (bind mounts,
    // etc.) cannot slip past the string-level CliTarget check.
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

/// Outcome of inspecting a destination path before creating a managed symlink.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Slot {
    /// Nothing at the path (or we cleared our stale link) — caller should create.
    Ready,
    /// Already points at the desired target — no-op.
    AlreadyCorrect,
}

/// Shared "inspect destination before creating a managed symlink" step.
///
/// - missing → [`Slot::Ready`]
/// - already points at `want` → [`Slot::AlreadyCorrect`]
/// - symlink owned by us (`is_ours`) → remove, then [`Slot::Ready`]
/// - foreign symlink / regular file → error
pub(super) fn prepare_symlink_slot(
    link_path: &Path,
    want: &Path,
    is_ours: impl Fn(&Path) -> bool,
) -> Result<Slot, String> {
    let display = link_path.display();
    match fs::symlink_metadata(link_path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            let existing = fs::read_link(link_path)
                .map_err(|e| format!("failed to read symlink {display}: {e}"))?;
            if existing == want {
                return Ok(Slot::AlreadyCorrect);
            }
            if !is_ours(&existing) {
                return Err(format!(
                    "{display} is a symlink to {} (not ArcBox-owned, not replacing)",
                    existing.display()
                ));
            }
            fs::remove_file(link_path).map_err(|e| format!("failed to remove {display}: {e}"))?;
            Ok(Slot::Ready)
        }
        Ok(_) => Err(format!(
            "{display} exists and is not a symlink (not replacing)"
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Slot::Ready),
        Err(e) => Err(format!("failed to stat {display}: {e}")),
    }
}

/// Removes `link_path` only when it is a symlink whose target passes `is_ours`.
pub(super) fn remove_owned_symlink(
    link_path: &Path,
    is_ours: impl Fn(&Path) -> bool,
) -> Result<(), String> {
    let display = link_path.display();
    match fs::symlink_metadata(link_path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            let target = fs::read_link(link_path)
                .map_err(|e| format!("failed to read symlink {display}: {e}"))?;
            if is_ours(&target) {
                fs::remove_file(link_path)
                    .map_err(|e| format!("failed to remove {display}: {e}"))?;
            }
            Ok(())
        }
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("failed to stat {display}: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::{Slot, ensure_safe_cli_target, prepare_symlink_slot, remove_owned_symlink};
    use arcbox_constants::paths::is_arcbox_owned;
    use arcbox_helper::validate::CliTarget;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::{Path, PathBuf};

    #[test]
    fn rejects_missing_target() {
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
    fn prepare_slot_preserves_foreign_and_replaces_ours() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("docker");
        let want = Path::new("/Applications/ArcBox.app/Contents/MacOS/xbin/docker");

        symlink("/usr/local/bin/real-docker", &link).unwrap();
        let err = prepare_symlink_slot(&link, want, is_arcbox_owned).unwrap_err();
        assert!(err.contains("not ArcBox-owned"), "{err}");
        assert_eq!(
            fs::read_link(&link).unwrap(),
            PathBuf::from("/usr/local/bin/real-docker")
        );

        fs::remove_file(&link).unwrap();
        symlink("/Applications/Old.app/Contents/MacOS/xbin/docker", &link).unwrap();
        assert_eq!(
            prepare_symlink_slot(&link, want, is_arcbox_owned).unwrap(),
            Slot::Ready
        );
        assert!(!link.exists(), "owned stale link should be cleared");

        // Idempotent: already correct.
        symlink(want, &link).unwrap();
        assert_eq!(
            prepare_symlink_slot(&link, want, is_arcbox_owned).unwrap(),
            Slot::AlreadyCorrect
        );
        assert_eq!(fs::read_link(&link).unwrap(), want);
    }

    #[test]
    fn remove_owned_only() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("docker");

        symlink("/Applications/ArcBox.app/Contents/MacOS/xbin/docker", &link).unwrap();
        remove_owned_symlink(&link, is_arcbox_owned).unwrap();
        assert!(!link.exists());

        symlink("/usr/local/bin/real-docker", &link).unwrap();
        remove_owned_symlink(&link, is_arcbox_owned).unwrap();
        assert!(link.symlink_metadata().unwrap().file_type().is_symlink());
    }
}
