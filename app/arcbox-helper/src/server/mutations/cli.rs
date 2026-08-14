//! CLI tool symlink management in `/usr/local/bin/`.
//!
//! Creates symlinks like `/usr/local/bin/docker` → `.app/Contents/MacOS/xbin/docker`
//! so Docker CLI tools from the app bundle are available system-wide.

use std::fs;
use std::os::unix::fs as unix_fs;
use std::path::Path;

use arcbox_constants::paths::is_arcbox_owned;
use arcbox_helper::HelperError;
use arcbox_helper::validate::{CliName, CliTarget};

use crate::server::fs_root;

/// Default install prefix for system-wide CLI symlinks.
const CLI_BIN_DIR: &str = "/usr/local/bin";

/// Creates `/usr/local/bin/{name}` → `target`.
pub fn link(name: &CliName, target: &CliTarget) -> Result<(), HelperError> {
    link_at(&fs_root::resolve(CLI_BIN_DIR), name, target)
}

/// Removes `/usr/local/bin/{name}` if it is a symlink pointing inside an ArcBox bundle.
pub fn unlink(name: &CliName) -> Result<(), HelperError> {
    unlink_at(&fs_root::resolve(CLI_BIN_DIR), name)
}

fn link_at(bin_dir: &Path, name: &CliName, target: &CliTarget) -> Result<(), HelperError> {
    let link_path = bin_dir.join(name.as_str());
    let target_path = Path::new(target.as_str());

    ensure_safe_cli_target(target_path, target)?;
    if prepare_symlink_slot(&link_path, target_path, is_arcbox_owned)? == Slot::AlreadyCorrect {
        return Ok(());
    }

    fs::create_dir_all(bin_dir).map_err(|e| HelperError::io("create_dir", bin_dir, e))?;

    unix_fs::symlink(target_path, &link_path).map_err(|e| HelperError::io("symlink", &link_path, e))
}

fn unlink_at(bin_dir: &Path, name: &CliName) -> Result<(), HelperError> {
    remove_owned_symlink(&bin_dir.join(name.as_str()), is_arcbox_owned)
}

fn ensure_safe_cli_target(target_path: &Path, display: &CliTarget) -> Result<(), HelperError> {
    let meta = fs::symlink_metadata(target_path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            HelperError::CliTargetMissing {
                target: display.to_string(),
            }
        } else {
            HelperError::io("stat", target_path, e)
        }
    })?;

    if meta.file_type().is_symlink() {
        return Err(HelperError::CliTargetIsSymlink {
            target: display.to_string(),
        });
    }
    if !meta.file_type().is_file() {
        return Err(HelperError::CliTargetNotFile {
            target: display.to_string(),
        });
    }

    let canonical = fs::canonicalize(target_path)
        .map_err(|e| HelperError::io("canonicalize", target_path, e))?;
    if !is_arcbox_owned(&canonical) {
        return Err(HelperError::CliTargetEscaped {
            target: display.to_string(),
            resolved: canonical.display().to_string(),
        });
    }

    Ok(())
}

/// Outcome of inspecting a destination path before creating a managed symlink.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Slot {
    Ready,
    AlreadyCorrect,
}

pub(super) fn prepare_symlink_slot(
    link_path: &Path,
    want: &Path,
    is_ours: impl Fn(&Path) -> bool,
) -> Result<Slot, HelperError> {
    match fs::symlink_metadata(link_path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            let existing =
                fs::read_link(link_path).map_err(|e| HelperError::io("read_link", link_path, e))?;
            if existing == want {
                return Ok(Slot::AlreadyCorrect);
            }
            if !is_ours(&existing) {
                return Err(HelperError::foreign_symlink(link_path, &existing));
            }
            fs::remove_file(link_path).map_err(|e| HelperError::io("remove", link_path, e))?;
            Ok(Slot::Ready)
        }
        Ok(_) => Err(HelperError::not_a_symlink(link_path)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Slot::Ready),
        Err(e) => Err(HelperError::io("stat", link_path, e)),
    }
}

pub(super) fn remove_owned_symlink(
    link_path: &Path,
    is_ours: impl Fn(&Path) -> bool,
) -> Result<(), HelperError> {
    match fs::symlink_metadata(link_path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            let target =
                fs::read_link(link_path).map_err(|e| HelperError::io("read_link", link_path, e))?;
            if is_ours(&target) {
                fs::remove_file(link_path).map_err(|e| HelperError::io("remove", link_path, e))?;
            }
            Ok(())
        }
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(HelperError::io("stat", link_path, e)),
    }
}

#[cfg(test)]
mod tests {
    use super::{Slot, ensure_safe_cli_target, prepare_symlink_slot, remove_owned_symlink};
    use arcbox_constants::paths::is_arcbox_owned;
    use arcbox_helper::HelperError;
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
        assert!(matches!(err, HelperError::CliTargetMissing { .. }), "{err}");
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
        assert!(
            matches!(err, HelperError::CliTargetIsSymlink { .. }),
            "{err}"
        );
    }

    #[test]
    fn prepare_slot_preserves_foreign_and_replaces_ours() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("docker");
        let want = Path::new("/Applications/ArcBox.app/Contents/MacOS/xbin/docker");

        symlink("/usr/local/bin/real-docker", &link).unwrap();
        let err = prepare_symlink_slot(&link, want, is_arcbox_owned).unwrap_err();
        assert!(matches!(err, HelperError::ForeignSymlink { .. }), "{err}");
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
        assert!(!link.exists());

        symlink(want, &link).unwrap();
        assert_eq!(
            prepare_symlink_slot(&link, want, is_arcbox_owned).unwrap(),
            Slot::AlreadyCorrect
        );
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
