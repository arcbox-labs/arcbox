//! CLI tool symlink management in `/usr/local/bin/`.
//!
//! Creates symlinks like `/usr/local/bin/docker` → `.app/Contents/MacOS/xbin/docker`
//! so Docker CLI tools from the app bundle are available system-wide.

use std::fs;
use std::os::unix::fs as unix_fs;
use std::path::Path;

use arcbox_constants::paths::is_arcbox_owned;
use arcbox_helper::validate::{CliName, CliTarget};

/// Creates `/usr/local/bin/{name}` → `target`.
///
/// Idempotent: if the symlink already points to `target`, this is a no-op.
/// Only replaces existing symlinks that point into an ArcBox bundle.
/// Refuses to overwrite regular files or non-ArcBox symlinks.
pub fn link(name: &CliName, target: &CliTarget) -> Result<(), String> {
    let link_path = Path::new("/usr/local/bin").join(name.as_str());
    let target_path = Path::new(target.as_str());

    if !target_path.exists() {
        return Err(format!("CLI target does not exist: {target}"));
    }

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

    fs::create_dir_all("/usr/local/bin")
        .map_err(|e| format!("failed to create /usr/local/bin: {e}"))?;

    unix_fs::symlink(target_path, &link_path).map_err(|e| {
        format!(
            "failed to create symlink {} -> {target}: {e}",
            link_path.display()
        )
    })
}

/// Removes `/usr/local/bin/{name}` if it is a symlink pointing inside an ArcBox bundle.
///
/// Idempotent: returns Ok if already absent or not an ArcBox-owned symlink.
pub fn unlink(name: &CliName) -> Result<(), String> {
    let link_path = Path::new("/usr/local/bin").join(name.as_str());

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
