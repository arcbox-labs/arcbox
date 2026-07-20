//! Docker socket symlink management.
//!
//! Creates or removes a symlink at `/var/run/docker.sock` pointing to the
//! user's ArcBox Docker socket. This lets Docker CLI tools find the daemon
//! without explicit `DOCKER_HOST` configuration.

use std::fs;
use std::os::unix::fs as unix_fs;
use std::path::Path;

use arcbox_helper::validate::SocketTarget;

/// Standard Docker socket path.
const DOCKER_SOCK: &str = arcbox_constants::paths::privileged::DOCKER_SOCKET;

/// Creates a symlink at `/var/run/docker.sock` → `target`.
///
/// Idempotent: if the symlink already points to `target`, this is a no-op.
/// If it is a symlink pointing elsewhere **and** that target is ArcBox-owned
/// (`~/.arcbox/` or `~/.arcbox-dev/`), it is replaced. Foreign symlinks and
/// real socket files are refused.
pub fn link(target: &SocketTarget) -> Result<(), String> {
    link_at(Path::new(DOCKER_SOCK), target)
}

/// Removes the `/var/run/docker.sock` symlink **only** when it points into an
/// ArcBox data dir. Foreign symlinks and real sockets are left alone.
///
/// Idempotent: returns Ok if already absent or not ArcBox-owned.
pub fn unlink() -> Result<(), String> {
    unlink_at(Path::new(DOCKER_SOCK))
}

fn link_at(link_path: &Path, target: &SocketTarget) -> Result<(), String> {
    let target_path = Path::new(target.as_str());
    let display = link_path.display();

    match fs::symlink_metadata(link_path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            let existing = fs::read_link(link_path)
                .map_err(|e| format!("failed to read symlink {display}: {e}"))?;
            if existing == target_path {
                return Ok(());
            }
            if !is_arcbox_socket_target(&existing) {
                return Err(format!(
                    "{display} is a symlink to {} (not ArcBox-owned, not replacing)",
                    existing.display()
                ));
            }
            fs::remove_file(link_path)
                .map_err(|e| format!("failed to remove existing {display}: {e}"))?;
        }
        Ok(_) => {
            return Err(format!(
                "{display} exists but is not a symlink \
                 (is Docker Desktop running? stop it first)"
            ));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(format!("failed to stat {display}: {e}"));
        }
    }

    // Ensure parent exists (production: /var/run always does; tests may use tmp).
    if let Some(parent) = link_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create {}: {e}", parent.display()))?;
    }

    unix_fs::symlink(target_path, link_path)
        .map_err(|e| format!("failed to create symlink {display} -> {target}: {e}"))
}

fn unlink_at(link_path: &Path) -> Result<(), String> {
    let display = link_path.display();

    match fs::symlink_metadata(link_path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            let target = fs::read_link(link_path)
                .map_err(|e| format!("failed to read symlink {display}: {e}"))?;
            if !is_arcbox_socket_target(&target) {
                // Not ours — leave it. Matches cli_unlink ownership policy.
                return Ok(());
            }
            fs::remove_file(link_path).map_err(|e| format!("failed to remove {display}: {e}"))
        }
        Ok(_) => {
            // Real socket / file owned by another daemon — do not touch.
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("failed to stat {display}: {e}")),
    }
}

/// `true` when `target` parses as a valid ArcBox socket path
/// (`/Users/…/.arcbox/…` or `…/.arcbox-dev/…`).
fn is_arcbox_socket_target(target: &Path) -> bool {
    target
        .to_str()
        .is_some_and(|s| s.parse::<SocketTarget>().is_ok())
}

#[cfg(test)]
mod tests {
    use super::{is_arcbox_socket_target, link_at, unlink_at};
    use arcbox_helper::validate::SocketTarget;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::{Path, PathBuf};

    #[test]
    fn recognizes_arcbox_socket_paths() {
        assert!(is_arcbox_socket_target(Path::new(
            "/Users/alice/.arcbox/run/docker.sock"
        )));
        assert!(is_arcbox_socket_target(Path::new(
            "/Users/alice/.arcbox-dev/run/docker.sock"
        )));
    }

    #[test]
    fn rejects_foreign_socket_paths() {
        assert!(!is_arcbox_socket_target(Path::new("/var/run/docker.sock")));
        assert!(!is_arcbox_socket_target(Path::new(
            "/Users/alice/.docker/run/docker.sock"
        )));
        assert!(!is_arcbox_socket_target(Path::new("/tmp/evil.sock")));
    }

    #[test]
    fn link_replaces_arcbox_owned_only() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("docker.sock");
        let target = "/Users/alice/.arcbox/run/docker.sock"
            .parse::<SocketTarget>()
            .unwrap();

        // Foreign existing symlink — refuse.
        symlink("/var/run/other.sock", &link).unwrap();
        let err = link_at(&link, &target).unwrap_err();
        assert!(err.contains("not ArcBox-owned"), "{err}");
        assert_eq!(
            fs::read_link(&link).unwrap(),
            PathBuf::from("/var/run/other.sock")
        );

        // ArcBox-owned existing — replace.
        fs::remove_file(&link).unwrap();
        symlink("/Users/alice/.arcbox/run/old.sock", &link).unwrap();
        link_at(&link, &target).unwrap();
        assert_eq!(fs::read_link(&link).unwrap(), Path::new(target.as_str()));

        // Idempotent.
        link_at(&link, &target).unwrap();
    }

    #[test]
    fn unlink_removes_arcbox_owned_only() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("docker.sock");

        symlink("/Users/alice/.arcbox/run/docker.sock", &link).unwrap();
        unlink_at(&link).unwrap();
        assert!(!link.exists());

        // Foreign — leave alone.
        symlink("/var/run/other.sock", &link).unwrap();
        unlink_at(&link).unwrap();
        assert!(link.symlink_metadata().unwrap().file_type().is_symlink());

        // Real file — leave alone.
        fs::remove_file(&link).unwrap();
        fs::write(&link, b"not a socket").unwrap();
        unlink_at(&link).unwrap();
        assert!(link.is_file());

        // Missing — ok.
        fs::remove_file(&link).unwrap();
        unlink_at(&link).unwrap();
    }

    #[test]
    fn link_refuses_non_symlink_destination() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("docker.sock");
        fs::write(&link, b"real socket stand-in").unwrap();
        let target = "/Users/alice/.arcbox/run/docker.sock"
            .parse::<SocketTarget>()
            .unwrap();
        let err = link_at(&link, &target).unwrap_err();
        assert!(err.contains("not a symlink"), "{err}");
    }
}
