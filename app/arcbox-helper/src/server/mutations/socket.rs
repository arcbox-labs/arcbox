//! Docker socket symlink management.

use std::fs;
use std::os::unix::fs as unix_fs;
use std::path::Path;

use arcbox_helper::HelperError;
use arcbox_helper::validate::SocketTarget;

use crate::server::fs_root;
use crate::server::mutations::cli::{Slot, prepare_symlink_slot, remove_owned_symlink};

const DOCKER_SOCK: &str = arcbox_constants::paths::privileged::DOCKER_SOCKET;

/// Creates a symlink at `/var/run/docker.sock` → `target`.
pub fn link(target: &SocketTarget) -> Result<(), HelperError> {
    link_at(&fs_root::resolve(DOCKER_SOCK), target)
}

/// Removes the `/var/run/docker.sock` symlink only when ArcBox-owned.
pub fn unlink() -> Result<(), HelperError> {
    unlink_at(&fs_root::resolve(DOCKER_SOCK))
}

fn link_at(link_path: &Path, target: &SocketTarget) -> Result<(), HelperError> {
    let target_path = Path::new(target.as_str());
    let slot = prepare_symlink_slot(link_path, target_path, is_arcbox_socket_target).map_err(
        |e| match e {
            HelperError::NotASymlink { path } => HelperError::NotASymlink {
                path: format!("{path} (is Docker Desktop running? stop it first)"),
            },
            other => other,
        },
    )?;
    if slot == Slot::AlreadyCorrect {
        return Ok(());
    }

    if let Some(parent) = link_path.parent() {
        fs::create_dir_all(parent).map_err(|e| HelperError::io("create_dir", parent, e))?;
    }

    unix_fs::symlink(target_path, link_path).map_err(|e| HelperError::io("symlink", link_path, e))
}

fn unlink_at(link_path: &Path) -> Result<(), HelperError> {
    remove_owned_symlink(link_path, is_arcbox_socket_target)
}

fn is_arcbox_socket_target(target: &Path) -> bool {
    target
        .to_str()
        .is_some_and(|s| s.parse::<SocketTarget>().is_ok())
}

#[cfg(test)]
mod tests {
    use super::{is_arcbox_socket_target, link_at, unlink_at};
    use arcbox_helper::HelperError;
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
        assert!(!is_arcbox_socket_target(Path::new("/tmp/evil.sock")));
    }

    #[test]
    fn link_replaces_arcbox_owned_only() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("docker.sock");
        let target = "/Users/alice/.arcbox/run/docker.sock"
            .parse::<SocketTarget>()
            .unwrap();

        symlink("/var/run/other.sock", &link).unwrap();
        let err = link_at(&link, &target).unwrap_err();
        assert!(matches!(err, HelperError::ForeignSymlink { .. }), "{err}");
        assert_eq!(
            fs::read_link(&link).unwrap(),
            PathBuf::from("/var/run/other.sock")
        );

        fs::remove_file(&link).unwrap();
        symlink("/Users/alice/.arcbox/run/old.sock", &link).unwrap();
        link_at(&link, &target).unwrap();
        assert_eq!(fs::read_link(&link).unwrap(), Path::new(target.as_str()));
        link_at(&link, &target).unwrap();
    }

    #[test]
    fn unlink_removes_arcbox_owned_only() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("docker.sock");

        symlink("/Users/alice/.arcbox/run/docker.sock", &link).unwrap();
        unlink_at(&link).unwrap();
        assert!(!link.exists());

        symlink("/var/run/other.sock", &link).unwrap();
        unlink_at(&link).unwrap();
        assert!(link.symlink_metadata().unwrap().file_type().is_symlink());
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
        assert!(matches!(err, HelperError::NotASymlink { .. }), "{err}");
    }
}
