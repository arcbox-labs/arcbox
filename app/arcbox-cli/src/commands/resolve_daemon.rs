//! Locate `arcbox-daemon` next to `abctl`, following Homebrew cask symlinks.

use std::path::{Path, PathBuf};

const LOCATE_ERR: &str = "Failed to locate `arcbox-daemon` next to `abctl` or in PATH";

pub(crate) fn resolve_daemon_binary_from(
    current_exe: &Path,
    path_lookup: impl FnOnce(&str) -> Option<PathBuf>,
) -> Result<PathBuf, String> {
    if let Some(path) = daemon_sibling_file(current_exe) {
        return Ok(path);
    }

    // Homebrew cask PATH-links only `abctl`, so current_exe() is that
    // symlink and the sibling lives next to the real binary.
    if let Ok(resolved) = current_exe.canonicalize() {
        if let Some(path) = daemon_sibling_file(&resolved) {
            return Ok(path);
        }
    }

    if let Some(path) = path_lookup("arcbox-daemon") {
        return Ok(path);
    }

    Err(LOCATE_ERR.to_string())
}

fn daemon_sibling_file(exe: &Path) -> Option<PathBuf> {
    let sibling = exe.parent()?.join("arcbox-daemon");
    sibling.is_file().then_some(sibling)
}

#[cfg(test)]
mod tests {
    use super::resolve_daemon_binary_from;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn scratch() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("arcbox-resolve-daemon-{nanos}"));
        fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    fn touch(path: &Path) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent dirs");
        }
        fs::write(path, []).expect("touch file");
    }

    #[test]
    fn follows_brew_cask_symlink_to_app_bundle_sibling() {
        let dir = scratch();
        let app_bin = dir
            .join("ArcBox.app")
            .join("Contents")
            .join("MacOS")
            .join("bin");
        let brew_bin = dir.join("opt").join("homebrew").join("bin");
        let real_abctl = app_bin.join("abctl");
        let real_daemon = app_bin.join("arcbox-daemon");
        let brew_abctl = brew_bin.join("abctl");

        touch(&real_abctl);
        touch(&real_daemon);
        fs::create_dir_all(&brew_bin).expect("create brew bin");
        symlink(&real_abctl, &brew_abctl).expect("symlink brew abctl");

        let found = resolve_daemon_binary_from(&brew_abctl, |_| None)
            .expect("should find daemon beside the resolved abctl");
        assert_eq!(found, real_daemon);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn uses_direct_sibling() {
        let dir = scratch();
        let bin = dir.join("bin");
        let abctl = bin.join("abctl");
        let daemon = bin.join("arcbox-daemon");
        touch(&abctl);
        touch(&daemon);

        let found =
            resolve_daemon_binary_from(&abctl, |_| None).expect("should find daemon next to abctl");
        assert_eq!(found, daemon);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn falls_back_to_path() {
        let dir = scratch();
        let brew_abctl = dir.join("opt").join("homebrew").join("bin").join("abctl");
        let path_daemon = dir.join("elsewhere").join("arcbox-daemon");
        touch(&brew_abctl);
        touch(&path_daemon);

        let found = resolve_daemon_binary_from(&brew_abctl, |_| Some(path_daemon.clone()))
            .expect("should use PATH when no sibling exists");
        assert_eq!(found, path_daemon);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn errors_when_missing() {
        let dir = scratch();
        let abctl = dir.join("bin").join("abctl");
        touch(&abctl);

        let err = resolve_daemon_binary_from(&abctl, |_| None)
            .expect_err("missing sibling and PATH must fail");
        assert!(err.contains("Failed to locate `arcbox-daemon` next to `abctl` or in PATH"));
        let _ = fs::remove_dir_all(&dir);
    }
}
