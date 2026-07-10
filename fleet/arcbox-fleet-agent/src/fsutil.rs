//! Small filesystem helper shared by anything that persists state to the
//! data directory with an owner-only file mode. The directory itself gets
//! the same owner-only barrier: callers persist secrets here from paths
//! that never run `control::serve` (the headless `enroll`), so the helper
//! cannot rely on the socket startup's chmod.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Serialize;

/// Write `bytes` to `path`, owner-only (`0600`) from creation — every
/// supported target (macOS, Linux) is Unix.
fn write_owner_only(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    // `mode` only takes effect when this call creates the file; a leftover temp
    // from a crashed run keeps its old mode, so fchmod the open handle as a
    // backstop (operating on the fd, never racing a path lookup).
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 0600 {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("writing {}", path.display()))
}

/// Serialize `value` as pretty JSON and write it to `path` atomically:
/// write a `<path>.tmp` sibling owner-only (`0600` from creation), then
/// rename it over `path`. The rename makes the replace atomic, so a crash
/// mid-write can't leave a truncated file that fails to parse on the next
/// read, and it preserves the temp file's mode so a secret is never briefly
/// world-readable at the final path.
pub fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
        // Owner-only like the file below, and unconditional (not just on
        // creation) so a dir left behind by an older or umask-lenient run
        // gets the same traversal barrier `control::serve` applies at
        // startup — the headless `enroll` persists here without `serve`.
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("chmod 0700 {}", parent.display()))?;
    }
    let json = serde_json::to_vec_pretty(value).context("serializing to JSON")?;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    write_owner_only(&tmp, &json)?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("renaming {} -> {}", tmp.display(), path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// The parent directory must come out owner-only even when this write is
    /// what creates it (the headless `enroll` path, which never runs
    /// `control::serve`), and even when it pre-exists with a lenient mode.
    #[test]
    fn write_json_atomic_makes_the_parent_owner_only() {
        let dir = std::env::temp_dir().join(format!("fleet-fsutil-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("state").join("creds.json");

        write_json_atomic(&path, &serde_json::json!({"k": "v"})).unwrap();
        let parent = path.parent().unwrap();
        let mode = std::fs::metadata(parent).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);

        // A lenient pre-existing dir is tightened, not trusted.
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o755)).unwrap();
        write_json_atomic(&path, &serde_json::json!({"k": "v2"})).unwrap();
        let mode = std::fs::metadata(parent).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
