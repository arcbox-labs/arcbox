//! Small filesystem helper shared by anything that persists state to the
//! data directory with an owner-only file mode.

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
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let json = serde_json::to_vec_pretty(value).context("serializing to JSON")?;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    write_owner_only(&tmp, &json)?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("renaming {} -> {}", tmp.display(), path.display()))
}
