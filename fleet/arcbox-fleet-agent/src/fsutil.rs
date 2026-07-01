//! Small filesystem helper shared by anything that persists state to the
//! data directory with an owner-only file mode.

use std::path::Path;

use anyhow::{Context, Result};

/// Write `bytes` to `path`, owner-only (`0600`) from creation on Unix. On
/// non-Unix platforms this writes normally — callers with a secret to
/// protect (unlike a plain settings file) must refuse or otherwise harden
/// separately; see `credentials.rs`'s own `write_private`.
#[cfg(unix)]
pub fn write_owner_only(path: &Path, bytes: &[u8]) -> Result<()> {
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

#[cfg(not(unix))]
pub fn write_owner_only(path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes).with_context(|| format!("writing {}", path.display()))
}
