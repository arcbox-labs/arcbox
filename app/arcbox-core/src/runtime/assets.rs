use crate::boot_assets::REQUIRED_RUNTIME_BINARIES;
use crate::error::{CoreError, Result};
use std::path::Path;

/// Checks that a file exists and has at least one executable permission bit set.
pub(super) fn check_executable(path: &Path, context: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(path)
        .map_err(|_| CoreError::config(format!("{} at {}", context, path.display())))?;
    if !meta.is_file() {
        return Err(CoreError::config(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    if meta.permissions().mode() & 0o111 == 0 {
        return Err(CoreError::config(format!(
            "{} is not executable (chmod +x)",
            path.display()
        )));
    }
    Ok(())
}

/// Ensures all guest binaries are present and executable in the VirtioFS-shared
/// directories. Called before VM start. Fails fast if any binary is missing or
/// not executable.
///
/// These binaries are provisioned by `abctl boot prefetch` (release builds) or
/// manually by developers (see `cargo xtask dev boot-assets`). This function
/// only validates — it does not download or install anything.
pub(super) fn ensure_guest_binaries(data_dir: &Path, generation: &str) -> Result<()> {
    let agent_path = data_dir.join("bin/arcbox-agent");
    check_executable(
        &agent_path,
        &format!(
            "agent binary not found at {}; run 'abctl boot prefetch' to download it",
            agent_path.display()
        ),
    )?;

    let runtime_dir = data_dir.join("runtime").join(generation).join("bin");
    for name in REQUIRED_RUNTIME_BINARIES {
        check_executable(
            &runtime_dir.join(name),
            &format!(
                "runtime binary '{name}' not found at {}; run 'abctl boot prefetch' to download runtime assets",
                runtime_dir.join(name).display()
            ),
        )?;
    }

    tracing::info!(
        "All guest binaries verified: agent + {} runtime assets",
        REQUIRED_RUNTIME_BINARIES.len()
    );
    Ok(())
}
