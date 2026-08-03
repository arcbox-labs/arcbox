//! Guest-local runtime materialization and architecture translator setup.

use std::path::Path;
use std::sync::{Mutex, OnceLock};

use anyhow::{Context as _, Result, bail};

use arcbox_constants::paths::{ARCBOX_RUNTIME_BIN_DIR, ARCBOX_RUNTIME_DIR};

use super::btrfs::{BTRFS_TEMP_MOUNT, ensure_data_mount};
use super::cmdline::runtime_generation;
use crate::runtime_materialize::{MaterializeRequest, materialize_runtime};

const RUNTIME_SOURCE_ROOT: &str = "/arcbox/runtime";
const BOOT_SOURCE_ROOT: &str = "/arcbox/boot";
const FEX_BINFMT_ENTRY: &str = "/proc/sys/fs/binfmt_misc/FEX-x86_64";
const ROSETTA_BINFMT_ENTRY: &str = "/proc/sys/fs/binfmt_misc/rosetta";
const BINFMT_REGISTER: &str = "/proc/sys/fs/binfmt_misc/register";

fn runtime_state() -> &'static Mutex<Option<String>> {
    static STATE: OnceLock<Mutex<Option<String>>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(None))
}

/// Ensures the Btrfs data disk contains the active runtime generation.
pub(super) async fn ensure_local_runtime() -> Result<String, String> {
    tokio::task::spawn_blocking(ensure_local_runtime_blocking)
        .await
        .map_err(|error| format!("runtime materialization task failed: {error}"))?
        .map_err(|error| format!("{error:#}"))
}

fn ensure_local_runtime_blocking() -> Result<String> {
    let mut state = runtime_state()
        .lock()
        .map_err(|_| anyhow::anyhow!("runtime materialization lock poisoned"))?;
    if let Some(note) = state.as_ref() {
        return Ok(note.clone());
    }

    unregister_fex()?;
    let data_note = ensure_data_mount().map_err(anyhow::Error::msg)?;
    let generation = runtime_generation().map_err(anyhow::Error::msg)?;
    let arch = manifest_arch()?;
    let manifest_path = Path::new(BOOT_SOURCE_ROOT)
        .join(&generation)
        .join("manifest.json");
    let source_root = Path::new(RUNTIME_SOURCE_ROOT).join(&generation);

    let runtime = materialize_runtime(&MaterializeRequest {
        manifest_path: &manifest_path,
        source_root: &source_root,
        data_root: Path::new(BTRFS_TEMP_MOUNT),
        stable_root: Path::new(ARCBOX_RUNTIME_DIR),
        generation: &generation,
        arch,
    })?;
    let fex_note = register_local_fex(Path::new(ARCBOX_RUNTIME_BIN_DIR))?;
    let action = if runtime.reused {
        "reused"
    } else {
        "materialized"
    };

    tracing::info!(
        generation,
        arch,
        runtime_root = %runtime.root.display(),
        asset_count = runtime.asset_count,
        action,
        "guest-local runtime ready"
    );
    let note = format!(
        "{data_note}; {action} runtime generation {generation} ({} assets); {fex_note}",
        runtime.asset_count
    );
    *state = Some(note.clone());
    Ok(note)
}

fn manifest_arch() -> Result<&'static str> {
    match std::env::consts::ARCH {
        "aarch64" => Ok("arm64"),
        "x86_64" => Ok("x86_64"),
        arch => bail!("unsupported runtime architecture {arch}"),
    }
}

fn register_local_fex(runtime_bin_dir: &Path) -> Result<String> {
    if cfg!(not(target_arch = "aarch64")) {
        return Ok("FEX not required on this architecture".to_string());
    }

    let fex = runtime_bin_dir.join("FEX");
    if Path::new(ROSETTA_BINFMT_ENTRY).exists() {
        return Ok("Rosetta binfmt already active; FEX registration skipped".to_string());
    }

    if !fex.exists() {
        return Ok("FEX not present in this boot manifest".to_string());
    }

    ensure_binfmt_mounted()?;
    let link = std::process::Command::new("/bin/busybox")
        .args(["ln", "-snf", "/proc/self/fd", "/dev/fd"])
        .status()
        .context("create /dev/fd for FEX")?;
    if !link.success() {
        bail!(
            "create /dev/fd for FEX failed (exit={})",
            link.code().unwrap_or(-1)
        );
    }

    let registration = format!(
        ":FEX-x86_64:M:0:\\x7fELF\\x02\\x01\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x02\\x00\\x3e\\x00:\\xff\\xff\\xff\\xff\\xff\\xfe\\xfe\\x00\\x00\\x00\\x00\\xff\\xff\\xff\\xff\\xff\\xfe\\xff\\xff\\xff:{}:POCF",
        fex.display()
    );
    std::fs::write(BINFMT_REGISTER, registration.as_bytes())
        .context("register Btrfs-backed FEX interpreter")?;
    if !Path::new(FEX_BINFMT_ENTRY).exists() {
        bail!("FEX binfmt registration did not create {FEX_BINFMT_ENTRY}");
    }

    Ok(format!("registered FEX from {}", fex.display()))
}

fn unregister_fex() -> Result<()> {
    if cfg!(target_arch = "aarch64") && Path::new(FEX_BINFMT_ENTRY).exists() {
        // `F` pins the interpreter inode, so remove the legacy VirtioFS entry
        // before materialization can fail.
        std::fs::write(FEX_BINFMT_ENTRY, b"-1\n")
            .context("remove stale FEX binfmt registration")?;
    }
    Ok(())
}

fn ensure_binfmt_mounted() -> Result<()> {
    if Path::new(BINFMT_REGISTER).exists() {
        return Ok(());
    }
    std::fs::create_dir_all("/proc/sys/fs/binfmt_misc")
        .context("create binfmt_misc mount point")?;
    let status = std::process::Command::new("/bin/busybox")
        .args([
            "mount",
            "-t",
            "binfmt_misc",
            "binfmt_misc",
            "/proc/sys/fs/binfmt_misc",
        ])
        .status()
        .context("mount binfmt_misc")?;
    if !status.success() {
        bail!(
            "mount binfmt_misc failed (exit={})",
            status.code().unwrap_or(-1)
        );
    }
    if !Path::new(BINFMT_REGISTER).exists() {
        bail!("binfmt_misc mounted without register endpoint");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::manifest_arch;

    #[test]
    fn current_arch_has_manifest_name() {
        assert!(matches!(manifest_arch(), Ok("arm64" | "x86_64")));
    }
}
