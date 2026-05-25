//! Creates `/usr/local/bin/` symlinks for Docker CLI tools bundled in the app.
//!
//! This is the **system-wide** path: `/usr/local/bin/docker` →
//! `.app/Contents/MacOS/xbin/docker`, created here by the daemon via the
//! privileged helper. Works for all users and shells without PATH changes.
//!
//! A parallel **user-space** path (`~/.arcbox/bin/docker`, written by
//! `abctl setup install`, exposed via `~/.arcbox/bin` on PATH) is the
//! unprivileged fallback. Both can coexist.
//!
//! Coexistence with Docker Desktop / `brew install docker`: if a slot in
//! `/usr/local/bin/` is already owned by another tool, the helper refuses
//! to overwrite. We treat that as satisfied — the user keeps their existing
//! `docker`, and ArcBox remains reachable via `~/.arcbox/bin`.

use std::path::{Path, PathBuf};

use arcbox_constants::paths::{DOCKER_CLI_TOOLS, is_arcbox_owned};
use arcbox_helper::client::{Client, ClientError};

use super::SetupTask;

pub struct CliTools {
    /// Path to `Contents/MacOS/xbin/` inside the app bundle.
    pub xbin_dir: PathBuf,
}

/// Status of a single `/usr/local/bin/{tool}` slot from our perspective.
enum SlotStatus {
    /// Already points to our xbin binary — nothing to do.
    OurLink,
    /// Owned by another tool or is a non-symlink file — we'll defer.
    Foreign,
    /// Absent — we should ask the helper to create the link.
    Vacant,
}

fn slot_status(link: &Path, expected_target: &Path) -> SlotStatus {
    match std::fs::symlink_metadata(link) {
        Ok(meta) if meta.file_type().is_symlink() => match std::fs::read_link(link) {
            Ok(target) if target == expected_target => SlotStatus::OurLink,
            // Stale ArcBox-owned symlink (e.g. previous version of the app):
            // helper will replace, so still treat as needing apply.
            Ok(target) if is_arcbox_owned(&target) => SlotStatus::Vacant,
            Ok(_) | Err(_) => SlotStatus::Foreign,
        },
        Ok(_) => SlotStatus::Foreign,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => SlotStatus::Vacant,
        // Stat failed for some other reason — treat as foreign so we don't loop.
        Err(_) => SlotStatus::Foreign,
    }
}

#[async_trait::async_trait]
impl SetupTask for CliTools {
    fn name(&self) -> &'static str {
        "CLI tools"
    }

    fn is_satisfied(&self) -> bool {
        DOCKER_CLI_TOOLS.iter().all(|name| {
            let link = PathBuf::from(format!("/usr/local/bin/{name}"));
            // "Satisfied" means we have no work to do: either we own the link
            // already, or it's foreign-owned and we'd defer anyway.
            !matches!(
                slot_status(&link, &self.xbin_dir.join(name)),
                SlotStatus::Vacant
            )
        })
    }

    async fn apply(&self, client: &Client) -> Result<(), ClientError> {
        let mut attempted = 0usize;
        let mut succeeded = 0usize;
        let mut last_err: Option<ClientError> = None;
        for name in DOCKER_CLI_TOOLS {
            let target = self.xbin_dir.join(name);
            if !target.exists() {
                continue;
            }
            let link = PathBuf::from(format!("/usr/local/bin/{name}"));
            match slot_status(&link, &target) {
                SlotStatus::OurLink => {}
                SlotStatus::Foreign => {
                    tracing::info!(
                        tool = name,
                        "/usr/local/bin/{name} owned by another tool, deferring"
                    );
                }
                SlotStatus::Vacant => {
                    attempted += 1;
                    match client.cli_link(name, &target.to_string_lossy()).await {
                        Ok(()) => succeeded += 1,
                        Err(e) => {
                            tracing::warn!(tool = name, error = %e, "cli_link failed");
                            last_err = Some(e);
                        }
                    }
                }
            }
        }
        // If we tried to link any vacant slot and every attempt failed, surface
        // the last error so the setup runner logs it (rather than silently
        // swallowing a total failure as success).
        if attempted > 0 && succeeded == 0 {
            return Err(last_err.expect("attempted>0 && succeeded==0 implies at least one Err"));
        }
        Ok(())
    }
}
