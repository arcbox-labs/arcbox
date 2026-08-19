//! Sandbox file operations over the guest agent's file channel (CORE-62).
//!
//! Thin manager façade over the guest-agent port's
//! [`GuestFiles`](crate::agent::GuestFiles): each verb verifies the sandbox
//! is alive (Ready or Running — file I/O works alongside a running
//! workload) and forwards to the agent. Paused states surface as
//! [`ComputerError::Paused`] so the daemon's transparent auto-resume applies.

use super::*;
use crate::agent::DirWatch;
use crate::file_proto::FileStatDto;

impl ComputerManager {
    /// Read a file from inside an alive sandbox.
    pub async fn read_computer_file(&self, id: &ComputerId, path: &str) -> Result<Vec<u8>> {
        let agent = self.require_alive_agent(id)?;
        agent.files().read(path).await
    }

    /// Write a file into an alive sandbox.
    pub async fn write_computer_file(
        &self,
        id: &ComputerId,
        path: &str,
        mode: u32,
        data: &[u8],
    ) -> Result<()> {
        let agent = self.require_alive_agent(id)?;
        agent.files().write(path, mode, data).await
    }

    /// Stat one path inside an alive sandbox (symlinks reported, not
    /// followed).
    pub async fn stat_computer_path(&self, id: &ComputerId, path: &str) -> Result<FileStatDto> {
        let agent = self.require_alive_agent(id)?;
        agent.files().stat(path).await
    }

    /// List a directory inside an alive sandbox, non-recursively, with full
    /// per-entry metadata.
    pub async fn list_computer_dir(&self, id: &ComputerId, path: &str) -> Result<Vec<FileStatDto>> {
        let agent = self.require_alive_agent(id)?;
        agent.files().list(path).await
    }

    /// Create a directory (and missing parents) inside an alive sandbox.
    /// Succeeds when the directory already exists. `mode` must already be
    /// defaulted by the caller.
    pub async fn make_computer_dir(&self, id: &ComputerId, path: &str, mode: u32) -> Result<()> {
        let agent = self.require_alive_agent(id)?;
        agent.files().make_dir(path, mode).await
    }

    /// Remove a file, symlink, or directory inside an alive sandbox. A
    /// non-empty directory requires `recursive`.
    pub async fn remove_computer_path(
        &self,
        id: &ComputerId,
        path: &str,
        recursive: bool,
    ) -> Result<()> {
        let agent = self.require_alive_agent(id)?;
        agent.files().remove(path, recursive).await
    }

    /// Rename / move an entry within an alive sandbox.
    pub async fn move_computer_path(&self, id: &ComputerId, from: &str, to: &str) -> Result<()> {
        let agent = self.require_alive_agent(id)?;
        agent.files().rename(from, to).await
    }

    /// Open a directory watch inside an alive sandbox. The returned stream
    /// ends cleanly when the sandbox stops; dropping it cancels the watch.
    pub async fn watch_computer_dir(
        &self,
        id: &ComputerId,
        path: &str,
        recursive: bool,
    ) -> Result<DirWatch> {
        let agent = self.require_alive_agent(id)?;
        agent.files().watch(path, recursive).await
    }
}
