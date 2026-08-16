//! Sandbox file operations over the vsock file channel (CORE-62).
//!
//! Thin manager façade over [`crate::file_io`]: each verb verifies the
//! sandbox is alive (Ready or Running — file I/O works alongside a running
//! workload) and forwards to the vm-agent. Paused states surface as
//! [`VmmError::Paused`] so the daemon's transparent auto-resume applies.

use super::*;
use crate::file_io::{self, DirWatch, proto::FileStatDto};

impl SandboxManager {
    /// Read a file from inside an alive sandbox over the vsock file channel.
    pub async fn read_sandbox_file(&self, id: &SandboxId, path: &str) -> Result<Vec<u8>> {
        let uds = self.require_alive_vsock(id)?;
        file_io::read_file(&vsock::UdsVsock(uds), path).await
    }

    /// Write a file into an alive sandbox over the vsock file channel.
    pub async fn write_sandbox_file(
        &self,
        id: &SandboxId,
        path: &str,
        mode: u32,
        data: &[u8],
    ) -> Result<()> {
        let uds = self.require_alive_vsock(id)?;
        file_io::write_file(&vsock::UdsVsock(uds), path, mode, data).await
    }

    /// Stat one path inside an alive sandbox (symlinks reported, not
    /// followed).
    pub async fn stat_sandbox_path(&self, id: &SandboxId, path: &str) -> Result<FileStatDto> {
        let uds = self.require_alive_vsock(id)?;
        file_io::stat_file(&vsock::UdsVsock(uds), path).await
    }

    /// List a directory inside an alive sandbox, non-recursively, with full
    /// per-entry metadata.
    pub async fn list_sandbox_dir(&self, id: &SandboxId, path: &str) -> Result<Vec<FileStatDto>> {
        let uds = self.require_alive_vsock(id)?;
        file_io::list_dir(&vsock::UdsVsock(uds), path).await
    }

    /// Create a directory (and missing parents) inside an alive sandbox.
    /// Succeeds when the directory already exists. `mode` must already be
    /// defaulted by the caller.
    pub async fn make_sandbox_dir(&self, id: &SandboxId, path: &str, mode: u32) -> Result<()> {
        let uds = self.require_alive_vsock(id)?;
        file_io::make_dir(&vsock::UdsVsock(uds), path, mode).await
    }

    /// Remove a file, symlink, or directory inside an alive sandbox. A
    /// non-empty directory requires `recursive`.
    pub async fn remove_sandbox_path(
        &self,
        id: &SandboxId,
        path: &str,
        recursive: bool,
    ) -> Result<()> {
        let uds = self.require_alive_vsock(id)?;
        file_io::remove_entry(&vsock::UdsVsock(uds), path, recursive).await
    }

    /// Rename / move an entry within an alive sandbox.
    pub async fn move_sandbox_path(&self, id: &SandboxId, from: &str, to: &str) -> Result<()> {
        let uds = self.require_alive_vsock(id)?;
        file_io::move_entry(&vsock::UdsVsock(uds), from, to).await
    }

    /// Open a directory watch inside an alive sandbox. The returned stream
    /// ends cleanly when the sandbox stops; dropping it cancels the watch.
    pub async fn watch_sandbox_dir(
        &self,
        id: &SandboxId,
        path: &str,
        recursive: bool,
    ) -> Result<DirWatch> {
        let uds = self.require_alive_vsock(id)?;
        file_io::watch_dir(&vsock::UdsVsock(uds), path, recursive).await
    }
}
