use std::os::unix::fs::MetadataExt;

use crate::passthrough::PassthroughFs;

/// Extension trait for `PassthroughFs` that adds DAX-specific operations.
///
/// Kept separate from `PassthroughFs` so that the general-purpose filesystem
/// abstraction stays free of DAX protocol concerns. Only `FuseDispatcher`
/// (and tests) need to call this method.
pub trait DaxFsExt {
    /// Opens a short-lived `File` for the given inode, for use in
    /// `FUSE_SETUPMAPPING` requests that carry the [`FUSE_NO_FH`] sentinel.
    ///
    /// When `writable` is `true` the file is opened O_RDWR so that a subsequent
    /// `mmap(MAP_SHARED | PROT_WRITE)` does not get EACCES.  When `writable` is
    /// `false` the file is opened O_RDONLY.
    ///
    /// After opening, performs a TOCTOU check by comparing the `st_ino` of the
    /// opened fd against the `st_ino` of the path still in the filesystem.
    /// Returns `io::Error` with `EIO` if they differ (file was swapped between
    /// the path resolution and the open call).
    ///
    /// The caller is expected to pass the returned fd to `mmap` / `hv_vm_map`
    /// and then drop the `File`. The kernel mapping survives fd close.
    fn open_inode_for_dax(&self, inode: u64, writable: bool) -> std::io::Result<std::fs::File>;
}

impl DaxFsExt for PassthroughFs {
    fn open_inode_for_dax(&self, inode: u64, writable: bool) -> std::io::Result<std::fs::File> {
        // Retrieve the kernel st_ino that was recorded at lookup/create time.
        // This is the ground truth: it reflects the file the guest believes it
        // has a reference to. If the directory entry is later renamed so that
        // the path now resolves to a different kernel inode, the comparison
        // below will catch the swap even when open() itself did not race.
        let registered_ino = self.kernel_ino_for(inode).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("inode {inode} not found in passthrough table"),
            )
        })?;

        let path = self
            .inode_path(inode)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::NotFound, e.to_string()))?;

        // Open with the mode the caller requested.  A writable DAX mapping
        // requires O_RDWR: mmap(MAP_SHARED | PROT_WRITE) on an O_RDONLY fd
        // returns EACCES even if the host file itself is writable.
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(writable)
            .open(&path)?;

        // TOCTOU guard: compare the fd's st_ino against the value that was
        // stored at inode-registration time. A rename that happened at any
        // point after registration — including before this function was called
        // — will cause the fd to have a different kernel inode number, which we
        // detect here and reject with EIO.
        let fd_ino = file.metadata()?.ino();
        if fd_ino != registered_ino {
            tracing::warn!(
                inode,
                path = %path.display(),
                fd_ino,
                registered_ino,
                "TOCTOU mismatch: inode was swapped after registration; rejecting DAX mapping"
            );
            return Err(std::io::Error::from_raw_os_error(libc::EIO));
        }

        Ok(file)
    }
}
