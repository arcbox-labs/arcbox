use super::*;

impl FuseDispatcher {
    pub(super) fn handle_setup_mapping(
        &self,
        ctx: &RequestContext,
        body: &[u8],
        response: &mut ResponseBuilder,
    ) {
        use crate::fuse::FuseSetupMappingIn;

        let Some(ref mapper) = self.dax_mapper else {
            response.write_error(ctx.unique, libc::ENOSYS);
            return;
        };

        if body.len() < std::mem::size_of::<FuseSetupMappingIn>() {
            response.write_error(ctx.unique, libc::EINVAL);
            return;
        }

        let req = unsafe { std::ptr::read_unaligned(body.as_ptr().cast::<FuseSetupMappingIn>()) };

        let writable = req.flags & crate::fuse::FUSE_SETUPMAPPING_FLAG_WRITE != 0;

        // The Linux virtiofs DAX client sends `fh = FUSE_NO_FH` (u64::MAX) when
        // it wants to map a file for which it has no open file handle — typically
        // the on-demand mapping path used during `execve` and read-ahead.
        // For that case we fall back to opening a fresh host fd via
        // `DaxFsExt::open_inode_for_dax`, which also performs a TOCTOU check.
        // The fd is opened writable when the guest requests a writable mapping so
        // that mmap(MAP_SHARED | PROT_WRITE) does not fail with EACCES.
        // `mmap(2)` keeps the mapping alive independent of the fd's lifetime,
        // so the temporary `File` can be dropped as soon as `setup_mapping` returns.
        let result = if req.fh == FUSE_NO_FH {
            match DaxFsExt::open_inode_for_dax(self.fs.as_ref(), ctx.nodeid, writable) {
                Ok(file) => {
                    use std::os::unix::io::AsRawFd;
                    let host_fd = file.as_raw_fd();
                    tracing::debug!(
                        "FUSE SETUPMAPPING (inode-fd): nodeid={} host_fd={} foffset={:#x} moffset={:#x} len={:#x} writable={}",
                        ctx.nodeid,
                        host_fd,
                        req.foffset,
                        req.moffset,
                        req.len,
                        writable,
                    );
                    mapper.setup_mapping(host_fd, req.foffset, req.moffset, req.len, writable)
                    // `file` drops here — closes the fd. The mapping
                    // installed by `mmap` stays alive regardless.
                }
                Err(e) => {
                    tracing::warn!(
                        "FUSE SETUPMAPPING: failed to open nodeid={} for fh-sentinel mapping: {}",
                        ctx.nodeid,
                        e,
                    );
                    Err(libc::EBADF)
                }
            }
        } else {
            match self.fs.get_file_raw_fd(req.fh) {
                Some(host_fd) => {
                    tracing::debug!(
                        "FUSE SETUPMAPPING: fh={:#x} host_fd={} foffset={:#x} moffset={:#x} len={:#x} writable={}",
                        req.fh,
                        host_fd,
                        req.foffset,
                        req.moffset,
                        req.len,
                        writable,
                    );
                    mapper.setup_mapping(host_fd, req.foffset, req.moffset, req.len, writable)
                }
                None => {
                    tracing::warn!(
                        "FUSE SETUPMAPPING: unknown fh={:#x} (foffset={:#x} moffset={:#x} len={:#x} flags={:#x})",
                        req.fh,
                        req.foffset,
                        req.moffset,
                        req.len,
                        req.flags,
                    );
                    Err(libc::EBADF)
                }
            }
        };

        match result {
            Ok(()) => response.write_empty(ctx.unique),
            Err(errno) => {
                tracing::warn!(
                    "FUSE SETUPMAPPING: failed errno={} fh={:#x} nodeid={} foffset={:#x} moffset={:#x} len={:#x}",
                    errno,
                    req.fh,
                    ctx.nodeid,
                    req.foffset,
                    req.moffset,
                    req.len,
                );
                response.write_error(ctx.unique, errno);
            }
        }
    }

    pub(super) fn handle_remove_mapping(
        &self,
        ctx: &RequestContext,
        body: &[u8],
        response: &mut ResponseBuilder,
    ) {
        use crate::fuse::{FuseRemoveMappingIn, FuseRemoveMappingOne};

        let Some(ref mapper) = self.dax_mapper else {
            response.write_error(ctx.unique, libc::ENOSYS);
            return;
        };

        let hdr_size = std::mem::size_of::<FuseRemoveMappingIn>();
        if body.len() < hdr_size {
            response.write_error(ctx.unique, libc::EINVAL);
            return;
        }

        let hdr = unsafe { std::ptr::read_unaligned(body.as_ptr().cast::<FuseRemoveMappingIn>()) };
        let entry_size = std::mem::size_of::<FuseRemoveMappingOne>();
        let entries = &body[hdr_size..];

        for i in 0..hdr.count as usize {
            let off = i * entry_size;
            if off + entry_size > entries.len() {
                break;
            }
            let entry = unsafe {
                std::ptr::read_unaligned(entries[off..].as_ptr().cast::<FuseRemoveMappingOne>())
            };
            if let Err(errno) = mapper.remove_mapping(entry.moffset, entry.len) {
                response.write_error(ctx.unique, errno);
                return;
            }
        }

        response.write_empty(ctx.unique);
    }

    pub(super) fn handle_getxattr(
        &self,
        ctx: &RequestContext,
        body: &[u8],
        response: &mut ResponseBuilder,
    ) {
        if body.len() < size_of::<FuseGetxattrIn>() {
            response.write_error(ctx.unique, libc::EINVAL);
            return;
        }

        // SAFETY: FuseGetxattrIn may sit at an unaligned offset in the VirtIO buffer.
        let getxattr_in =
            unsafe { std::ptr::read_unaligned(body.as_ptr() as *const FuseGetxattrIn) };
        let name = self.parse_name(&body[size_of::<FuseGetxattrIn>()..]);

        // Bound the guest-controlled `size`: no xattr exceeds XATTR_SIZE_MAX
        // (64 KiB), so a larger value can only be an attempt to force a huge
        // per-request allocation. Clamping keeps the get correct (a real value
        // fits; an over-large request that wouldn't fit still gets ERANGE).
        const MAX_XATTR_SIZE: u32 = 64 * 1024;
        let size = getxattr_in.size.min(MAX_XATTR_SIZE);
        match self.fs.getxattr(ctx.nodeid, name, size) {
            Ok(value) => {
                if size == 0 {
                    // Return size only
                    let out = FuseGetxattrOut {
                        size: value.len() as u32,
                        padding: 0,
                    };
                    response.write_data(ctx.unique, &out);
                } else {
                    response.write_bytes(ctx.unique, &value);
                }
            }
            Err(e) => response.write_error(ctx.unique, e.to_errno()),
        }
    }

    pub(super) fn handle_setxattr(
        &self,
        ctx: &RequestContext,
        body: &[u8],
        response: &mut ResponseBuilder,
    ) {
        if body.len() < size_of::<FuseSetxattrIn>() {
            response.write_error(ctx.unique, libc::EINVAL);
            return;
        }

        // SAFETY: FuseSetxattrIn may sit at an unaligned offset in the VirtIO buffer.
        let setxattr_in =
            unsafe { std::ptr::read_unaligned(body.as_ptr() as *const FuseSetxattrIn) };
        let rest = &body[size_of::<FuseSetxattrIn>()..];

        // Parse name\0value
        if let Some(null_pos) = rest.iter().position(|&b| b == 0) {
            let name = OsStr::from_bytes(&rest[..null_pos]);
            // The declared value length must fit the bytes actually present
            // after `name\0`; an oversized `size` used to index-panic here, and
            // with panic=abort that killed the whole host process.
            let Some(value) = rest
                .get(null_pos + 1..)
                .and_then(|v| v.get(..setxattr_in.size as usize))
            else {
                response.write_error(ctx.unique, libc::EINVAL);
                return;
            };

            match self.fs.setxattr(ctx.nodeid, name, value, setxattr_in.flags) {
                Ok(()) => response.write_empty(ctx.unique),
                Err(e) => response.write_error(ctx.unique, e.to_errno()),
            }
        } else {
            response.write_error(ctx.unique, libc::EINVAL);
        }
    }

    pub(super) fn handle_removexattr(
        &self,
        ctx: &RequestContext,
        body: &[u8],
        response: &mut ResponseBuilder,
    ) {
        let name = self.parse_name(body);

        match self.fs.removexattr(ctx.nodeid, name) {
            Ok(()) => response.write_empty(ctx.unique),
            Err(e) => response.write_error(ctx.unique, e.to_errno()),
        }
    }

    pub(super) fn handle_statfs(&self, ctx: &RequestContext, response: &mut ResponseBuilder) {
        match self.fs.statfs() {
            Ok(st) => {
                let statfs_out = FuseStatfsOut { st };
                response.write_data(ctx.unique, &statfs_out);
            }
            Err(e) => response.write_error(ctx.unique, e.to_errno()),
        }
    }

    pub(super) fn handle_access(
        &self,
        ctx: &RequestContext,
        body: &[u8],
        response: &mut ResponseBuilder,
    ) {
        if body.len() < size_of::<FuseAccessIn>() {
            response.write_error(ctx.unique, libc::EINVAL);
            return;
        }

        // SAFETY: FuseAccessIn may sit at an unaligned offset in the VirtIO buffer.
        let access_in = unsafe { std::ptr::read_unaligned(body.as_ptr() as *const FuseAccessIn) };

        match self.fs.access(ctx.nodeid, access_in.mask) {
            Ok(()) => response.write_empty(ctx.unique),
            Err(e) => response.write_error(ctx.unique, e.to_errno()),
        }
    }
}
