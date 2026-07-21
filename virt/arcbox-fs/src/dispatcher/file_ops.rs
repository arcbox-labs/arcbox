use super::*;

impl FuseDispatcher {
    pub(super) fn handle_open(
        &self,
        ctx: &RequestContext,
        body: &[u8],
        response: &mut ResponseBuilder,
    ) {
        if body.len() < size_of::<FuseOpenIn>() {
            response.write_error(ctx.unique, libc::EINVAL);
            return;
        }

        // SAFETY: FuseOpenIn may sit at an unaligned offset in the VirtIO buffer.
        let open_in = unsafe { std::ptr::read_unaligned(body.as_ptr() as *const FuseOpenIn) };

        match self.fs.open(ctx.nodeid, open_in.flags) {
            Ok(handle) => {
                let open_out = FuseOpenOut {
                    fh: handle,
                    open_flags: 0,
                    padding: 0,
                };
                response.write_data(ctx.unique, &open_out);
            }
            Err(e) => response.write_error(ctx.unique, e.to_errno()),
        }
    }

    pub(super) fn handle_read(
        &self,
        ctx: &RequestContext,
        body: &[u8],
        response: &mut ResponseBuilder,
    ) {
        if body.len() < size_of::<FuseReadIn>() {
            response.write_error(ctx.unique, libc::EINVAL);
            return;
        }

        // SAFETY: FuseReadIn may sit at an unaligned offset in the VirtIO buffer.
        let read_in = unsafe { std::ptr::read_unaligned(body.as_ptr() as *const FuseReadIn) };

        match self.fs.read(read_in.fh, read_in.offset, read_in.size) {
            Ok(data) => response.write_bytes(ctx.unique, &data),
            Err(e) => response.write_error(ctx.unique, e.to_errno()),
        }
    }

    pub(super) fn handle_write(
        &self,
        ctx: &RequestContext,
        body: &[u8],
        response: &mut ResponseBuilder,
    ) {
        if body.len() < size_of::<FuseWriteIn>() {
            response.write_error(ctx.unique, libc::EINVAL);
            return;
        }

        // SAFETY: FuseWriteIn may sit at an unaligned offset in the VirtIO buffer.
        let write_in = unsafe { std::ptr::read_unaligned(body.as_ptr() as *const FuseWriteIn) };
        // Honor the request's declared length rather than writing whatever
        // bytes trail the header: a padded/oversized descriptor chain must not
        // expand the write beyond `write_in.size`.
        let Some(data) = body
            .get(size_of::<FuseWriteIn>()..)
            .and_then(|d| d.get(..write_in.size as usize))
        else {
            response.write_error(ctx.unique, libc::EINVAL);
            return;
        };

        match self
            .fs
            .write(write_in.fh, write_in.offset, data, write_in.write_flags)
        {
            Ok(written) => {
                let write_out = FuseWriteOut {
                    size: written,
                    padding: 0,
                };
                response.write_data(ctx.unique, &write_out);
            }
            Err(e) => response.write_error(ctx.unique, e.to_errno()),
        }
    }

    pub(super) fn handle_release(
        &self,
        ctx: &RequestContext,
        body: &[u8],
        response: &mut ResponseBuilder,
    ) {
        if body.len() < size_of::<FuseReleaseIn>() {
            response.write_error(ctx.unique, libc::EINVAL);
            return;
        }

        // SAFETY: FuseReleaseIn may sit at an unaligned offset in the VirtIO buffer.
        let release_in = unsafe { std::ptr::read_unaligned(body.as_ptr() as *const FuseReleaseIn) };

        match self.fs.release(release_in.fh) {
            Ok(()) => response.write_empty(ctx.unique),
            Err(e) => response.write_error(ctx.unique, e.to_errno()),
        }
    }

    pub(super) fn handle_flush(
        &self,
        ctx: &RequestContext,
        body: &[u8],
        response: &mut ResponseBuilder,
    ) {
        if body.len() < size_of::<FuseFlushIn>() {
            response.write_error(ctx.unique, libc::EINVAL);
            return;
        }

        // SAFETY: FuseFlushIn may sit at an unaligned offset in the VirtIO buffer.
        let flush_in = unsafe { std::ptr::read_unaligned(body.as_ptr() as *const FuseFlushIn) };

        match self.fs.flush(flush_in.fh) {
            Ok(()) => response.write_empty(ctx.unique),
            Err(e) => response.write_error(ctx.unique, e.to_errno()),
        }
    }

    pub(super) fn handle_fsync(
        &self,
        ctx: &RequestContext,
        body: &[u8],
        response: &mut ResponseBuilder,
    ) {
        if body.len() < size_of::<FuseFsyncIn>() {
            response.write_error(ctx.unique, libc::EINVAL);
            return;
        }

        // SAFETY: FuseFsyncIn may sit at an unaligned offset in the VirtIO buffer.
        let fsync_in = unsafe { std::ptr::read_unaligned(body.as_ptr() as *const FuseFsyncIn) };
        let datasync = fsync_in.fsync_flags & 1 != 0;

        match self.fs.fsync(fsync_in.fh, datasync) {
            Ok(()) => response.write_empty(ctx.unique),
            Err(e) => response.write_error(ctx.unique, e.to_errno()),
        }
    }

    pub(super) fn handle_lseek(
        &self,
        ctx: &RequestContext,
        body: &[u8],
        response: &mut ResponseBuilder,
    ) {
        if body.len() < size_of::<FuseLseekIn>() {
            response.write_error(ctx.unique, libc::EINVAL);
            return;
        }

        // SAFETY: FuseLseekIn may sit at an unaligned offset in the VirtIO buffer.
        let lseek_in = unsafe { std::ptr::read_unaligned(body.as_ptr() as *const FuseLseekIn) };

        match self
            .fs
            .lseek(lseek_in.fh, lseek_in.offset as i64, lseek_in.whence)
        {
            Ok(offset) => {
                let lseek_out = FuseLseekOut { offset };
                response.write_data(ctx.unique, &lseek_out);
            }
            Err(e) => response.write_error(ctx.unique, e.to_errno()),
        }
    }

    pub(super) fn handle_fallocate(
        &self,
        ctx: &RequestContext,
        body: &[u8],
        response: &mut ResponseBuilder,
    ) {
        if body.len() < size_of::<FuseFallocateIn>() {
            response.write_error(ctx.unique, libc::EINVAL);
            return;
        }

        // SAFETY: FuseFallocateIn may sit at an unaligned offset in the VirtIO buffer.
        let fallocate_in =
            unsafe { std::ptr::read_unaligned(body.as_ptr() as *const FuseFallocateIn) };

        match self.fs.fallocate(
            fallocate_in.fh,
            fallocate_in.mode,
            fallocate_in.offset,
            fallocate_in.length,
        ) {
            Ok(()) => response.write_empty(ctx.unique),
            Err(e) => response.write_error(ctx.unique, e.to_errno()),
        }
    }
}
