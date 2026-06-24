use super::*;

impl FuseDispatcher {
    pub(super) fn handle_mknod(
        &self,
        ctx: &RequestContext,
        body: &[u8],
        response: &mut ResponseBuilder,
    ) {
        if body.len() < size_of::<FuseMknodIn>() {
            response.write_error(ctx.unique, libc::EINVAL);
            return;
        }

        // SAFETY: FuseMknodIn may sit at an unaligned offset in the VirtIO buffer.
        let mknod_in = unsafe { std::ptr::read_unaligned(body.as_ptr() as *const FuseMknodIn) };
        let name = self.parse_name(&body[size_of::<FuseMknodIn>()..]);

        match self
            .fs
            .mknod(ctx.nodeid, name, mknod_in.mode, u64::from(mknod_in.rdev))
        {
            Ok((inode, attr)) => {
                let entry = self.make_entry_out(inode, &attr);
                response.write_data(ctx.unique, &entry);
            }
            Err(e) => response.write_error(ctx.unique, e.to_errno()),
        }
    }

    pub(super) fn handle_mkdir(
        &self,
        ctx: &RequestContext,
        body: &[u8],
        response: &mut ResponseBuilder,
    ) {
        if body.len() < size_of::<FuseMkdirIn>() {
            response.write_error(ctx.unique, libc::EINVAL);
            return;
        }

        // SAFETY: FuseMkdirIn may sit at an unaligned offset in the VirtIO buffer.
        let mkdir_in = unsafe { std::ptr::read_unaligned(body.as_ptr() as *const FuseMkdirIn) };
        let name = self.parse_name(&body[size_of::<FuseMkdirIn>()..]);

        match self.fs.mkdir(ctx.nodeid, name, mkdir_in.mode) {
            Ok((inode, attr)) => {
                let entry = self.make_entry_out(inode, &attr);
                response.write_data(ctx.unique, &entry);
            }
            Err(e) => response.write_error(ctx.unique, e.to_errno()),
        }
    }

    pub(super) fn handle_symlink(
        &self,
        ctx: &RequestContext,
        body: &[u8],
        response: &mut ResponseBuilder,
    ) {
        // Body: name\0linkname\0
        let parts: Vec<&[u8]> = body.splitn(2, |&b| b == 0).collect();
        if parts.len() < 2 {
            response.write_error(ctx.unique, libc::EINVAL);
            return;
        }

        let name = OsStr::from_bytes(parts[0]);
        let link_target = Path::new(OsStr::from_bytes(
            parts[1].split(|&b| b == 0).next().unwrap_or(&[]),
        ));

        match self.fs.symlink(ctx.nodeid, name, link_target) {
            Ok((inode, attr)) => {
                let entry = self.make_entry_out(inode, &attr);
                response.write_data(ctx.unique, &entry);
            }
            Err(e) => response.write_error(ctx.unique, e.to_errno()),
        }
    }

    pub(super) fn handle_link(
        &self,
        ctx: &RequestContext,
        body: &[u8],
        response: &mut ResponseBuilder,
    ) {
        if body.len() < size_of::<FuseLinkIn>() {
            response.write_error(ctx.unique, libc::EINVAL);
            return;
        }

        // SAFETY: FuseLinkIn may sit at an unaligned offset in the VirtIO buffer.
        let link_in = unsafe { std::ptr::read_unaligned(body.as_ptr() as *const FuseLinkIn) };
        let name = self.parse_name(&body[size_of::<FuseLinkIn>()..]);

        match self.fs.link(link_in.oldnodeid, ctx.nodeid, name) {
            Ok((inode, attr)) => {
                let entry = self.make_entry_out(inode, &attr);
                response.write_data(ctx.unique, &entry);
            }
            Err(e) => response.write_error(ctx.unique, e.to_errno()),
        }
    }

    pub(super) fn handle_create(
        &self,
        ctx: &RequestContext,
        body: &[u8],
        response: &mut ResponseBuilder,
    ) {
        if body.len() < size_of::<FuseCreateIn>() {
            response.write_error(ctx.unique, libc::EINVAL);
            return;
        }

        // SAFETY: FuseCreateIn may sit at an unaligned offset in the VirtIO buffer.
        let create_in = unsafe { std::ptr::read_unaligned(body.as_ptr() as *const FuseCreateIn) };
        let name = self.parse_name(&body[size_of::<FuseCreateIn>()..]);

        match self
            .fs
            .create(ctx.nodeid, name, create_in.mode, create_in.flags)
        {
            Ok((inode, attr, handle)) => {
                let entry = self.make_entry_out(inode, &attr);
                let open_out = FuseOpenOut {
                    fh: handle,
                    open_flags: 0,
                    padding: 0,
                };

                // Write entry followed by open response
                response.buffer.clear();
                let len = (FuseOutHeader::SIZE
                    + size_of::<FuseEntryOut>()
                    + size_of::<FuseOpenOut>()) as u32;
                let header = FuseOutHeader::success(ctx.unique, len);
                response.write_struct(&header);
                response.write_struct(&entry);
                response.write_struct(&open_out);
            }
            Err(e) => response.write_error(ctx.unique, e.to_errno()),
        }
    }

    pub(super) fn handle_unlink(
        &self,
        ctx: &RequestContext,
        body: &[u8],
        response: &mut ResponseBuilder,
    ) {
        let name = self.parse_name(body);

        match self.fs.unlink(ctx.nodeid, name) {
            Ok(()) => response.write_empty(ctx.unique),
            Err(e) => response.write_error(ctx.unique, e.to_errno()),
        }
    }

    pub(super) fn handle_rmdir(
        &self,
        ctx: &RequestContext,
        body: &[u8],
        response: &mut ResponseBuilder,
    ) {
        let name = self.parse_name(body);

        match self.fs.rmdir(ctx.nodeid, name) {
            Ok(()) => response.write_empty(ctx.unique),
            Err(e) => response.write_error(ctx.unique, e.to_errno()),
        }
    }

    pub(super) fn handle_rename(
        &self,
        ctx: &RequestContext,
        body: &[u8],
        response: &mut ResponseBuilder,
    ) {
        if body.len() < size_of::<FuseRenameIn>() {
            response.write_error(ctx.unique, libc::EINVAL);
            return;
        }

        // SAFETY: FuseRenameIn may sit at an unaligned offset in the VirtIO buffer.
        let rename_in = unsafe { std::ptr::read_unaligned(body.as_ptr() as *const FuseRenameIn) };
        let names = &body[size_of::<FuseRenameIn>()..];

        // Parse old_name\0new_name\0
        let parts: Vec<&[u8]> = names.splitn(2, |&b| b == 0).collect();
        if parts.len() < 2 {
            response.write_error(ctx.unique, libc::EINVAL);
            return;
        }

        let old_name = OsStr::from_bytes(parts[0]);
        let new_name = OsStr::from_bytes(parts[1].split(|&b| b == 0).next().unwrap_or(&[]));

        match self
            .fs
            .rename(ctx.nodeid, old_name, rename_in.newdir, new_name, 0)
        {
            Ok(()) => response.write_empty(ctx.unique),
            Err(e) => response.write_error(ctx.unique, e.to_errno()),
        }
    }
}
