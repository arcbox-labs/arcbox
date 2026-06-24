use super::*;

impl FuseDispatcher {
    pub(super) fn handle_opendir(
        &self,
        ctx: &RequestContext,
        body: &[u8],
        response: &mut ResponseBuilder,
    ) {
        if body.len() < size_of::<FuseOpenIn>() {
            response.write_error(ctx.unique, libc::EINVAL);
            return;
        }

        match self.fs.opendir(ctx.nodeid) {
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

    pub(super) fn handle_readdir(
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

        match self.fs.readdir(read_in.fh, read_in.offset) {
            Ok(entries) => {
                let mut dirent_buf = Vec::new();
                let base_offset = read_in.offset + 1;

                for (i, entry) in entries.into_iter().enumerate() {
                    let name_bytes = entry.name.as_bytes();
                    let entry_size = FuseDirent::size(name_bytes.len());

                    // Check if we have room in the buffer
                    if dirent_buf.len() + entry_size > read_in.size as usize {
                        break;
                    }

                    let dirent = FuseDirent {
                        ino: entry.ino,
                        off: base_offset + i as u64,
                        namelen: name_bytes.len() as u32,
                        typ: entry.file_type.to_dirent_type(),
                    };

                    // Write dirent header
                    let dirent_bytes = unsafe {
                        std::slice::from_raw_parts(
                            std::ptr::from_ref::<FuseDirent>(&dirent) as *const u8,
                            size_of::<FuseDirent>(),
                        )
                    };
                    dirent_buf.extend_from_slice(dirent_bytes);

                    // Write name
                    dirent_buf.extend_from_slice(name_bytes);

                    // Pad to 8-byte boundary
                    let padding = entry_size - size_of::<FuseDirent>() - name_bytes.len();
                    dirent_buf.extend(std::iter::repeat_n(0u8, padding));
                }

                response.write_bytes(ctx.unique, &dirent_buf);
            }
            Err(e) => response.write_error(ctx.unique, e.to_errno()),
        }
    }

    /// Handles FUSE_READDIRPLUS: like readdir but each entry includes a full
    /// `FuseEntryOut` with inode attributes and cache timeouts. This allows
    /// the guest kernel to populate its dcache and icache in a single round
    /// trip, eliminating separate LOOKUP calls after directory listing.
    pub(super) fn handle_readdirplus(
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

        match self.fs.readdir(read_in.fh, read_in.offset) {
            Ok(entries) => {
                let mut buf = Vec::new();
                let mut offset = read_in.offset + 1;

                for entry in entries {
                    let name_bytes = entry.name.as_bytes();
                    // READDIRPLUS entry: FuseEntryOut + FuseDirent + name + padding
                    let dirent_size = FuseDirent::size(name_bytes.len());
                    let entry_size = size_of::<FuseEntryOut>() + dirent_size;

                    // Check if we have room in the buffer
                    if buf.len() + entry_size > read_in.size as usize {
                        break;
                    }

                    // Try to get attributes for this entry via getattr.
                    // If getattr fails (e.g. inode disappeared between opendir
                    // and readdirplus) we skip the entry rather than failing
                    // the entire request.
                    let attr = match self.fs.getattr(entry.ino) {
                        Ok(attr) => attr,
                        Err(_) => continue,
                    };

                    // Build the entry_out with cache timeouts
                    let entry_out = self.make_entry_out(entry.ino, &attr);

                    // Write FuseEntryOut
                    let entry_out_bytes = unsafe {
                        std::slice::from_raw_parts(
                            std::ptr::from_ref::<FuseEntryOut>(&entry_out) as *const u8,
                            size_of::<FuseEntryOut>(),
                        )
                    };
                    buf.extend_from_slice(entry_out_bytes);

                    // Write FuseDirent header
                    let dirent = FuseDirent {
                        ino: entry.ino,
                        off: offset,
                        namelen: name_bytes.len() as u32,
                        typ: entry.file_type.to_dirent_type(),
                    };
                    let dirent_bytes = unsafe {
                        std::slice::from_raw_parts(
                            std::ptr::from_ref::<FuseDirent>(&dirent) as *const u8,
                            size_of::<FuseDirent>(),
                        )
                    };
                    buf.extend_from_slice(dirent_bytes);

                    // Write name
                    buf.extend_from_slice(name_bytes);

                    // Pad to 8-byte boundary
                    let padding = dirent_size - size_of::<FuseDirent>() - name_bytes.len();
                    buf.extend(std::iter::repeat_n(0u8, padding));

                    offset += 1;
                }

                response.write_bytes(ctx.unique, &buf);
            }
            Err(e) => response.write_error(ctx.unique, e.to_errno()),
        }
    }

    pub(super) fn handle_releasedir(
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

        match self.fs.releasedir(release_in.fh) {
            Ok(()) => response.write_empty(ctx.unique),
            Err(e) => response.write_error(ctx.unique, e.to_errno()),
        }
    }

    pub(super) fn handle_fsyncdir(
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

        match self.fs.fsyncdir(fsync_in.fh, datasync) {
            Ok(()) => response.write_empty(ctx.unique),
            Err(e) => response.write_error(ctx.unique, e.to_errno()),
        }
    }
}
