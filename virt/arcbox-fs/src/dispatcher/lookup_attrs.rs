use super::*;

impl FuseDispatcher {
    pub(super) fn handle_destroy(&self, ctx: &RequestContext, response: &mut ResponseBuilder) {
        response.write_empty(ctx.unique);
    }

    pub(super) fn handle_lookup(
        &self,
        ctx: &RequestContext,
        body: &[u8],
        response: &mut ResponseBuilder,
    ) {
        // Body is null-terminated name
        let name = self.parse_name(body);

        match self.fs.lookup(ctx.nodeid, name) {
            Ok((inode, attr)) => {
                let entry = self.make_entry_out(inode, &attr);
                response.write_data(ctx.unique, &entry);
            }
            Err(e) => response.write_error(ctx.unique, e.to_errno()),
        }
    }

    pub(super) fn handle_forget(
        &self,
        ctx: &RequestContext,
        body: &[u8],
        response: &mut ResponseBuilder,
    ) {
        if body.len() >= size_of::<FuseForgetIn>() {
            // SAFETY: FuseForgetIn may sit at an unaligned offset in the VirtIO buffer.
            let forget_in =
                unsafe { std::ptr::read_unaligned(body.as_ptr() as *const FuseForgetIn) };
            self.fs.forget(ctx.nodeid, forget_in.nlookup);
        }
        // FORGET has no response
        let _ = response;
    }

    pub(super) fn handle_getattr(
        &self,
        ctx: &RequestContext,
        _body: &[u8],
        response: &mut ResponseBuilder,
    ) {
        match self.fs.getattr(ctx.nodeid) {
            Ok(attr) => {
                let attr_out = FuseAttrOut {
                    attr_valid: self.config.attr_timeout,
                    attr_valid_nsec: 0,
                    dummy: 0,
                    attr,
                };
                response.write_data(ctx.unique, &attr_out);
            }
            Err(e) => response.write_error(ctx.unique, e.to_errno()),
        }
    }

    pub(super) fn handle_setattr(
        &self,
        ctx: &RequestContext,
        body: &[u8],
        response: &mut ResponseBuilder,
    ) {
        if body.len() < size_of::<FuseSetattrIn>() {
            response.write_error(ctx.unique, libc::EINVAL);
            return;
        }

        // SAFETY: FuseSetattrIn may sit at an unaligned offset in the VirtIO buffer.
        let setattr_in = unsafe { std::ptr::read_unaligned(body.as_ptr() as *const FuseSetattrIn) };

        let mode = if setattr_in.valid & FATTR_MODE != 0 {
            Some(setattr_in.mode)
        } else {
            None
        };

        let uid = if setattr_in.valid & FATTR_UID != 0 {
            Some(setattr_in.uid)
        } else {
            None
        };

        let gid = if setattr_in.valid & FATTR_GID != 0 {
            Some(setattr_in.gid)
        } else {
            None
        };

        let size = if setattr_in.valid & FATTR_SIZE != 0 {
            Some(setattr_in.size)
        } else {
            None
        };

        let atime = if setattr_in.valid & FATTR_ATIME != 0 {
            Some((setattr_in.atime as i64, setattr_in.atimensec))
        } else {
            None
        };

        let mtime = if setattr_in.valid & FATTR_MTIME != 0 {
            Some((setattr_in.mtime as i64, setattr_in.mtimensec))
        } else {
            None
        };

        match self
            .fs
            .setattr(ctx.nodeid, mode, uid, gid, size, atime, mtime)
        {
            Ok(attr) => {
                let attr_out = FuseAttrOut {
                    attr_valid: self.config.attr_timeout,
                    attr_valid_nsec: 0,
                    dummy: 0,
                    attr,
                };
                response.write_data(ctx.unique, &attr_out);
            }
            Err(e) => response.write_error(ctx.unique, e.to_errno()),
        }
    }

    pub(super) fn handle_readlink(&self, ctx: &RequestContext, response: &mut ResponseBuilder) {
        match self.fs.readlink(ctx.nodeid) {
            Ok(target) => {
                response.write_bytes(ctx.unique, target.as_os_str().as_bytes());
            }
            Err(e) => response.write_error(ctx.unique, e.to_errno()),
        }
    }
}
