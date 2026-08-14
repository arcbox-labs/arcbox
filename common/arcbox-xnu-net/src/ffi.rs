//! Platform-specific FFI declarations for batch datagram syscalls.

#[cfg(target_os = "macos")]
pub mod darwin {
    use std::ffi::c_int;

    /// XNU's extended `msghdr` for batch I/O.
    ///
    /// Layout matches `struct msghdr_x` from `bsd/sys/socket_private.h`:
    /// identical to `struct msghdr` with an appended `msg_datalen` field.
    ///
    /// **Must be fully zeroed before each `recvmsg_x` call** — older XNU
    /// kernels validate all fields, not just the ones we set.
    #[repr(C)]
    #[derive(Clone, Copy)]
    #[allow(clippy::struct_field_names)] // mirrors the C struct naming
    #[allow(non_camel_case_types)]
    pub struct msghdr_x {
        pub msg_name: *mut libc::c_void,
        pub msg_namelen: libc::socklen_t,
        pub msg_iov: *mut libc::iovec,
        pub msg_iovlen: c_int,
        pub msg_control: *mut libc::c_void,
        pub msg_controllen: libc::socklen_t,
        pub msg_flags: c_int,
        /// Byte length of data transferred.
        /// - `recvmsg_x`: kernel fills this with actual received length.
        /// - `sendmsg_x`: ignored by kernel (data length comes from iovec).
        pub msg_datalen: usize,
    }

    // SAFETY: msghdr_x is a plain C struct with no interior references that
    // require thread-local access.
    unsafe impl Send for msghdr_x {}

    impl msghdr_x {
        /// Returns a zeroed instance. This is the ONLY correct way to
        /// initialize before passing to `recvmsg_x`.
        #[inline]
        pub fn zeroed() -> Self {
            // SAFETY: msghdr_x is repr(C) with all-zero-bits being valid
            // (null pointers, zero lengths/flags).
            unsafe { std::mem::zeroed() }
        }
    }

    /// Reads an integer `kern.ipc.max{send,recv}msgx` sysctl and clamps it to
    /// [`MAX_BATCH`](crate::MAX_BATCH).
    ///
    /// Both sysctls default to 256 but are tunable **down**, and a batch call
    /// with `cnt` above the live value fails outright with `EINVAL` instead of
    /// degrading to a shorter batch — so the value has to be read, not assumed.
    /// An unreadable or nonsensical sysctl falls back to 1, which is always
    /// legal and reduces batching to the unbatched syscall rate.
    pub fn sysctl_batch_cap(name: &std::ffi::CStr) -> usize {
        let mut value: c_int = 0;
        let mut len = std::mem::size_of::<c_int>();
        // SAFETY: `name` is a valid NUL-terminated C string; `value`/`len` are
        // a correctly sized out-parameter pair; the new-value pointer is null
        // (read-only query).
        let ret = unsafe {
            libc::sysctlbyname(
                name.as_ptr(),
                (&raw mut value).cast(),
                &raw mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if ret != 0 || value <= 0 {
            return 1;
        }
        (value as usize).min(crate::MAX_BATCH)
    }

    // Symbols exported from libsystem_kernel.dylib. No syscall numbers needed.
    unsafe extern "C" {
        /// Receive up to `cnt` datagrams in a single syscall.
        /// Returns the number of datagrams received, or -1 on error.
        pub fn recvmsg_x(s: c_int, msgp: *mut msghdr_x, cnt: libc::c_uint, flags: c_int) -> isize;

        /// Send up to `cnt` datagrams in a single syscall.
        /// Returns the number of datagrams sent, or -1 on error.
        pub fn sendmsg_x(s: c_int, msgp: *const msghdr_x, cnt: libc::c_uint, flags: c_int)
        -> isize;
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_msghdr_x_layout() {
            let base = std::mem::size_of::<libc::msghdr>();
            let extended = std::mem::size_of::<msghdr_x>();
            // msghdr_x extends msghdr with msg_datalen (usize) plus possible
            // padding. Verify the struct is at least as large as msghdr and
            // the growth is bounded.
            assert!(
                extended >= base,
                "msghdr_x ({extended}) must be >= msghdr ({base})"
            );
            assert!(
                extended - base <= std::mem::size_of::<usize>() * 2,
                "msghdr_x is unexpectedly larger than msghdr + usize + padding"
            );
        }

        #[test]
        fn test_msghdr_x_zeroed_is_safe() {
            let hdr = msghdr_x::zeroed();
            assert!(hdr.msg_name.is_null());
            assert_eq!(hdr.msg_namelen, 0);
            assert!(hdr.msg_iov.is_null());
            assert_eq!(hdr.msg_iovlen, 0);
            assert!(hdr.msg_control.is_null());
            assert_eq!(hdr.msg_controllen, 0);
            assert_eq!(hdr.msg_flags, 0);
            assert_eq!(hdr.msg_datalen, 0);
        }
    }
}

// Linux: no custom FFI needed — libc crate provides mmsghdr, recvmmsg, sendmmsg.
