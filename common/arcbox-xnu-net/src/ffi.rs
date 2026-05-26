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
