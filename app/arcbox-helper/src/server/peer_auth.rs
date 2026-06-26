//! Peer authentication via macOS code signature verification.
//!
//! On each accepted connection, the server:
//! 1. Gets the peer PID via `LOCAL_PEERPID`
//! 2. Obtains a `SecCodeRef` for that PID from Security.framework
//! 3. Validates the code signature against an allow-list of identifiers
//!    signed by Team ID 422ACSY6Y5
//!
//! In debug builds, authentication is skipped to allow adhoc-signed
//! development binaries to connect.

use std::os::unix::io::AsRawFd;

// TODO: enable when peer verification is wired up
#[allow(dead_code)]
/// ArcBox Team ID (Apple Developer Portal).
const TEAM_ID: &str = "422ACSY6Y5";

// TODO: enable when peer verification is wired up
#[allow(dead_code)]
/// Bundle identifiers allowed to connect to the helper.
const ALLOWED_IDENTIFIERS: &[&str] = &[
    "com.arcboxlabs.desktop.daemon",
    "com.arcboxlabs.desktop.dev.daemon",
    "com.arcboxlabs.desktop.cli",
    "com.arcboxlabs.desktop",
    "com.arcboxlabs.desktop.dev",
];

/// Returns `true` if the peer on the other end of `stream` is an
/// ArcBox-signed binary. In debug builds, always returns `true`.
pub fn verify(stream: &tokio::net::UnixStream) -> bool {
    if cfg!(debug_assertions) {
        return true;
    }

    verify_release(stream)
}

#[cfg(not(debug_assertions))]
fn verify_release(stream: &tokio::net::UnixStream) -> bool {
    let Some(pid) = peer_pid(stream) else {
        tracing::warn!("peer auth: failed to get peer PID");
        return false;
    };

    for identifier in ALLOWED_IDENTIFIERS {
        if check_code_signature(pid, identifier, TEAM_ID) {
            return true;
        }
    }

    tracing::warn!(pid, "peer auth: rejected (no matching code signature)");
    false
}

#[cfg(debug_assertions)]
fn verify_release(_stream: &tokio::net::UnixStream) -> bool {
    true
}

/// Gets the PID of the peer process via `LOCAL_PEERPID`.
// TODO: enable when peer verification is wired up
#[allow(dead_code)]
fn peer_pid(stream: &tokio::net::UnixStream) -> Option<i32> {
    let fd = stream.as_raw_fd();
    let mut pid: libc::pid_t = 0;
    let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;

    // SAFETY: getsockopt with valid fd and correctly sized buffer.
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            std::ptr::addr_of_mut!(pid).cast::<libc::c_void>(),
            &raw mut len,
        )
    };

    if ret == 0 { Some(pid) } else { None }
}

#[cfg(not(debug_assertions))]
mod security {
    use std::ffi::c_void;
    use std::ptr;

    // Opaque types from Security.framework.
    type SecCodeRef = *const c_void;
    type SecRequirementRef = *const c_void;

    // CoreFoundation types.
    type CFDictionaryRef = *const c_void;
    type CFStringRef = *const c_void;
    type CFNumberRef = *const c_void;
    type CFAllocatorRef = *const c_void;

    const K_CF_ALLOCATOR_DEFAULT: CFAllocatorRef = ptr::null();
    const K_CF_NUMBER_INT_TYPE: isize = 9; // kCFNumberIntType

    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        fn SecCodeCopyGuestWithAttributes(
            host: SecCodeRef,
            attrs: CFDictionaryRef,
            flags: u32,
            guest: *mut SecCodeRef,
        ) -> i32;

        fn SecCodeCheckValidity(
            code: SecCodeRef,
            flags: u32,
            requirement: SecRequirementRef,
        ) -> i32;

        fn SecRequirementCreateWithString(
            text: CFStringRef,
            flags: u32,
            requirement: *mut SecRequirementRef,
        ) -> i32;

        static kSecGuestAttributePid: CFStringRef;
    }

    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFDictionaryCreate(
            allocator: CFAllocatorRef,
            keys: *const *const c_void,
            values: *const *const c_void,
            num_values: isize,
            key_callbacks: *const c_void,
            value_callbacks: *const c_void,
        ) -> CFDictionaryRef;

        fn CFNumberCreate(
            allocator: CFAllocatorRef,
            the_type: isize,
            value_ptr: *const c_void,
        ) -> CFNumberRef;

        fn CFRelease(cf: *const c_void);

        static kCFTypeDictionaryKeyCallBacks: c_void;
        static kCFTypeDictionaryValueCallBacks: c_void;
    }

    /// Creates a CFString from a Rust &str. Caller must CFRelease.
    unsafe fn cf_string(s: &str) -> CFStringRef {
        #[link(name = "CoreFoundation", kind = "framework")]
        unsafe extern "C" {
            fn CFStringCreateWithBytes(
                alloc: CFAllocatorRef,
                bytes: *const u8,
                num_bytes: isize,
                encoding: u32,
                is_external: u8,
            ) -> CFStringRef;
        }

        const K_CF_STRING_ENCODING_UTF8: u32 = 0x08000100;

        let num_bytes = match isize::try_from(s.len()) {
            Ok(n) => n,
            Err(_) => return std::ptr::null(),
        };

        unsafe {
            CFStringCreateWithBytes(
                K_CF_ALLOCATOR_DEFAULT,
                s.as_ptr(),
                num_bytes,
                K_CF_STRING_ENCODING_UTF8,
                0,
            )
        }
    }

    /// Verifies that `pid` is signed with `identifier` by `team_id`.
    pub fn check_code_signature(pid: i32, identifier: &str, team_id: &str) -> bool {
        unsafe {
            // Build attributes dict: { kSecGuestAttributePid: pid }
            let pid_number = CFNumberCreate(
                K_CF_ALLOCATOR_DEFAULT,
                K_CF_NUMBER_INT_TYPE,
                (&raw const pid).cast::<c_void>(),
            );
            if pid_number.is_null() {
                return false;
            }

            let keys = [kSecGuestAttributePid];
            let values = [pid_number];
            let attrs = CFDictionaryCreate(
                K_CF_ALLOCATOR_DEFAULT,
                keys.as_ptr(),
                values.as_ptr(),
                1,
                &raw const kCFTypeDictionaryKeyCallBacks,
                &raw const kCFTypeDictionaryValueCallBacks,
            );
            CFRelease(pid_number);

            if attrs.is_null() {
                return false;
            }

            // Get SecCodeRef for the PID.
            let mut code: SecCodeRef = ptr::null();
            let status = SecCodeCopyGuestWithAttributes(ptr::null(), attrs, 0, &raw mut code);
            CFRelease(attrs);

            if status != 0 || code.is_null() {
                return false;
            }

            // Build requirement string.
            let req_str = format!(
                "identifier \"{identifier}\" and \
                 anchor apple generic and \
                 certificate leaf[subject.OU] = \"{team_id}\""
            );
            let cf_req_str = cf_string(&req_str);
            if cf_req_str.is_null() {
                CFRelease(code);
                return false;
            }

            let mut requirement: SecRequirementRef = ptr::null();
            let status = SecRequirementCreateWithString(cf_req_str, 0, &raw mut requirement);
            CFRelease(cf_req_str);

            if status != 0 || requirement.is_null() {
                CFRelease(code);
                return false;
            }

            // Validate!
            let status = SecCodeCheckValidity(code, 0, requirement);
            CFRelease(requirement);
            CFRelease(code);

            status == 0
        }
    }
}

#[cfg(not(debug_assertions))]
fn check_code_signature(pid: i32, identifier: &str, team_id: &str) -> bool {
    security::check_code_signature(pid, identifier, team_id)
}
