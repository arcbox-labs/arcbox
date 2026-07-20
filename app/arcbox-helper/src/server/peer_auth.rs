//! Peer authentication via macOS code signature verification.
//!
//! **Release builds** reject any connection whose peer is not an ArcBox-signed
//! binary (Team ID + allow-listed identifier). This is the primary auth gate:
//! the launchd socket is world-connectable (`SockPathMode` 0666) so input
//! validation alone is not enough.
//!
//! **Debug builds** skip verification so ad-hoc-signed local binaries can talk
//! to a manually started helper.
//!
//! ## Threat model (socket `0666`)
//!
//! Any local process can *connect* to `/var/run/arcbox-helper.sock`. Privilege
//! is enforced here, not by filesystem mode:
//! - Release: `SecCodeCheckValidity` against identifier + Team ID.
//! - Prefer `LOCAL_PEERTOKEN` (audit token) so the check binds to the live
//!   connecting process, not a recycled PID.
//! - Fall back to `LOCAL_PEERPID` when the token sockopt is unavailable.
//! - Debug: skip (dev ergonomics only — never ship a release helper without
//!   this gate).
//!
//! Authentication flow (release):
//! 1. Prefer `LOCAL_PEERTOKEN` when the kernel provides it.
//! 2. Fall back to `LOCAL_PEERPID`.
//! 3. `SecCodeCopyGuestWithAttributes` → `SecCodeCheckValidity` against
//!    `identifier "…" and anchor apple generic and certificate leaf[subject.OU] = "TEAM"`.

#[cfg(not(debug_assertions))]
use std::os::unix::io::AsRawFd;

/// ArcBox Team ID (Apple Developer Portal).
#[cfg(any(test, not(debug_assertions)))]
const TEAM_ID: &str = "422ACSY6Y5";

/// Bundle / code-signing identifiers allowed to connect to the helper.
#[cfg(any(test, not(debug_assertions)))]
const ALLOWED_IDENTIFIERS: &[&str] = &[
    "com.arcboxlabs.desktop.daemon",
    "com.arcboxlabs.desktop.dev.daemon",
    "com.arcboxlabs.desktop.cli",
    "com.arcboxlabs.desktop",
    "com.arcboxlabs.desktop.dev",
];

// SOL_LOCAL sockopts (sys/un.h / XNU). Not always exposed by libc bindings.
#[cfg(not(debug_assertions))]
const LOCAL_PEERPID: libc::c_int = 0x002;
#[cfg(not(debug_assertions))]
const LOCAL_PEERTOKEN: libc::c_int = 0x006;

/// Returns `true` if the peer on `stream` is allowed to call privileged RPCs.
///
/// Debug builds always return `true`. Release builds require a matching
/// code signature; failures are logged and the connection is dropped.
#[cfg(debug_assertions)]
pub fn verify(_stream: &tokio::net::UnixStream) -> bool {
    true
}

/// Release: prefer audit-token binding; fall back to PID if the sockopt fails.
#[cfg(not(debug_assertions))]
pub fn verify(stream: &tokio::net::UnixStream) -> bool {
    if let Some(token) = peer_audit_token(stream) {
        for identifier in ALLOWED_IDENTIFIERS {
            if security::check_code_signature_audit(&token, identifier, TEAM_ID) {
                tracing::debug!(identifier, source = "audit_token", "peer auth: accepted");
                return true;
            }
        }
        tracing::warn!(
            source = "audit_token",
            stage = "code_signature",
            "peer auth: rejected (no matching code signature)"
        );
        return false;
    }

    let Some(pid) = peer_pid(stream) else {
        tracing::warn!(
            source = "none",
            stage = "peer_identity",
            "peer auth: failed to get peer PID or audit token"
        );
        return false;
    };

    for identifier in ALLOWED_IDENTIFIERS {
        if security::check_code_signature_pid(pid, identifier, TEAM_ID) {
            tracing::debug!(pid, identifier, source = "pid", "peer auth: accepted");
            return true;
        }
    }

    tracing::warn!(
        pid,
        source = "pid",
        stage = "code_signature",
        "peer auth: rejected (no matching code signature)"
    );
    false
}

/// Peer PID via `LOCAL_PEERPID`.
#[cfg(not(debug_assertions))]
fn peer_pid(stream: &tokio::net::UnixStream) -> Option<i32> {
    let fd = stream.as_raw_fd();
    let mut pid: libc::pid_t = 0;
    let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;

    // SAFETY: getsockopt with a valid fd and correctly sized buffer.
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_LOCAL,
            LOCAL_PEERPID,
            std::ptr::addr_of_mut!(pid).cast::<libc::c_void>(),
            &raw mut len,
        )
    };

    if ret == 0 { Some(pid) } else { None }
}

/// Peer audit token via `LOCAL_PEERTOKEN` (macOS).
#[cfg(not(debug_assertions))]
fn peer_audit_token(stream: &tokio::net::UnixStream) -> Option<security::AuditToken> {
    let fd = stream.as_raw_fd();
    let mut token = security::AuditToken::zeroed();
    let mut len = std::mem::size_of_val(&token) as libc::socklen_t;

    // SAFETY: getsockopt with a valid fd and correctly sized audit_token_t.
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_LOCAL,
            LOCAL_PEERTOKEN,
            std::ptr::addr_of_mut!(token).cast::<libc::c_void>(),
            &raw mut len,
        )
    };

    if ret == 0 { Some(token) } else { None }
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
    type CFDataRef = *const c_void;

    const K_CF_ALLOCATOR_DEFAULT: CFAllocatorRef = ptr::null();
    /// `kCFNumberIntType` (CFNumber.h).
    const K_CF_NUMBER_INT_TYPE: isize = 9;

    /// `kSecCSDefaultFlags | kSecCSCheckNestedCode | kSecCSStrictValidate`
    /// from SecStaticCode.h / CSCommon.h:
    /// - `kSecCSDefaultFlags = 0`
    /// - `kSecCSCheckNestedCode = 1 << 3`
    /// - `kSecCSStrictValidate = 1 << 4`
    // kSecCSDefaultFlags (= 0) is intentionally omitted: ORing identity zero
    // trips clippy::identity_op. Nested + strict is the full check set.
    pub(super) const SEC_CS_CHECK_FLAGS: u32 = (1 << 3) | (1 << 4);

    /// macOS `audit_token_t` — 8 × u32.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct AuditToken {
        vals: [u32; 8],
    }

    impl AuditToken {
        pub fn zeroed() -> Self {
            Self { vals: [0; 8] }
        }
    }

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
        static kSecGuestAttributeAudit: CFStringRef;
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

        fn CFDataCreate(allocator: CFAllocatorRef, bytes: *const u8, length: isize) -> CFDataRef;

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

        const K_CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;

        let Ok(num_bytes) = isize::try_from(s.len()) else {
            return std::ptr::null();
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

    fn requirement_string(identifier: &str, team_id: &str) -> String {
        // Apple generic anchor + leaf OU (Team ID). Matches Developer ID and
        // Apple Development leaves under the same team — both are used for
        // local daemon builds that still need helper access.
        format!(
            "identifier \"{identifier}\" and \
             anchor apple generic and \
             certificate leaf[subject.OU] = \"{team_id}\""
        )
    }

    /// Takes ownership of `attrs` (always CFRelease'd).
    unsafe fn check_with_attrs(attrs: CFDictionaryRef, identifier: &str, team_id: &str) -> bool {
        if attrs.is_null() {
            return false;
        }

        let mut code: SecCodeRef = ptr::null();
        let status =
            unsafe { SecCodeCopyGuestWithAttributes(ptr::null(), attrs, 0, &raw mut code) };
        unsafe { CFRelease(attrs) };

        if status != 0 || code.is_null() {
            return false;
        }

        let req_str = requirement_string(identifier, team_id);
        let cf_req_str = unsafe { cf_string(&req_str) };
        if cf_req_str.is_null() {
            unsafe { CFRelease(code) };
            return false;
        }

        let mut requirement: SecRequirementRef = ptr::null();
        let status = unsafe { SecRequirementCreateWithString(cf_req_str, 0, &raw mut requirement) };
        unsafe { CFRelease(cf_req_str) };

        if status != 0 || requirement.is_null() {
            unsafe { CFRelease(code) };
            return false;
        }

        let status = unsafe { SecCodeCheckValidity(code, SEC_CS_CHECK_FLAGS, requirement) };
        unsafe {
            CFRelease(requirement);
            CFRelease(code);
        }

        status == 0
    }

    /// Verifies that `pid` is signed with `identifier` by `team_id`.
    pub fn check_code_signature_pid(pid: i32, identifier: &str, team_id: &str) -> bool {
        unsafe {
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
                keys.as_ptr().cast(),
                values.as_ptr().cast(),
                1,
                &raw const kCFTypeDictionaryKeyCallBacks,
                &raw const kCFTypeDictionaryValueCallBacks,
            );
            // Dictionary retains values; release our local ref.
            CFRelease(pid_number);

            check_with_attrs(attrs, identifier, team_id)
        }
    }

    /// Verifies the process identified by `token` is signed with `identifier`
    /// by `team_id`. Prefer this over PID when `LOCAL_PEERTOKEN` is available.
    pub fn check_code_signature_audit(token: &AuditToken, identifier: &str, team_id: &str) -> bool {
        unsafe {
            let token_bytes = std::slice::from_raw_parts(
                std::ptr::from_ref(token).cast::<u8>(),
                std::mem::size_of::<AuditToken>(),
            );
            let Ok(len) = isize::try_from(token_bytes.len()) else {
                return false;
            };
            let token_data = CFDataCreate(K_CF_ALLOCATOR_DEFAULT, token_bytes.as_ptr(), len);
            if token_data.is_null() {
                return false;
            }

            let keys = [kSecGuestAttributeAudit];
            let values = [token_data];
            let attrs = CFDictionaryCreate(
                K_CF_ALLOCATOR_DEFAULT,
                keys.as_ptr().cast(),
                values.as_ptr().cast(),
                1,
                &raw const kCFTypeDictionaryKeyCallBacks,
                &raw const kCFTypeDictionaryValueCallBacks,
            );
            CFRelease(token_data);

            check_with_attrs(attrs, identifier, team_id)
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn allowed_identifiers_are_nonempty_and_arcbox() {
        // Compile-time sanity: every allowed id is under our reverse-DNS.
        for id in super::ALLOWED_IDENTIFIERS {
            assert!(
                id.starts_with("com.arcboxlabs."),
                "unexpected allow-listed identifier: {id}"
            );
        }
        assert!(!super::ALLOWED_IDENTIFIERS.is_empty());
        assert_eq!(super::TEAM_ID, "422ACSY6Y5");
    }

    #[test]
    #[cfg(not(debug_assertions))]
    fn sec_cs_check_flags_match_apple_headers() {
        // kSecCSCheckNestedCode = 1<<3, kSecCSStrictValidate = 1<<4
        assert_eq!(super::security::SEC_CS_CHECK_FLAGS, (1 << 3) | (1 << 4));
    }
}
