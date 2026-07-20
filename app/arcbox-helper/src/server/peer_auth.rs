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
//! Implementation uses the `security-framework` crate's code-signing bindings
//! (`GuestAttributes`, `SecCode`, `SecRequirement`).

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
            if check_code_signature_audit(&token, identifier, TEAM_ID) {
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
        if check_code_signature_pid(pid, identifier, TEAM_ID) {
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
    use std::os::unix::io::AsRawFd;

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

/// macOS `audit_token_t` — 8 × u32.
#[cfg(not(debug_assertions))]
#[repr(C)]
#[derive(Clone, Copy)]
struct AuditToken {
    vals: [u32; 8],
}

#[cfg(not(debug_assertions))]
impl AuditToken {
    fn zeroed() -> Self {
        Self { vals: [0; 8] }
    }

    fn as_bytes(&self) -> &[u8] {
        // SAFETY: plain POD, no padding concerns for [u32; 8].
        unsafe {
            std::slice::from_raw_parts(
                std::ptr::from_ref(self).cast::<u8>(),
                std::mem::size_of::<Self>(),
            )
        }
    }
}

/// Peer audit token via `LOCAL_PEERTOKEN` (macOS).
#[cfg(not(debug_assertions))]
fn peer_audit_token(stream: &tokio::net::UnixStream) -> Option<AuditToken> {
    use std::os::unix::io::AsRawFd;

    let fd = stream.as_raw_fd();
    let mut token = AuditToken::zeroed();
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
fn requirement_string(identifier: &str, team_id: &str) -> String {
    format!(
        "identifier \"{identifier}\" and \
         anchor apple generic and \
         certificate leaf[subject.OU] = \"{team_id}\""
    )
}

/// Flags accepted by `SecCodeCheckValidity` for a live process.
///
/// Nested and strict validation flags are for static bundle validation and
/// make the dynamic API fail with `errSecCSInvalidFlags`.
#[cfg(all(target_os = "macos", any(test, not(debug_assertions))))]
fn dynamic_validation_flags() -> security_framework::os::macos::code_signing::Flags {
    use security_framework::os::macos::code_signing::Flags;
    Flags::NONE
}

#[cfg(not(debug_assertions))]
fn check_code_signature_pid(pid: i32, identifier: &str, team_id: &str) -> bool {
    use security_framework::os::macos::code_signing::{GuestAttributes, SecCode, SecRequirement};

    let mut attrs = GuestAttributes::new();
    attrs.set_pid(pid);
    let Ok(code) = SecCode::copy_guest_with_attribues(None, &attrs, Default::default()) else {
        return false;
    };
    let Ok(req) = requirement_string(identifier, team_id).parse::<SecRequirement>() else {
        return false;
    };
    code.check_validity(dynamic_validation_flags(), &req)
        .is_ok()
}

#[cfg(not(debug_assertions))]
fn check_code_signature_audit(token: &AuditToken, identifier: &str, team_id: &str) -> bool {
    use core_foundation::base::TCFType;
    use core_foundation::data::CFData;
    use security_framework::os::macos::code_signing::{GuestAttributes, SecCode, SecRequirement};

    let token_data = CFData::from_buffer(token.as_bytes());
    let mut attrs = GuestAttributes::new();
    attrs.set_audit_token(token_data.as_concrete_TypeRef());

    let Ok(code) = SecCode::copy_guest_with_attribues(None, &attrs, Default::default()) else {
        return false;
    };
    let Ok(req) = requirement_string(identifier, team_id).parse::<SecRequirement>() else {
        return false;
    };
    code.check_validity(dynamic_validation_flags(), &req)
        .is_ok()
}

#[cfg(test)]
mod tests {
    #[test]
    fn allowed_identifiers_are_nonempty_and_arcbox() {
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
    #[cfg(target_os = "macos")]
    fn dynamic_validation_flags_are_accepted_by_security_framework() {
        use security_framework::os::macos::code_signing::{Flags, SecCode, SecRequirement};

        let code = SecCode::for_self(Flags::NONE).expect("test process should be inspectable");
        let requirement = "true"
            .parse::<SecRequirement>()
            .expect("unconditional requirement should parse");

        code.check_validity(super::dynamic_validation_flags(), &requirement)
            .expect("dynamic code validation flags should be accepted");
    }
}
