//! Sandbox error-registry attachment (CORE-58 phase 2).
//!
//! Daemon-originated sandbox errors attach the registry detail directly
//! (see [`nested_virt_unsupported`]); guest agent errors are classified
//! centrally in `crate::error`'s `ApiError → ConnectError` conversion,
//! which every sandbox handler already funnels through. The shared
//! `ErrorInfo` builder lives in `crate::error::error_info`.

use arcbox_connect::sandbox_v1 as pb;
use connectrpc::{ConnectError, ErrorCode as ConnectCode};

use crate::error::error_info;

/// The CORE-13 fail-fast error for `Create` on a host without nested virt.
///
/// `FAILED_PRECONDITION` carrying `NESTED_VIRT_UNSUPPORTED` with the
/// daemon's authoritative reason, exactly what `GetCapabilities` reports.
pub(super) fn nested_virt_unsupported(
    capability: &arcbox_core::NestedVirtCapability,
) -> ConnectError {
    let mut error = ConnectError::new(
        ConnectCode::FailedPrecondition,
        format!("sandboxes cannot run on this host: {}", capability.reason),
    );
    error.details.push(error_info(
        pb::ErrorCode::NestedVirtUnsupported,
        "check `SandboxService.GetCapabilities` for this host's sandbox support",
        &[("reason", capability.reason.as_str())],
    ));
    error
}
