//! Docker workload identifier classification helpers.

/// A short hex ID is at least 4 hex characters and shorter than a full
/// canonical ID. We use this as the trigger for prefix scans so non-hex
/// names like `alpine` don't pay the cost of a scan and arbitrary strings
/// can't accidentally prefix-match a canonical ID.
pub(super) fn is_hex_short_id(id: &str) -> bool {
    let len = id.len();
    (4..64).contains(&len) && id.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Docker container/exec canonical IDs are 64 lowercase hex characters.
pub(super) fn is_canonical_id(id: &str) -> bool {
    id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit())
}
