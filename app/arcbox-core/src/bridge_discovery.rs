//! Bridge discovery for L3 container routing (macOS only).
//!
//! Uses the `ifbridge` crate to query the kernel's bridge forwarding database
//! (FDB) directly via private ioctls, replacing fragile `ifconfig` text parsing.

use std::ffi::CString;

/// Information about a bridge interface suitable for container routing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeTarget {
    /// Interface name (e.g. "bridge104").
    pub name: String,
    /// Interface index (from `if_nametoindex`).
    pub ifindex: u16,
}

impl BridgeTarget {
    /// Returns whether this name still identifies the same kernel interface.
    #[must_use]
    pub fn is_current(&self) -> bool {
        if_nametoindex(&self.name) == Some(self.ifindex)
    }
}

/// Resolve a VM bridge MAC to a bridge interface.
///
/// Enumerates all bridges, queries each FDB, and returns the bridge that
/// has learned the given MAC address. This identifies which bridge the
/// VM's bridge NIC is connected to.
pub fn resolve_bridge_by_mac(mac_str: &str) -> Option<BridgeTarget> {
    let mac: ifbridge::MacAddr = mac_str.parse().ok()?;

    let bridge_name = ifbridge::find_bridge_by_mac(mac)
        .inspect_err(|e| tracing::debug!(error = %e, "bridge enumeration failed"))
        .ok()
        .flatten()?;

    let ifindex = if_nametoindex(&bridge_name)?;

    Some(BridgeTarget {
        name: bridge_name,
        ifindex,
    })
}

/// Find any bridge that has a vmenet member (quick check for `doctor`).
pub fn find_bridge_with_vmenet() -> Option<(String, String)> {
    let bridges = ifbridge::list_bridges().ok()?;
    for bridge in bridges {
        if let Ok(members) = ifbridge::list_members(&bridge) {
            for member in &members {
                if member.name.starts_with("vmenet") {
                    return Some((bridge, member.name.clone()));
                }
            }
        }
    }
    None
}

fn if_nametoindex(name: &str) -> Option<u16> {
    let cname = CString::new(name).ok()?;
    // SAFETY: if_nametoindex is a standard POSIX function with a valid C string.
    let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if idx == 0 {
        None
    } else {
        u16::try_from(idx).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_nonexistent_mac() {
        // Should return None, not panic.
        assert!(resolve_bridge_by_mac("ff:ff:ff:ff:ff:ff").is_none());
    }

    #[test]
    fn test_resolve_invalid_mac() {
        assert!(resolve_bridge_by_mac("not-a-mac").is_none());
    }

    #[test]
    fn test_find_bridge_with_vmenet_no_panic() {
        // Should not panic regardless of system state.
        let _ = find_bridge_with_vmenet();
    }
}
