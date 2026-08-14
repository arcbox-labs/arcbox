//! Bridge discovery for L3 container routing (macOS only).
//!
//! Uses the `ifbridge` crate to query the kernel's bridge forwarding database
//! (FDB) directly via private ioctls, replacing fragile `ifconfig` text parsing.

use std::ffi::CString;

/// Information about a bridge interface suitable for container routing.
#[derive(Debug, Clone)]
pub struct BridgeTarget {
    /// Interface name (e.g. "bridge104").
    pub name: String,
    /// Interface index (from `if_nametoindex`).
    pub ifindex: u32,
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

fn if_nametoindex(name: &str) -> Option<u32> {
    let cname = CString::new(name).ok()?;
    // SAFETY: if_nametoindex is a standard POSIX function with a valid C string.
    let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if idx == 0 { None } else { Some(idx) }
}

/// Recomposes the engine's vmnet interface MAC with host bridge discovery.
///
/// The engine exposes only the MAC of the vmnet shared interface
/// (`vmnet_interface_mac`); mapping it to the host bridge the system
/// created around it is host-side knowledge, so the composition lives
/// here, next to `resolve_bridge_by_mac`.
#[cfg(feature = "vmnet")]
pub trait MachineBridgeExt {
    /// Returns the host bridge interface name for the machine's vmnet NIC.
    fn vmnet_bridge_name(&self, name: &str) -> Option<String>;
}

#[cfg(feature = "vmnet")]
impl MachineBridgeExt for arcbox_engine::machine::MachineManager {
    fn vmnet_bridge_name(&self, name: &str) -> Option<String> {
        let mac = self.vmnet_interface_mac(name)?;
        resolve_bridge_by_mac(&mac).map(|bridge| bridge.name)
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
