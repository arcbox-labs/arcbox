//! VPN awareness.

/// VPN detector.
pub struct VpnDetector {
    // TODO: VPN detection state
}

impl VpnDetector {
    /// Creates a new VPN detector.
    #[must_use]
    pub fn new() -> Self {
        Self {}
    }

    /// Checks if a VPN is active.
    #[must_use]
    pub fn is_vpn_active(&self) -> bool {
        // TODO: Detect VPN
        false
    }

    /// Gets VPN interface name.
    #[must_use]
    pub fn vpn_interface(&self) -> Option<String> {
        // TODO: Get VPN interface
        None
    }
}

impl Default for VpnDetector {
    fn default() -> Self {
        Self::new()
    }
}
