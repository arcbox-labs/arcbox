//! Workload role definitions shared by the daemon, the runtime, and the
//! Docker compatibility layer.
//!
//! ArcBox runs two long-lived utility VM roles on macOS Apple Silicon:
//!
//! - [`UtilityVmRole::Native`] — the fast path backed by the custom HV
//!   hypervisor. Hosts `linux/arm64` workloads.
//! - [`UtilityVmRole::Rosetta`] — the compatibility path backed by
//!   `Virtualization.framework` plus Apple Rosetta. Hosts `linux/amd64`
//!   workloads.
//!
//! The role is the unit of routing: every Docker workload (container, exec,
//! BuildKit session), every guest network endpoint, and every host control
//! plane interaction is decided per role. Backend choice (HV vs VZ) is an
//! implementation detail of the role, not part of its public identity.

use std::fmt;

/// One of the long-lived utility VM roles the daemon orchestrates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UtilityVmRole {
    /// Default fast path. Hosts `linux/arm64` workloads on the HV backend.
    Native,
    /// Compatibility path that hosts `linux/amd64` workloads on the VZ
    /// backend via Apple Rosetta. Only available on macOS Apple Silicon.
    Rosetta,
}

impl UtilityVmRole {
    /// Stable diagnostic label, also used as the machine name suffix and as
    /// the key in role-keyed registries.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Rosetta => "rosetta",
        }
    }

    /// Returns every role the daemon may orchestrate, in stable order.
    /// Suitable for iteration when building per-role state.
    #[must_use]
    pub const fn all() -> [Self; 2] {
        [Self::Native, Self::Rosetta]
    }

    /// Parses a role from its stable diagnostic label.
    #[must_use]
    pub fn from_str_ascii(s: &str) -> Option<Self> {
        match s {
            "native" => Some(Self::Native),
            "rosetta" => Some(Self::Rosetta),
            _ => None,
        }
    }
}

impl fmt::Display for UtilityVmRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_string() {
        for role in UtilityVmRole::all() {
            assert_eq!(UtilityVmRole::from_str_ascii(role.as_str()), Some(role));
        }
    }

    #[test]
    fn from_str_rejects_unknown() {
        assert!(UtilityVmRole::from_str_ascii("kvm").is_none());
        assert!(UtilityVmRole::from_str_ascii("").is_none());
    }

    #[test]
    fn all_lists_every_variant_once() {
        let all = UtilityVmRole::all();
        assert_eq!(all.len(), 2);
        assert!(all.contains(&UtilityVmRole::Native));
        assert!(all.contains(&UtilityVmRole::Rosetta));
    }
}
