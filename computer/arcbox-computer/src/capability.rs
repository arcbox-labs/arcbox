//! Whether this host can run sandboxes at all (CORE-13).
//!
//! A sandbox is a Firecracker microVM nested inside the System VM, so it
//! needs `/dev/kvm` in the guest — which exists only when both halves
//! allow nesting: the active backend must expose it, and the host
//! hardware or kernel must support it. Answering without booting
//! anything is what lets `GetCapabilities` report honestly and lets
//! `Create` fail fast with a reason instead of timing out against a
//! guest that will never have KVM.

use arcbox_engine::{VmBackend, host_nested_virt};

/// Whether this host can run sandboxes, and why not when it cannot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NestedVirtCapability {
    /// True when sandboxes can run on the current backend and hardware.
    pub supported: bool,
    /// The authoritative reason when unsupported (empty when supported);
    /// surfaced verbatim in `NESTED_VIRT_UNSUPPORTED` errors.
    pub reason: String,
}

impl NestedVirtCapability {
    fn supported() -> Self {
        Self {
            supported: true,
            reason: String::new(),
        }
    }

    fn unsupported(reason: impl Into<String>) -> Self {
        Self {
            supported: false,
            reason: reason.into(),
        }
    }
}

/// Nested-virt capability for a given hypervisor backend on this host.
///
/// The backend half is re-evaluated per call because a backend switch
/// changes it at runtime; the hardware probe underneath is cached.
#[must_use]
pub fn nested_virt_for_backend(backend: VmBackend) -> NestedVirtCapability {
    if !backend.supports_nested_virt() {
        return NestedVirtCapability::unsupported(format!(
            "sandboxes require nested virtualization, which the {} backend does not support; \
             switch to the VZ backend (`abctl system backend vz`)",
            backend.as_str().to_uppercase()
        ));
    }
    let host = host_nested_virt();
    if host.supported {
        NestedVirtCapability::supported()
    } else {
        // The probe phrases its reason as the requirement that failed, with
        // no subject of its own, so the sandbox context goes in front
        // rather than being stapled on after an explanation.
        NestedVirtCapability::unsupported(format!("sandboxes cannot run: {}", host.reason))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // `VmBackend::Hv` only refuses nesting on macOS, where it names
    // Hypervisor.framework specifically. Off macOS the enum selects
    // nothing (see `VmBackend::supports_nested_virt`), so this case
    // belongs with the cross-platform test below instead.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_backend_that_cannot_nest_is_refused_with_an_actionable_reason() {
        let capability = nested_virt_for_backend(VmBackend::Hv);
        assert!(!capability.supported);
        assert!(
            capability.reason.contains("VZ backend"),
            "{}",
            capability.reason
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_nesting_backend_defers_to_the_hardware_probe() {
        let capability = nested_virt_for_backend(VmBackend::Vz);
        assert_eq!(capability.supported, host_nested_virt().supported);
        // Whatever the host answers, the two halves stay consistent: a
        // supported capability carries no reason, an unsupported one always
        // does — an empty reason would reach the client as a bare error.
        assert_eq!(capability.supported, capability.reason.is_empty());
    }

    // Off macOS `VmBackend` is not a real backend selector (`Vmm::initialize`
    // on Linux always boots through KVM regardless of it), so neither
    // variant should pre-empt the hardware probe there.
    #[cfg(not(target_os = "macos"))]
    #[test]
    fn off_macos_every_backend_defers_to_the_hardware_probe() {
        for backend in [VmBackend::Hv, VmBackend::Vz] {
            let capability = nested_virt_for_backend(backend);
            assert_eq!(capability.supported, host_nested_virt().supported);
            assert_eq!(capability.supported, capability.reason.is_empty());
        }
    }
}
