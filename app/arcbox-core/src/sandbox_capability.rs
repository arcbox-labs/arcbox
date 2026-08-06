//! Nested-virtualization capability detection for sandboxes (CORE-13).
//!
//! Sandboxes are Firecracker microVMs inside the System VM, so they need
//! `/dev/kvm` in the guest — which exists only when the host can nest:
//! on macOS that means the VZ backend on hardware where
//! `VZGenericPlatformConfiguration.isNestedVirtualizationSupported` is true
//! (Apple Silicon M3+, macOS 15+); on Linux it means nested KVM enabled in
//! the host kernel modules. The daemon answers this without booting
//! anything so `GetCapabilities` and the `Create` fail-fast gate work even
//! before the first sandbox request reaches the guest.

use crate::runtime::Runtime;
use arcbox_vmm::VmBackend;

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

impl Runtime {
    /// Nested-virt capability for the System VM's *current* backend.
    ///
    /// The hardware probe is cached; the backend half is re-evaluated per
    /// call because `switch_system_vm_backend` can change it at runtime.
    #[must_use]
    pub fn sandbox_nested_virt(&self) -> NestedVirtCapability {
        nested_virt_for_backend(self.system_vm_backend())
    }
}

/// Nested-virt capability for a given hypervisor backend on this host.
#[must_use]
pub fn nested_virt_for_backend(backend: VmBackend) -> NestedVirtCapability {
    #[cfg(target_os = "macos")]
    {
        match backend {
            VmBackend::Hv => NestedVirtCapability::unsupported(
                "sandboxes require nested virtualization, which the HV backend does not \
                 support; switch to the VZ backend (`abctl system backend vz`)",
            ),
            VmBackend::Vz => {
                if vz_hardware_supports_nested() {
                    NestedVirtCapability::supported()
                } else {
                    NestedVirtCapability::unsupported(
                        "this Mac does not support nested virtualization; sandboxes require \
                         Apple Silicon M3 or newer with macOS 15 or newer",
                    )
                }
            }
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = backend;
        if linux_kvm_supports_nested() {
            NestedVirtCapability::supported()
        } else {
            NestedVirtCapability::unsupported(
                "the host kernel does not expose nested KVM \
                 (/sys/module/kvm_{intel,amd}/parameters/nested); sandboxes cannot run",
            )
        }
    }
}

/// Cached `VZGenericPlatformConfiguration.isNestedVirtualizationSupported`.
///
/// A pure hardware/OS property — safe to probe once per process.
#[cfg(target_os = "macos")]
fn vz_hardware_supports_nested() -> bool {
    static SUPPORTED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *SUPPORTED.get_or_init(arcbox_vz::GenericPlatform::is_nested_virt_supported)
}

/// Nested-KVM module parameters, mirroring the hypervisor crate's probe.
#[cfg(not(target_os = "macos"))]
fn linux_kvm_supports_nested() -> bool {
    ["kvm_intel", "kvm_amd"].iter().any(|module| {
        std::fs::read_to_string(format!("/sys/module/{module}/parameters/nested"))
            .is_ok_and(|content| matches!(content.trim(), "1" | "Y" | "y"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "macos")]
    #[test]
    fn hv_backend_is_always_unsupported_with_an_actionable_reason() {
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
    fn vz_backend_reflects_the_hardware_probe() {
        let capability = nested_virt_for_backend(VmBackend::Vz);
        if capability.supported {
            assert!(capability.reason.is_empty());
        } else {
            assert!(capability.reason.contains("M3"), "{}", capability.reason);
        }
    }
}
