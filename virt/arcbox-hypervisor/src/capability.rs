//! Host capability probes that answer without constructing a hypervisor.
//!
//! `Hypervisor::capabilities` is the richer surface, but reaching it means
//! opening `/dev/kvm` (or a VZ configuration) first. Callers that must
//! answer before any VM exists — the sandbox capability gate, which
//! `GetCapabilities` and the `Create` fail-fast path both consult — use
//! these instead. The concrete backends read the same probes when they
//! fill in `PlatformCapabilities`, so the two never drift.

/// Whether this host can nest a VM, and the platform's own reason when it
/// cannot.
///
/// The reason is platform knowledge, not product copy: it names the
/// hardware or kernel requirement that failed, so a caller can surface it
/// without carrying a `#[cfg]` of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NestedVirtSupport {
    /// True when the hardware and kernel allow a nested guest.
    pub supported: bool,
    /// Why not, when `supported` is false; empty otherwise.
    pub reason: &'static str,
}

/// Probes nested-virtualization support on this host.
///
/// Cached: on every platform this is a fixed hardware/kernel property, so
/// the answer cannot change while the process lives.
#[must_use]
pub fn host_nested_virt() -> NestedVirtSupport {
    static SUPPORTED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    let supported = *SUPPORTED.get_or_init(probe_nested_virt);
    NestedVirtSupport {
        supported,
        reason: if supported { "" } else { UNSUPPORTED_REASON },
    }
}

#[cfg(target_os = "macos")]
const UNSUPPORTED_REASON: &str = concat!(
    "this Mac does not support nested virtualization; ",
    "it requires Apple Silicon M3 or newer with macOS 15 or newer",
);

/// `VZGenericPlatformConfiguration.isNestedVirtualizationSupported`.
#[cfg(target_os = "macos")]
fn probe_nested_virt() -> bool {
    arcbox_vz::GenericPlatform::is_nested_virt_supported()
}

#[cfg(target_os = "linux")]
const UNSUPPORTED_REASON: &str = concat!(
    "the host kernel does not expose nested KVM ",
    "(/sys/module/kvm_{intel,amd}/parameters/nested)",
);

/// Nested-KVM module parameters.
///
/// Not gated on x86_64: the files simply do not exist on other
/// architectures, so the read fails and the answer is false — which is
/// also the honest answer for ARM until the kernel grows a probe for
/// ARMv8.4 nested virtualization.
#[cfg(target_os = "linux")]
fn probe_nested_virt() -> bool {
    ["kvm_intel", "kvm_amd"].iter().any(|module| {
        std::fs::read_to_string(format!("/sys/module/{module}/parameters/nested"))
            .is_ok_and(|content| matches!(content.trim(), "1" | "Y" | "y"))
    })
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
const UNSUPPORTED_REASON: &str = "nested virtualization is not supported on this platform";

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn probe_nested_virt() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unsupported_host_always_carries_a_reason() {
        let support = host_nested_virt();
        assert_eq!(support.supported, support.reason.is_empty());
    }

    #[test]
    fn the_probe_is_cached_and_therefore_stable() {
        assert_eq!(host_nested_virt(), host_nested_virt());
    }
}
