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
    ///
    /// Phrased as the requirement that failed, with no leading subject, so
    /// a caller can prefix its own context — `arcbox-api` renders it as
    /// `"sandboxes cannot run on this host: {reason}"` — without ending up
    /// with two stapled-together clauses.
    pub reason: &'static str,
}

/// Probes nested-virtualization support on this host.
///
/// Cached on macOS, where this is a fixed hardware/OS property that
/// cannot change while the process lives. Re-probed on every call
/// elsewhere: on Linux the answer depends on the `kvm_intel`/`kvm_amd`
/// module being loaded, and this function is reachable — via the sandbox
/// capability gate — before any VM has ever booted (in particular under
/// `--no-linux-vm`, where nothing in this process ever opens `/dev/kvm`).
/// A query that lands before the module autoloads would otherwise cache a
/// false negative for the rest of the process's life.
#[must_use]
pub fn host_nested_virt() -> NestedVirtSupport {
    let supported = cached_or_reprobed();
    NestedVirtSupport {
        supported,
        reason: if supported { "" } else { UNSUPPORTED_REASON },
    }
}

#[cfg(target_os = "macos")]
fn cached_or_reprobed() -> bool {
    static SUPPORTED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *SUPPORTED.get_or_init(probe_nested_virt)
}

#[cfg(not(target_os = "macos"))]
fn cached_or_reprobed() -> bool {
    probe_nested_virt()
}

#[cfg(target_os = "macos")]
const UNSUPPORTED_REASON: &str = concat!(
    "nested virtualization requires Apple Silicon M3 or newer ",
    "with macOS 15 or newer",
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

    // The reason is user-facing: `arcbox-computer` surfaces it verbatim in
    // the `NESTED_VIRT_UNSUPPORTED` error a failing `Create` returns, so
    // the hardware requirement it names is contract, not an internal
    // string. Pin it here, where the constant lives.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_macos_reason_names_the_hardware_requirement() {
        let reason = super::UNSUPPORTED_REASON;
        assert!(reason.contains("M3"), "{reason}");
        assert!(reason.contains("macOS 15"), "{reason}");
    }

    #[test]
    fn an_unsupported_host_always_carries_a_reason() {
        let support = host_nested_virt();
        assert_eq!(support.supported, support.reason.is_empty());
    }

    #[test]
    fn the_probe_is_stable_across_repeated_calls() {
        // Cached on macOS (a fixed hardware property); re-probed every call
        // on Linux (see `cached_or_reprobed`). Either way, two calls back to
        // back must agree — nothing in this process changes kernel module
        // state between them.
        assert_eq!(host_nested_virt(), host_nested_virt());
    }
}
