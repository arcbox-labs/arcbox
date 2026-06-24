use super::{ResolvedBackend, VmBackend, VmmConfig};

/// Resolves the backend selection based on platform constraints.
///
/// When `Auto` is selected, Rosetta requires VZ (Hypervisor.framework cannot
/// translate x86_64 instructions). Otherwise, default to VZ until the HV
/// backend is fully validated.
#[cfg(target_os = "macos")]
pub(super) fn resolve_backend(config: &VmmConfig) -> ResolvedBackend {
    match config.backend {
        VmBackend::Vz => ResolvedBackend::Vz,
        VmBackend::Hv => ResolvedBackend::Hv,
        // Auto: Rosetta x86_64 translation requires VZ (Hypervisor.framework
        // cannot translate instructions). For native ARM64 workloads, prefer HV.
        VmBackend::Auto => {
            if config.enable_rosetta {
                ResolvedBackend::Vz
            } else {
                ResolvedBackend::Hv
            }
        }
    }
}

pub(super) fn placeholder_vcpu_snapshots(vcpu_count: u32) -> Vec<arcbox_hypervisor::VcpuSnapshot> {
    #[cfg(target_arch = "aarch64")]
    {
        (0..vcpu_count)
            .map(|id| {
                arcbox_hypervisor::VcpuSnapshot::new_arm64(
                    id,
                    arcbox_hypervisor::Arm64Registers::default(),
                )
            })
            .collect()
    }

    #[cfg(not(target_arch = "aarch64"))]
    {
        (0..vcpu_count)
            .map(|id| {
                arcbox_hypervisor::VcpuSnapshot::new_x86(
                    id,
                    arcbox_hypervisor::Registers::default(),
                )
            })
            .collect()
    }
}
