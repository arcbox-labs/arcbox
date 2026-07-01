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
