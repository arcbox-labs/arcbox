//! macOS Virtualization.framework hypervisor implementation.
//!
//! This implementation uses `arcbox-vz` for the underlying Virtualization.framework bindings.

use crate::{
    config::VmConfig,
    error::HypervisorError,
    traits::Hypervisor,
    types::{CpuArch, PlatformCapabilities},
};

use super::vm::DarwinVm;

/// macOS hypervisor implementation using Virtualization.framework.
///
/// This is the main entry point for creating VMs on macOS.
///
/// # Example
///
/// ```ignore
/// use arcbox_hypervisor::darwin::DarwinHypervisor;
///
/// let hypervisor = DarwinHypervisor::new()?;
/// let caps = hypervisor.capabilities();
/// println!("Max vCPUs: {}", caps.max_vcpus);
/// ```
pub struct DarwinHypervisor {
    capabilities: PlatformCapabilities,
}

impl DarwinHypervisor {
    /// Creates a new Darwin hypervisor instance.
    ///
    /// # Errors
    ///
    /// Returns an error if Virtualization.framework is not available.
    pub fn new() -> Result<Self, HypervisorError> {
        // Check if Virtualization.framework is supported using arcbox-vz
        if !arcbox_vz::is_supported() {
            return Err(HypervisorError::UnsupportedPlatform(
                "Virtualization.framework not available".to_string(),
            ));
        }

        let capabilities = Self::detect_capabilities();

        tracing::info!(
            "Darwin hypervisor initialized: max_vcpus={}, max_memory={}GB, rosetta={}, nested_virt={}",
            capabilities.max_vcpus,
            capabilities.max_memory / (1024 * 1024 * 1024),
            capabilities.rosetta,
            capabilities.nested_virt
        );

        Ok(Self { capabilities })
    }

    /// Detects platform capabilities using arcbox-vz.
    fn detect_capabilities() -> PlatformCapabilities {
        let max_vcpus = arcbox_vz::max_cpu_count();
        let max_memory = arcbox_vz::max_memory_size();

        // Check Rosetta availability using arcbox-vz
        let rosetta = matches!(
            arcbox_vz::LinuxRosettaDirectoryShare::availability(),
            arcbox_vz::RosettaAvailability::Supported
                | arcbox_vz::RosettaAvailability::NotInstalled
        );

        // Determine supported architectures
        let mut supported_archs = vec![CpuArch::native()];

        // On ARM64, we can run x86_64 via Rosetta
        #[cfg(target_arch = "aarch64")]
        if rosetta {
            supported_archs.push(CpuArch::X86_64);
        }

        PlatformCapabilities {
            supported_archs,
            max_vcpus: max_vcpus as u32,
            max_memory,
            nested_virt: arcbox_vz::GenericPlatform::is_nested_virt_supported(),
            rosetta,
        }
    }

    /// Checks if the given architecture is supported.
    #[must_use]
    pub fn supports_arch(&self, arch: CpuArch) -> bool {
        self.capabilities.supported_archs.contains(&arch)
    }

    /// Checks if Rosetta 2 translation is available.
    #[must_use]
    pub fn rosetta_available(&self) -> bool {
        self.capabilities.rosetta
    }
}

impl Hypervisor for DarwinHypervisor {
    type Vm = DarwinVm;

    fn capabilities(&self) -> &PlatformCapabilities {
        &self.capabilities
    }

    fn create_vm(&self, config: VmConfig) -> Result<Self::Vm, HypervisorError> {
        // Validate configuration
        self.validate_config(&config)?;

        // Create the VM
        DarwinVm::new(config)
    }
}

impl DarwinHypervisor {
    /// Validates VM configuration against platform capabilities.
    fn validate_config(&self, config: &VmConfig) -> Result<(), HypervisorError> {
        // Check vCPU count
        if config.vcpu_count == 0 {
            return Err(HypervisorError::invalid_config("vCPU count must be > 0"));
        }

        if config.vcpu_count > self.capabilities.max_vcpus {
            return Err(HypervisorError::invalid_config(format!(
                "vCPU count {} exceeds maximum {}",
                config.vcpu_count, self.capabilities.max_vcpus
            )));
        }

        // Check memory size
        const MIN_MEMORY: u64 = 64 * 1024 * 1024; // 64MB minimum
        if config.memory_size < MIN_MEMORY {
            return Err(HypervisorError::invalid_config(format!(
                "Memory size {} is below minimum {}",
                config.memory_size, MIN_MEMORY
            )));
        }

        if config.memory_size > self.capabilities.max_memory {
            return Err(HypervisorError::invalid_config(format!(
                "Memory size {} exceeds maximum {}",
                config.memory_size, self.capabilities.max_memory
            )));
        }

        // Check architecture
        if !self.supports_arch(config.arch) {
            return Err(HypervisorError::invalid_config(format!(
                "Architecture {:?} is not supported",
                config.arch
            )));
        }

        // Check Rosetta requirement
        #[cfg(target_arch = "aarch64")]
        if config.arch == CpuArch::X86_64 && !self.capabilities.rosetta {
            return Err(HypervisorError::invalid_config(
                "x86_64 requires Rosetta 2, which is not available",
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hypervisor_creation() {
        // This test will only pass on macOS with Virtualization.framework
        if !arcbox_vz::is_supported() {
            println!("Virtualization not supported, skipping");
            return;
        }

        let result = DarwinHypervisor::new();
        assert!(result.is_ok());

        let hypervisor = result.unwrap();
        assert!(hypervisor.capabilities().max_vcpus >= 1);
    }

    #[test]
    fn test_config_validation() {
        if !arcbox_vz::is_supported() {
            println!("Virtualization not supported, skipping");
            return;
        }

        let hypervisor = DarwinHypervisor::new().unwrap();

        // Valid config
        let config = VmConfig {
            vcpu_count: 2,
            memory_size: 512 * 1024 * 1024,
            ..Default::default()
        };
        assert!(hypervisor.validate_config(&config).is_ok());

        // Invalid: 0 vCPUs
        let config = VmConfig {
            vcpu_count: 0,
            ..Default::default()
        };
        assert!(hypervisor.validate_config(&config).is_err());

        // Invalid: too little memory
        let config = VmConfig {
            memory_size: 1024, // 1KB
            ..Default::default()
        };
        assert!(hypervisor.validate_config(&config).is_err());
    }
}
