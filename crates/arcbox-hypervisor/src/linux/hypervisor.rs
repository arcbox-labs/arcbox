//! Linux KVM hypervisor implementation.

use std::sync::Arc;

use crate::{
    config::VmConfig,
    error::HypervisorError,
    traits::Hypervisor,
    types::{CpuArch, PlatformCapabilities},
};

use super::ffi::{self, KVM_CAP_MAX_VCPUS, KVM_CAP_NR_MEMSLOTS, KvmSystem};
use super::vm::KvmVm;

/// Linux hypervisor implementation using KVM.
///
/// This is the main entry point for creating VMs on Linux.
///
/// # Example
///
/// ```ignore
/// use arcbox_hypervisor::linux::KvmHypervisor;
///
/// let hypervisor = KvmHypervisor::new()?;
/// let caps = hypervisor.capabilities();
/// println!("Max vCPUs: {}", caps.max_vcpus);
/// ```
pub struct KvmHypervisor {
    /// KVM system handle.
    kvm: Arc<KvmSystem>,
    /// Platform capabilities.
    capabilities: PlatformCapabilities,
    /// Size of the vCPU mmap region.
    vcpu_mmap_size: usize,
}

impl KvmHypervisor {
    /// Creates a new KVM hypervisor instance.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `/dev/kvm` cannot be opened
    /// - KVM API version is not supported
    /// - Required KVM capabilities are not available
    pub fn new() -> Result<Self, HypervisorError> {
        // Open /dev/kvm
        let kvm = KvmSystem::open().map_err(|e| {
            HypervisorError::InitializationFailed(format!("Failed to open /dev/kvm: {}", e))
        })?;

        // Check API version
        let api_version = kvm.api_version().map_err(|e| {
            HypervisorError::InitializationFailed(format!("Failed to get KVM API version: {}", e))
        })?;

        if api_version != 12 {
            return Err(HypervisorError::InitializationFailed(format!(
                "Unsupported KVM API version: {} (expected 12)",
                api_version
            )));
        }

        // Get vCPU mmap size
        let vcpu_mmap_size = kvm.vcpu_mmap_size().map_err(|e| {
            HypervisorError::InitializationFailed(format!("Failed to get vCPU mmap size: {}", e))
        })?;

        // Detect capabilities
        let capabilities = Self::detect_capabilities(&kvm)?;

        tracing::info!(
            "KVM hypervisor initialized: max_vcpus={}, max_memory={}GB, nested_virt={}",
            capabilities.max_vcpus,
            capabilities.max_memory / (1024 * 1024 * 1024),
            capabilities.nested_virt
        );

        Ok(Self {
            kvm: Arc::new(kvm),
            capabilities,
            vcpu_mmap_size,
        })
    }

    /// Detects platform capabilities from KVM.
    fn detect_capabilities(kvm: &KvmSystem) -> Result<PlatformCapabilities, HypervisorError> {
        // Get max vCPUs
        let max_vcpus = kvm.check_extension(KVM_CAP_MAX_VCPUS).unwrap_or(1) as u32;

        // Get max memory slots (estimate max memory from this)
        let _max_memslots = kvm.check_extension(KVM_CAP_NR_MEMSLOTS).unwrap_or(32);

        // Calculate max memory (conservative estimate: 512GB)
        let max_memory = 512 * 1024 * 1024 * 1024_u64;

        // Determine supported architectures
        let supported_archs = vec![CpuArch::native()];

        // Check for nested virtualization support
        #[cfg(target_arch = "x86_64")]
        let nested_virt = Self::check_nested_virt();
        #[cfg(not(target_arch = "x86_64"))]
        let nested_virt = false;

        Ok(PlatformCapabilities {
            supported_archs,
            max_vcpus,
            max_memory,
            nested_virt,
            rosetta: false, // Not applicable on Linux
        })
    }

    /// Checks if nested virtualization is supported (x86 only).
    #[cfg(target_arch = "x86_64")]
    fn check_nested_virt() -> bool {
        // Check Intel VMX nested support
        if let Ok(content) = std::fs::read_to_string("/sys/module/kvm_intel/parameters/nested") {
            if content.trim() == "Y" || content.trim() == "1" {
                return true;
            }
        }

        // Check AMD SVM nested support
        if let Ok(content) = std::fs::read_to_string("/sys/module/kvm_amd/parameters/nested") {
            if content.trim() == "Y" || content.trim() == "1" {
                return true;
            }
        }

        false
    }

    /// Returns the KVM system handle.
    pub(crate) fn kvm(&self) -> &Arc<KvmSystem> {
        &self.kvm
    }

    /// Returns the vCPU mmap size.
    pub(crate) fn vcpu_mmap_size(&self) -> usize {
        self.vcpu_mmap_size
    }

    /// Checks if the given architecture is supported.
    #[must_use]
    pub fn supports_arch(&self, arch: CpuArch) -> bool {
        self.capabilities.supported_archs.contains(&arch)
    }

    /// Validates VM configuration against platform capabilities.
    fn validate_config(&self, config: &VmConfig) -> Result<(), HypervisorError> {
        // Check vCPU count
        if config.vcpu_count == 0 {
            return Err(HypervisorError::invalid_config(
                "vCPU count must be > 0".to_string(),
            ));
        }

        if config.vcpu_count > self.capabilities.max_vcpus {
            return Err(HypervisorError::invalid_config(format!(
                "vCPU count {} exceeds maximum {}",
                config.vcpu_count, self.capabilities.max_vcpus
            )));
        }

        // Check memory size
        const MIN_MEMORY: u64 = 16 * 1024 * 1024; // 16MB minimum
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

        Ok(())
    }
}

impl Hypervisor for KvmHypervisor {
    type Vm = KvmVm;

    fn capabilities(&self) -> &PlatformCapabilities {
        &self.capabilities
    }

    fn create_vm(&self, config: VmConfig) -> Result<Self::Vm, HypervisorError> {
        // Validate configuration
        self.validate_config(&config)?;

        // Create the VM
        KvmVm::new(Arc::clone(&self.kvm), self.vcpu_mmap_size, config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore] // Requires /dev/kvm
    fn test_hypervisor_creation() {
        let result = KvmHypervisor::new();
        assert!(result.is_ok());

        let hypervisor = result.unwrap();
        assert!(hypervisor.capabilities().max_vcpus >= 1);
    }

    #[test]
    #[ignore] // Requires /dev/kvm
    fn test_config_validation() {
        let hypervisor = KvmHypervisor::new().unwrap();

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

    #[test]
    #[ignore] // Requires /dev/kvm
    fn test_create_vm() {
        let hypervisor = KvmHypervisor::new().unwrap();

        let config = VmConfig {
            vcpu_count: 1,
            memory_size: 128 * 1024 * 1024,
            ..Default::default()
        };

        let vm = hypervisor.create_vm(config);
        assert!(vm.is_ok());
    }
}
