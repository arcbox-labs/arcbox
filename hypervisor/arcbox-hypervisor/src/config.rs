//! VM configuration types.

use crate::types::CpuArch;

/// Virtual machine configuration.
#[derive(Debug, Clone)]
pub struct VmConfig {
    /// Number of virtual CPUs.
    pub vcpu_count: u32,
    /// Memory size in bytes.
    pub memory_size: u64,
    /// CPU architecture (defaults to native).
    pub arch: CpuArch,
    /// Path to the kernel image.
    pub kernel_path: Option<String>,
    /// Kernel command line arguments.
    pub kernel_cmdline: Option<String>,
    /// Enable Rosetta 2 translation (macOS ARM only).
    pub enable_rosetta: bool,
}

impl Default for VmConfig {
    fn default() -> Self {
        Self {
            vcpu_count: 1,
            memory_size: 512 * 1024 * 1024, // 512MB
            arch: CpuArch::native(),
            kernel_path: None,
            kernel_cmdline: None,
            enable_rosetta: false,
        }
    }
}

impl VmConfig {
    /// Creates a new builder for VM configuration.
    #[must_use]
    pub fn builder() -> VmConfigBuilder {
        VmConfigBuilder::default()
    }
}

/// Builder for [`VmConfig`].
#[derive(Debug, Default)]
pub struct VmConfigBuilder {
    config: VmConfig,
}

impl VmConfigBuilder {
    /// Sets the number of vCPUs.
    #[must_use]
    pub fn vcpu_count(mut self, count: u32) -> Self {
        self.config.vcpu_count = count;
        self
    }

    /// Sets the memory size in bytes.
    #[must_use]
    pub fn memory_size(mut self, size: u64) -> Self {
        self.config.memory_size = size;
        self
    }

    /// Sets the CPU architecture.
    #[must_use]
    pub fn arch(mut self, arch: CpuArch) -> Self {
        self.config.arch = arch;
        self
    }

    /// Sets the kernel path.
    #[must_use]
    pub fn kernel_path(mut self, path: impl Into<String>) -> Self {
        self.config.kernel_path = Some(path.into());
        self
    }

    /// Sets the kernel command line.
    #[must_use]
    pub fn kernel_cmdline(mut self, cmdline: impl Into<String>) -> Self {
        self.config.kernel_cmdline = Some(cmdline.into());
        self
    }

    /// Enables Rosetta 2 translation.
    #[must_use]
    pub fn enable_rosetta(mut self, enable: bool) -> Self {
        self.config.enable_rosetta = enable;
        self
    }

    /// Builds the configuration.
    #[must_use]
    pub fn build(self) -> VmConfig {
        self.config
    }
}
