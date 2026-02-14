//! Boot protocol implementation.
//!
//! This module handles loading and configuring the Linux kernel for boot.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::error::{Result, VmmError};
use arcbox_hypervisor::GuestAddress;

/// Linux kernel boot protocol constants.
pub mod linux {
    /// bzImage magic number.
    pub const BZIMAGE_MAGIC: u32 = 0x53726448; // "HdrS"

    /// Minimum boot protocol version we support.
    pub const MIN_BOOT_PROTOCOL: u16 = 0x0200;

    /// Boot protocol version for 64-bit.
    pub const BOOT_PROTOCOL_64BIT: u16 = 0x0206;

    /// Setup header offset in bzImage.
    pub const SETUP_HEADER_OFFSET: u64 = 0x1F1;

    /// Boot flag.
    pub const BOOT_FLAG: u16 = 0xAA55;

    /// Default kernel load address (for direct kernel boot).
    pub const KERNEL_LOAD_ADDR: u64 = 0x100000; // 1MB

    /// Default initrd load address.
    pub const INITRD_LOAD_ADDR: u64 = 0x1000000; // 16MB

    /// Default command line address.
    pub const CMDLINE_ADDR: u64 = 0x20000;

    /// Maximum command line size.
    pub const CMDLINE_MAX_SIZE: usize = 2048;

    /// Boot parameters (zero page) address.
    pub const BOOT_PARAMS_ADDR: u64 = 0x7000;

    /// E820 memory map types.
    pub mod e820 {
        pub const RAM: u32 = 1;
        pub const RESERVED: u32 = 2;
        pub const ACPI: u32 = 3;
        pub const NVS: u32 = 4;
        pub const UNUSABLE: u32 = 5;
    }
}

/// ARM64 boot protocol constants.
pub mod arm64 {
    /// Kernel load address (2MB aligned).
    pub const KERNEL_LOAD_ADDR: u64 = 0x80000;

    /// Device tree load address.
    pub const FDT_LOAD_ADDR: u64 = 0x40000000; // 1GB

    /// Initrd load address.
    pub const INITRD_LOAD_ADDR: u64 = 0x48000000;

    /// Maximum FDT size.
    pub const FDT_MAX_SIZE: usize = 2 * 1024 * 1024; // 2MB
}

/// Kernel image type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelType {
    /// Linux x86_64 bzImage.
    LinuxBzImage,
    /// Linux ARM64 Image.
    LinuxArm64,
    /// Raw binary (PE or ELF).
    RawBinary,
    /// Unknown format.
    Unknown,
}

/// Boot parameters for the kernel.
#[derive(Debug, Clone)]
pub struct BootParams {
    /// Kernel image path.
    pub kernel_path: String,
    /// Kernel type.
    pub kernel_type: KernelType,
    /// Kernel load address.
    pub kernel_addr: GuestAddress,
    /// Kernel size.
    pub kernel_size: u64,
    /// Kernel entry point.
    pub entry_point: GuestAddress,
    /// Command line.
    pub cmdline: String,
    /// Command line address.
    pub cmdline_addr: GuestAddress,
    /// Initrd path (optional).
    pub initrd_path: Option<String>,
    /// Initrd load address.
    pub initrd_addr: Option<GuestAddress>,
    /// Initrd size.
    pub initrd_size: Option<u64>,
    /// Device tree blob (for ARM).
    pub fdt_addr: Option<GuestAddress>,
    /// Device tree size.
    pub fdt_size: Option<u64>,
}

impl BootParams {
    /// Creates new boot parameters.
    #[must_use]
    pub fn new(kernel_path: impl Into<String>, cmdline: impl Into<String>) -> Self {
        Self {
            kernel_path: kernel_path.into(),
            kernel_type: KernelType::Unknown,
            kernel_addr: GuestAddress::new(0),
            kernel_size: 0,
            entry_point: GuestAddress::new(0),
            cmdline: cmdline.into(),
            cmdline_addr: GuestAddress::new(0),
            initrd_path: None,
            initrd_addr: None,
            initrd_size: None,
            fdt_addr: None,
            fdt_size: None,
        }
    }

    /// Sets the initrd path.
    #[must_use]
    pub fn with_initrd(mut self, path: impl Into<String>) -> Self {
        self.initrd_path = Some(path.into());
        self
    }
}

/// Kernel loader.
///
/// Handles loading kernel images into guest memory.
pub struct KernelLoader;

impl KernelLoader {
    /// Detects the kernel type from a file.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read.
    pub fn detect_kernel_type(path: &Path) -> Result<KernelType> {
        let mut file =
            File::open(path).map_err(|e| VmmError::config(format!("Cannot open kernel: {}", e)))?;

        // Read enough to check all signatures (bzImage magic is at 0x202)
        let mut header = [0u8; 0x210];
        let bytes_read = file
            .read(&mut header)
            .map_err(|e| VmmError::config(format!("Cannot read kernel header: {}", e)))?;

        // Check for Linux bzImage (x86_64) - magic at offset 0x202
        if bytes_read >= 0x206 {
            let magic =
                u32::from_le_bytes([header[0x202], header[0x203], header[0x204], header[0x205]]);
            if magic == linux::BZIMAGE_MAGIC {
                return Ok(KernelType::LinuxBzImage);
            }
        }

        // Check for ARM64 Linux Image
        // ARM64 Image has magic "ARM\x64" at offset 0x38
        if bytes_read >= 0x40 && &header[0x38..0x3C] == b"ARM\x64" {
            return Ok(KernelType::LinuxArm64);
        }

        // Check for ELF
        if bytes_read >= 4 && &header[0..4] == b"\x7FELF" {
            return Ok(KernelType::RawBinary);
        }

        // Check for PE (Windows/UEFI)
        if bytes_read >= 2 && &header[0..2] == b"MZ" {
            return Ok(KernelType::RawBinary);
        }

        Ok(KernelType::Unknown)
    }

    /// Loads a kernel and returns boot parameters.
    ///
    /// # Errors
    ///
    /// Returns an error if the kernel cannot be loaded.
    pub fn load(path: &Path, cmdline: &str) -> Result<BootParams> {
        let kernel_type = Self::detect_kernel_type(path)?;

        tracing::info!(
            "Loading kernel: path={}, type={:?}",
            path.display(),
            kernel_type
        );

        let file_size = std::fs::metadata(path)
            .map_err(|e| VmmError::config(format!("Cannot stat kernel: {}", e)))?
            .len();

        let mut params = BootParams::new(path.to_string_lossy(), cmdline);
        params.kernel_type = kernel_type;
        params.kernel_size = file_size;

        match kernel_type {
            KernelType::LinuxBzImage => {
                params.kernel_addr = GuestAddress::new(linux::KERNEL_LOAD_ADDR);
                params.entry_point = GuestAddress::new(linux::KERNEL_LOAD_ADDR);
                params.cmdline_addr = GuestAddress::new(linux::CMDLINE_ADDR);
            }
            KernelType::LinuxArm64 => {
                params.kernel_addr = GuestAddress::new(arm64::KERNEL_LOAD_ADDR);
                params.entry_point = GuestAddress::new(arm64::KERNEL_LOAD_ADDR);
                params.fdt_addr = Some(GuestAddress::new(arm64::FDT_LOAD_ADDR));
            }
            KernelType::RawBinary | KernelType::Unknown => {
                // Use architecture-appropriate defaults
                #[cfg(target_arch = "aarch64")]
                {
                    params.kernel_addr = GuestAddress::new(arm64::KERNEL_LOAD_ADDR);
                    params.entry_point = GuestAddress::new(arm64::KERNEL_LOAD_ADDR);
                }
                #[cfg(target_arch = "x86_64")]
                {
                    params.kernel_addr = GuestAddress::new(linux::KERNEL_LOAD_ADDR);
                    params.entry_point = GuestAddress::new(linux::KERNEL_LOAD_ADDR);
                }
            }
        }

        Ok(params)
    }

    /// Loads an initrd and updates boot parameters.
    ///
    /// # Errors
    ///
    /// Returns an error if the initrd cannot be loaded.
    pub fn load_initrd(path: &Path, params: &mut BootParams) -> Result<()> {
        let file_size = std::fs::metadata(path)
            .map_err(|e| VmmError::config(format!("Cannot stat initrd: {}", e)))?
            .len();

        let load_addr = match params.kernel_type {
            KernelType::LinuxArm64 => arm64::INITRD_LOAD_ADDR,
            _ => linux::INITRD_LOAD_ADDR,
        };

        params.initrd_path = Some(path.to_string_lossy().to_string());
        params.initrd_addr = Some(GuestAddress::new(load_addr));
        params.initrd_size = Some(file_size);

        tracing::info!(
            "Loaded initrd: path={}, size={}, addr={:#x}",
            path.display(),
            file_size,
            load_addr
        );

        Ok(())
    }

    /// Reads the kernel image into memory.
    ///
    /// # Errors
    ///
    /// Returns an error if the kernel cannot be read.
    pub fn read_kernel(path: &Path) -> Result<Vec<u8>> {
        std::fs::read(path).map_err(|e| VmmError::config(format!("Cannot read kernel: {}", e)))
    }

    /// Reads the initrd into memory.
    ///
    /// # Errors
    ///
    /// Returns an error if the initrd cannot be read.
    pub fn read_initrd(path: &Path) -> Result<Vec<u8>> {
        std::fs::read(path).map_err(|e| VmmError::config(format!("Cannot read initrd: {}", e)))
    }
}

/// x86_64 boot setup.
#[cfg(target_arch = "x86_64")]
pub mod x86_64 {
    use super::*;

    /// E820 memory map entry.
    #[repr(C)]
    #[derive(Debug, Clone, Copy, Default)]
    pub struct E820Entry {
        pub addr: u64,
        pub size: u64,
        pub type_: u32,
    }

    /// Boot parameters structure (simplified zero page).
    #[repr(C)]
    #[derive(Debug, Clone)]
    pub struct BootParamsStruct {
        /// E820 memory map.
        pub e820_entries: u8,
        pub e820_table: [E820Entry; 128],
        /// Command line pointer.
        pub cmd_line_ptr: u32,
        /// Initrd address.
        pub ramdisk_image: u32,
        /// Initrd size.
        pub ramdisk_size: u32,
    }

    impl Default for BootParamsStruct {
        fn default() -> Self {
            Self {
                e820_entries: 0,
                e820_table: [E820Entry::default(); 128],
                cmd_line_ptr: 0,
                ramdisk_image: 0,
                ramdisk_size: 0,
            }
        }
    }

    /// Creates the x86_64 boot parameters structure.
    pub fn create_boot_params(params: &BootParams, memory_size: u64) -> BootParamsStruct {
        let mut boot_params = BootParamsStruct::default();

        // Create simple E820 map
        // Entry 0: Low memory (0 - 640KB usable)
        boot_params.e820_table[0] = E820Entry {
            addr: 0,
            size: 0x9FC00, // 639KB
            type_: linux::e820::RAM,
        };

        // Entry 1: Reserved (640KB - 1MB)
        boot_params.e820_table[1] = E820Entry {
            addr: 0x9FC00,
            size: 0x100000 - 0x9FC00,
            type_: linux::e820::RESERVED,
        };

        // Entry 2: Main memory (1MB - end)
        boot_params.e820_table[2] = E820Entry {
            addr: 0x100000,
            size: memory_size - 0x100000,
            type_: linux::e820::RAM,
        };

        boot_params.e820_entries = 3;

        // Set command line pointer
        boot_params.cmd_line_ptr = params.cmdline_addr.raw() as u32;

        // Set initrd if present
        if let (Some(addr), Some(size)) = (params.initrd_addr, params.initrd_size) {
            boot_params.ramdisk_image = addr.raw() as u32;
            boot_params.ramdisk_size = size as u32;
        }

        boot_params
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kernel_type_detection_bzimage() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        let path = temp.path();

        // Create a fake bzImage header (need at least 0x206 bytes for magic)
        let mut data = vec![0u8; 0x210];
        // Magic at offset 0x202 (little-endian "HdrS")
        data[0x202] = 0x48; // 'H'
        data[0x203] = 0x64; // 'd'
        data[0x204] = 0x72; // 'r'
        data[0x205] = 0x53; // 'S'

        std::fs::write(path, &data).unwrap();

        let kernel_type = KernelLoader::detect_kernel_type(path).unwrap();
        assert_eq!(kernel_type, KernelType::LinuxBzImage);
    }

    #[test]
    fn test_kernel_type_detection_arm64() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        let path = temp.path();

        // Create a fake ARM64 Image header
        let mut data = vec![0u8; 0x100];
        data[0x38..0x3C].copy_from_slice(b"ARM\x64");

        std::fs::write(path, &data).unwrap();

        let kernel_type = KernelLoader::detect_kernel_type(path).unwrap();
        assert_eq!(kernel_type, KernelType::LinuxArm64);
    }

    #[test]
    fn test_kernel_type_detection_elf() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        let path = temp.path();

        // Create a fake ELF header
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(b"\x7FELF");

        std::fs::write(path, &data).unwrap();

        let kernel_type = KernelLoader::detect_kernel_type(path).unwrap();
        assert_eq!(kernel_type, KernelType::RawBinary);
    }

    #[test]
    fn test_kernel_type_detection_pe() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        let path = temp.path();

        // Create a fake PE header
        let mut data = vec![0u8; 64];
        data[0..2].copy_from_slice(b"MZ");

        std::fs::write(path, &data).unwrap();

        let kernel_type = KernelLoader::detect_kernel_type(path).unwrap();
        assert_eq!(kernel_type, KernelType::RawBinary);
    }

    #[test]
    fn test_kernel_type_detection_unknown() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        let path = temp.path();

        // Create random data
        let data = vec![0x42u8; 64];
        std::fs::write(path, &data).unwrap();

        let kernel_type = KernelLoader::detect_kernel_type(path).unwrap();
        assert_eq!(kernel_type, KernelType::Unknown);
    }

    #[test]
    fn test_boot_params_creation() {
        let params =
            BootParams::new("/path/to/kernel", "console=ttyS0").with_initrd("/path/to/initrd");

        assert_eq!(params.kernel_path, "/path/to/kernel");
        assert_eq!(params.cmdline, "console=ttyS0");
        assert_eq!(params.initrd_path, Some("/path/to/initrd".to_string()));
    }

    #[test]
    fn test_linux_constants() {
        assert_eq!(linux::KERNEL_LOAD_ADDR, 0x100000);
        assert_eq!(linux::INITRD_LOAD_ADDR, 0x1000000);
        assert_eq!(linux::CMDLINE_ADDR, 0x20000);
    }

    #[test]
    fn test_arm64_constants() {
        assert_eq!(arm64::KERNEL_LOAD_ADDR, 0x80000);
        assert_eq!(arm64::FDT_LOAD_ADDR, 0x40000000);
    }
}
