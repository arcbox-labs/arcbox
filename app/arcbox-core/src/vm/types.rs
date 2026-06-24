use crate::machine::MachineState;
use uuid::Uuid;

/// VM identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VmId(String);

impl VmId {
    /// Creates a new VM ID.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    #[cfg(test)]
    pub(crate) fn from_string(id: String) -> Self {
        Self(id)
    }

    /// Returns the ID as a string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for VmId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for VmId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Derives a stable locally-administered MAC address for the macOS bridge NIC.
#[must_use]
pub fn bridge_nic_mac_for_vm_id(vm_id: &VmId) -> String {
    let hex: String = vm_id
        .as_str()
        .chars()
        .filter(|ch| ch.is_ascii_hexdigit())
        .collect();

    let mut bytes = [0_u8; 6];
    bytes[0] = 0x02;

    for (index, chunk) in hex.as_bytes().chunks(2).take(5).enumerate() {
        let text = std::str::from_utf8(chunk).unwrap_or("00");
        bytes[index + 1] = u8::from_str_radix(text, 16).unwrap_or(0);
    }

    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    )
}

/// VM information.
#[derive(Debug, Clone)]
pub struct VmInfo {
    /// VM ID.
    pub id: VmId,
    /// VM state.
    pub state: MachineState,
    /// Number of CPUs.
    pub cpus: u32,
    /// Memory in MB.
    pub memory_mb: u64,
}

/// Shared directory configuration for `VirtioFS`.
#[derive(Debug, Clone)]
pub struct SharedDirConfig {
    /// Host path to share.
    pub host_path: String,
    /// Tag for mounting in guest (e.g., "share").
    pub tag: String,
    /// Whether the share is read-only.
    pub read_only: bool,
}

impl SharedDirConfig {
    /// Creates a new shared directory configuration.
    #[must_use]
    pub fn new(host_path: impl Into<String>, tag: impl Into<String>) -> Self {
        Self {
            host_path: host_path.into(),
            tag: tag.into(),
            read_only: false,
        }
    }

    /// Sets the share as read-only.
    #[must_use]
    pub const fn read_only(mut self) -> Self {
        self.read_only = true;
        self
    }
}

/// Block device configuration for the VM.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BlockDeviceConfig {
    /// Path to the disk image file on the host.
    pub path: String,
    /// Whether the block device is read-only.
    pub read_only: bool,
}

/// VM configuration.
#[derive(Debug, Clone)]
pub struct VmConfig {
    /// Number of CPUs.
    pub cpus: u32,
    /// Memory in MB.
    pub memory_mb: u64,
    /// Kernel path.
    pub kernel: Option<String>,
    /// Kernel command line.
    pub cmdline: Option<String>,
    /// Shared directories for `VirtioFS`.
    pub shared_dirs: Vec<SharedDirConfig>,
    /// Block devices (e.g., EROFS rootfs, Btrfs data disk).
    pub block_devices: Vec<BlockDeviceConfig>,
    /// Enable networking.
    pub networking: bool,
    /// Enable vsock.
    pub vsock: bool,
    /// Guest CID for vsock connections (Linux).
    pub guest_cid: Option<u32>,
    /// Enable memory balloon device.
    ///
    /// The balloon device allows dynamic memory management by inflating
    /// (reclaiming memory from guest) or deflating (returning memory).
    pub balloon: bool,
    /// Enable Rosetta x86_64 translation (Apple Silicon only).
    ///
    /// When enabled, the VM exposes a VirtioFS share containing Apple's
    /// Rosetta binary and registers it via binfmt_misc in the guest.
    /// This allows near-native execution of x86_64 Linux binaries.
    pub rosetta: bool,
    /// macOS hypervisor backend selection.
    ///
    /// `Hv` (default) drives the custom HV-framework VMM; `Vz` drives
    /// Apple's Virtualization.framework managed execution and is the only
    /// backend that can host the Rosetta share.
    pub backend: arcbox_vmm::VmBackend,
}

impl Default for VmConfig {
    fn default() -> Self {
        Self {
            cpus: arcbox_hypervisor::default_vm_cpu_count(),
            memory_mb: 4096,
            kernel: None,
            cmdline: None,
            shared_dirs: Vec::new(),
            block_devices: Vec::new(),
            networking: true,
            vsock: true,
            guest_cid: None,
            balloon: true,
            rosetta: cfg!(all(target_os = "macos", target_arch = "aarch64")),
            backend: arcbox_vmm::VmBackend::Hv,
        }
    }
}
