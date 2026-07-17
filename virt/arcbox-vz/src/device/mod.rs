//! Device configuration types.
//!
//! This module provides configurations for various virtual devices
//! that can be attached to a virtual machine.

mod balloon;
mod entropy;
mod filesystem;
mod graphics;
mod network;
mod serial;
mod socket;
mod storage;

pub(crate) use balloon::vm_memory_balloon_devices;
pub use balloon::{MemoryBalloonDevice, MemoryBalloonDeviceConfiguration};
pub use entropy::EntropyDeviceConfiguration;
pub use filesystem::{
    DirectoryShare, LinuxRosettaDirectoryShare, RosettaAvailability, SharedDirectory,
    SingleDirectoryShare, VirtioFileSystemDeviceConfiguration,
};
pub use graphics::MacGraphicsDeviceConfiguration;
pub use network::{NetworkDeviceConfiguration, desired_network_mtu};
pub use serial::SerialPortConfiguration;
pub use socket::SocketDeviceConfiguration;
pub use storage::StorageDeviceConfiguration;
