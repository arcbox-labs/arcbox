//! Device configuration types.
//!
//! This module provides configurations for various virtual devices
//! that can be attached to a virtual machine.

mod entropy;
mod filesystem;
mod network;
mod serial;
mod socket;
mod storage;

pub use entropy::EntropyDeviceConfiguration;
pub use filesystem::{
    DirectoryShare, LinuxRosettaDirectoryShare, MultipleDirectoryShare, RosettaAvailability,
    SharedDirectory, SingleDirectoryShare, VirtioFileSystemDeviceConfiguration,
};
pub use network::NetworkDeviceConfiguration;
pub use serial::SerialPortConfiguration;
pub use socket::SocketDeviceConfiguration;
pub use storage::StorageDeviceConfiguration;
