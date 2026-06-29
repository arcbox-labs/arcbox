//! A running macOS guest VM, assembled from a cloned base image.
//!
//! [`MacVm::boot`] turns the disks produced by
//! [`MacImageManager::clone_base`](super::image::MacImageManager::clone_base) into a
//! live `arcbox-vz` virtual machine. The machine identifier is the one persisted with
//! the machine (the identifier its auxiliary storage was created with at install), so
//! a machine keeps a stable identity across reboots.

use std::path::Path;
use std::time::Duration;

use arcbox_vz::{
    MacAuxiliaryStorage, MacGraphicsDeviceConfiguration, MacHardwareModel, MacMachineIdentifier,
    MacOSBootLoader, MacPlatform, StorageDeviceConfiguration, VirtualMachine,
    VirtualMachineConfiguration, VirtualMachineState, min_cpu_count, min_memory_size,
};

use crate::error::{CoreError, Result};

const READINESS_POLL_INTERVAL: Duration = Duration::from_millis(250);
const READINESS_MAX_POLLS: u32 = 240; // ~60s

/// A booted macOS guest VM built from a cloned base image.
pub struct MacVm {
    vm: VirtualMachine,
}

impl MacVm {
    /// Boots a macOS guest from cloned instance disks and waits until it reaches the
    /// Running state.
    ///
    /// `machine_id` is the persisted identifier the auxiliary storage was created with;
    /// reusing it keeps the guest's identity stable across reboots. `cpus`/`memory_mib`
    /// are floored to the framework minimums. Apple Silicon only.
    ///
    /// # Errors
    /// Returns an error if the configuration is invalid, the VM cannot start, or it
    /// does not reach Running within the readiness window.
    #[allow(
        clippy::future_not_send,
        reason = "drives Virtualization.framework through ObjC pointers and the VM's dispatch queue, which are inherently !Send and held across await; the caller drives it on a single thread"
    )]
    pub async fn boot(
        disk: &Path,
        aux: &Path,
        hardware_model: &[u8],
        machine_id: &[u8],
        cpus: u32,
        memory_mib: u64,
    ) -> Result<Self> {
        let hardware_model = MacHardwareModel::from_data(hardware_model)?;
        let machine_id = MacMachineIdentifier::from_data(machine_id)?;
        let aux = MacAuxiliaryStorage::open(aux)?;
        let platform = MacPlatform::new(&hardware_model, &machine_id, &aux)?;

        let cpu_count = usize::try_from(u64::from(cpus).max(min_cpu_count())).unwrap_or(1);
        let memory = (memory_mib * 1024 * 1024).max(min_memory_size());

        let mut config = VirtualMachineConfiguration::new()?;
        config
            .set_cpu_count(cpu_count)
            .set_memory_size(memory)
            .set_platform(platform)
            .set_boot_loader(MacOSBootLoader::new()?)
            .add_storage_device(StorageDeviceConfiguration::disk_image(disk, false)?)
            .add_graphics_device(MacGraphicsDeviceConfiguration::new(1920, 1080, 80)?);
        config.validate()?;
        let vm = config.build()?;

        vm.start().await?;
        let mut polls = 0;
        while vm.state() != VirtualMachineState::Running && polls < READINESS_MAX_POLLS {
            tokio::time::sleep(READINESS_POLL_INTERVAL).await;
            polls += 1;
        }
        if vm.state() != VirtualMachineState::Running {
            return Err(CoreError::macos(format!(
                "macOS VM did not reach Running (state = {:?})",
                vm.state()
            )));
        }
        Ok(Self { vm })
    }

    /// Returns the current VM state.
    #[must_use]
    pub fn state(&self) -> VirtualMachineState {
        self.vm.state()
    }

    /// Returns whether the VM is in the Running state.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.vm.state() == VirtualMachineState::Running
    }

    /// Requests a graceful guest shutdown (the VM stops asynchronously).
    ///
    /// # Errors
    /// Returns an error if the guest cannot be asked to stop.
    pub fn request_stop(&self) -> Result<()> {
        Ok(self.vm.request_stop()?)
    }

    /// Forcibly stops the VM.
    ///
    /// # Errors
    /// Returns an error if the VM cannot be stopped.
    #[allow(
        clippy::future_not_send,
        reason = "Virtualization.framework VM handles are !Send; the caller drives stop on a single thread"
    )]
    pub async fn stop(&self) -> Result<()> {
        Ok(self.vm.stop().await?)
    }
}
