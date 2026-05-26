//! Safe wrapper around the macOS 15+ GICv3 emulation APIs.
//!
//! The GIC (Generic Interrupt Controller) is the standard interrupt controller
//! for ARM64. macOS 15 (Sequoia) added `hv_gic_*` APIs to Hypervisor.framework
//! that provide a hardware-accurate GICv3 model, eliminating the need for
//! software emulation.
//!
//! ## Xcode 26 API change
//!
//! Starting with the Xcode 26 SDK, the GIC API requires the VMM to explicitly
//! set distributor and redistributor base addresses via a config object.
//! The old `hv_gic_create(NULL)` pattern where the framework chose addresses
//! is no longer supported.

use tracing::debug;

use crate::error::{self, HvResult};
use crate::ffi;

/// Default GIC distributor base address (standard ARM64 VM layout).
pub const DEFAULT_GICD_BASE: u64 = 0x0800_0000;

/// Default GIC redistributor base address.
pub const DEFAULT_GICR_BASE: u64 = 0x080A_0000;

/// GIC configuration for creation.
pub struct GicConfig {
    /// Guest physical address of the GIC distributor (GICD).
    pub distributor_base: u64,
    /// Guest physical address of the GIC redistributor (GICR).
    pub redistributor_base: u64,
}

impl Default for GicConfig {
    fn default() -> Self {
        Self {
            distributor_base: DEFAULT_GICD_BASE,
            redistributor_base: DEFAULT_GICR_BASE,
        }
    }
}

/// Handle to the in-kernel GICv3 emulation.
///
/// Only one GIC instance exists per VM. Creating a [`Gic`] initialises the
/// interrupt controller; dropping it is a no-op (the GIC is destroyed with
/// the VM).
pub struct Gic {
    /// The distributor base address (stored for DTB generation).
    distributor_base: u64,
    /// The redistributor base address.
    redistributor_base: u64,
}

impl Gic {
    /// Creates and initialises the GICv3 with the given configuration.
    ///
    /// Must be called after `HvVm::new()` and before any vCPUs are started.
    /// Requires macOS 15+ with Xcode 26+ SDK.
    pub fn new(config: GicConfig) -> HvResult<Self> {
        // SAFETY: hv_gic_config_create returns an os_object; NULL on failure.
        let gic_config = unsafe { ffi::hv_gic_config_create() };
        if gic_config.is_null() {
            return Err(crate::error::HvError::NoResources);
        }

        // Set distributor base address.
        error::check(unsafe {
            ffi::hv_gic_config_set_distributor_base(gic_config, config.distributor_base)
        })?;

        // Set redistributor base address.
        error::check(unsafe {
            ffi::hv_gic_config_set_redistributor_base(gic_config, config.redistributor_base)
        })?;

        // Create the GIC with the configured addresses.
        error::check(unsafe { ffi::hv_gic_create(gic_config) })?;

        debug!(
            distributor_base = format_args!("{:#x}", config.distributor_base),
            redistributor_base = format_args!("{:#x}", config.redistributor_base),
            "GICv3 created"
        );

        Ok(Self {
            distributor_base: config.distributor_base,
            redistributor_base: config.redistributor_base,
        })
    }

    /// Creates a GIC with default base addresses (GICD=0x0800_0000, GICR=0x080A_0000).
    pub fn with_defaults() -> HvResult<Self> {
        Self::new(GicConfig::default())
    }

    /// Returns the distributor base address that was configured at creation.
    pub fn distributor_base(&self) -> u64 {
        self.distributor_base
    }

    /// Returns the redistributor base address that was configured at creation.
    pub fn redistributor_base(&self) -> u64 {
        self.redistributor_base
    }

    /// Resets the GIC to its initial state.
    pub fn reset(&self) -> HvResult<()> {
        error::check(unsafe { ffi::hv_gic_reset() })
    }

    /// Asserts or de-asserts a Shared Peripheral Interrupt (SPI).
    ///
    /// `intid` is the SPI number (32–1019 per the GICv3 spec).
    /// `level` = `true` to assert, `false` to de-assert.
    pub fn set_spi(&self, intid: u32, level: bool) -> HvResult<()> {
        error::check(unsafe { ffi::hv_gic_set_spi(intid, level) })
    }

    /// Returns the size of the GIC distributor MMIO region.
    pub fn get_distributor_size(&self) -> HvResult<usize> {
        let mut size: usize = 0;
        error::check(unsafe { ffi::hv_gic_get_distributor_size(&raw mut size) })?;
        Ok(size)
    }

    /// Returns the required alignment for the distributor base address.
    pub fn get_distributor_base_alignment(&self) -> HvResult<usize> {
        let mut alignment: usize = 0;
        error::check(unsafe { ffi::hv_gic_get_distributor_base_alignment(&raw mut alignment) })?;
        Ok(alignment)
    }

    /// Returns the base address of the GIC redistributor (GICR) for a given vCPU.
    pub fn get_redistributor_base(&self, vcpu_id: u64) -> HvResult<u64> {
        let mut addr: u64 = 0;
        error::check(unsafe { ffi::hv_gic_get_redistributor_base(vcpu_id, &raw mut addr) })?;
        Ok(addr)
    }

    /// Returns the total size of the GIC redistributor region (all vCPUs).
    pub fn get_redistributor_region_size(&self) -> HvResult<usize> {
        let mut size: usize = 0;
        error::check(unsafe { ffi::hv_gic_get_redistributor_region_size(&raw mut size) })?;
        Ok(size)
    }

    /// Returns the size of the MSI region.
    pub fn get_msi_region_size(&self) -> HvResult<usize> {
        let mut size: usize = 0;
        error::check(unsafe { ffi::hv_gic_get_msi_region_size(&raw mut size) })?;
        Ok(size)
    }

    /// Returns the supported SPI interrupt range (base, count).
    pub fn get_spi_interrupt_range(&self) -> HvResult<(u32, u32)> {
        let mut base: u32 = 0;
        let mut count: u32 = 0;
        error::check(unsafe {
            ffi::hv_gic_get_spi_interrupt_range(&raw mut base, &raw mut count)
        })?;
        Ok((base, count))
    }

    /// Restores GIC state from a previously saved snapshot.
    pub fn restore_state(&self, state: &[u8]) -> HvResult<()> {
        error::check(unsafe {
            ffi::hv_gic_set_state(state.as_ptr().cast::<std::ffi::c_void>(), state.len())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// M0 risk gate: verify hv_gic_create works on this macOS version.
    #[test]
    #[ignore = "requires com.apple.security.hypervisor entitlement"]
    fn gic_create_succeeds() {
        let _vm = crate::HvVm::new().expect("VM create failed");
        let _gic = Gic::with_defaults().expect("hv_gic_create failed — is macOS 15+?");
    }

    #[test]
    #[ignore = "requires com.apple.security.hypervisor entitlement"]
    fn gic_set_spi_does_not_error() {
        let _vm = crate::HvVm::new().expect("VM create failed");
        let gic = Gic::with_defaults().expect("GIC create failed");
        gic.set_spi(32, true).expect("set_spi assert failed");
        gic.set_spi(32, false).expect("set_spi deassert failed");
    }

    #[test]
    #[ignore = "requires com.apple.security.hypervisor entitlement"]
    fn gic_distributor_base_matches_config() {
        let _vm = crate::HvVm::new().expect("VM create failed");
        let gic = Gic::with_defaults().expect("GIC create failed");
        assert_eq!(gic.distributor_base(), DEFAULT_GICD_BASE);
    }

    #[test]
    #[ignore = "requires com.apple.security.hypervisor entitlement"]
    fn gic_redistributor_base_requires_vcpu() {
        let _vm = crate::HvVm::new().expect("VM create failed");
        let gic = Gic::with_defaults().expect("GIC create failed");
        let vcpu = crate::HvVcpu::new().expect("vCPU create failed");
        let base = gic
            .get_redistributor_base(vcpu.id())
            .expect("get_redistributor_base failed");
        assert_ne!(base, 0, "GICR base should be nonzero");
    }
}
