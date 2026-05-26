//! Safe wrapper around Hypervisor.framework VM lifecycle.
//!
//! Only one VM may exist per process. Creating a second VM will return
//! [`HvError::Busy`].

use std::ptr;

use tracing::debug;

use crate::error::{self, HvResult};
use crate::ffi;
use crate::memory::MemoryPermission;

/// Handle to a Hypervisor.framework VM instance.
///
/// Dropping this struct destroys the VM and releases all associated resources
/// (memory mappings, vCPUs, GIC state, etc.).
pub struct HvVm {
    _private: (),
}

impl HvVm {
    /// Creates a new VM with default configuration (36-bit IPA, ~64 GB).
    ///
    /// Only one VM may exist per process — calling this while a VM is already
    /// alive returns [`HvError::Busy`].
    pub fn new() -> HvResult<Self> {
        // SAFETY: `hv_vm_create(NULL)` creates a VM with default config.
        // The framework enforces single-VM-per-process internally.
        error::check(unsafe { ffi::hv_vm_create(ptr::null_mut()) })?;
        debug!("hypervisor VM created (default IPA size)");
        Ok(Self { _private: () })
    }

    /// Creates a new VM with a custom IPA (Intermediate Physical Address) size.
    ///
    /// The default IPA size is 36 bits (~64 GB). For VMs needing more guest
    /// physical address space (e.g. >32 GB RAM + MMIO), use 40 bits (~1 TB).
    ///
    /// Available since macOS 13.0.
    pub fn with_ipa_size(ipa_bits: u32) -> HvResult<Self> {
        let config = unsafe { ffi::hv_vm_config_create() };
        if config.is_null() {
            return Err(crate::error::HvError::NoResources);
        }
        // Note: config is a framework-managed object; no explicit free needed.
        error::check(unsafe { ffi::hv_vm_config_set_ipa_size(config, ipa_bits) })?;
        error::check(unsafe { ffi::hv_vm_create(config) })?;
        debug!(ipa_bits, "hypervisor VM created");
        Ok(Self { _private: () })
    }

    /// Maps a region of host memory into the guest physical address space.
    ///
    /// Both `host_addr` and `ipa` must be page-aligned (4 KiB on ARM64).
    /// `size` must also be a multiple of the page size.
    ///
    /// # Safety
    ///
    /// `host_addr` must point to a valid allocation of at least `size` bytes
    /// that will remain live for as long as the mapping exists.
    pub unsafe fn map_memory(
        &self,
        host_addr: *mut u8,
        ipa: u64,
        size: usize,
        perm: MemoryPermission,
    ) -> HvResult<()> {
        // SAFETY: Caller guarantees `host_addr` validity and alignment.
        // The framework validates IPA range and overlap.
        error::check(unsafe { ffi::hv_vm_map(host_addr, ipa, size, perm.bits()) })
    }

    /// Unmaps a previously mapped guest physical address region.
    ///
    /// `ipa` and `size` must exactly match a prior `map_memory` call.
    pub fn unmap_memory(&self, ipa: u64, size: usize) -> HvResult<()> {
        // SAFETY: The caller ensures the IPA region was previously mapped.
        error::check(unsafe { ffi::hv_vm_unmap(ipa, size) })
    }

    /// Changes the access permissions for a previously mapped IPA region.
    pub fn protect_memory(&self, ipa: u64, size: usize, perm: MemoryPermission) -> HvResult<()> {
        // SAFETY: The caller ensures the IPA region was previously mapped.
        error::check(unsafe { ffi::hv_vm_protect(ipa, size, perm.bits()) })
    }

    /// Forces the given vCPUs to exit their run loops.
    ///
    /// Any blocked [`HvVcpu::run()`](crate::HvVcpu::run) call on one of the
    /// listed vCPUs will return `VcpuExit::Canceled`. For a vCPU that is
    /// not currently inside `hv_vcpu_run`, the next call to `hv_vcpu_run`
    /// for that vCPU returns immediately without entering the guest. Can
    /// be called from any thread and is the primary mechanism for clean
    /// shutdown.
    ///
    /// # Important — arm64 vs x86
    ///
    /// On **arm64**, Apple's `hv_vcpus_exit` requires a concrete list of
    /// vCPU IDs; passing `NULL, 0` is a no-op ("exit 0 vCPUs from an empty
    /// list"). Callers must thread through the real `HvVcpu::raw_handle()`
    /// values from every vCPU thread. The x86 convention of `NULL, 0`
    /// meaning "all vCPUs" does not apply. See ABX-367 for the regression
    /// this prevents.
    pub fn exit_vcpus(&self, vcpus: &[u64]) -> HvResult<()> {
        if vcpus.is_empty() {
            return Ok(());
        }
        // SAFETY: `vcpus` is a live slice of vCPU IDs; the framework reads
        // `vcpus.len()` u64 elements and does not retain the pointer.
        #[allow(
            clippy::cast_possible_truncation,
            reason = "vcpu count cannot exceed u32::MAX"
        )]
        error::check(unsafe { ffi::hv_vcpus_exit(vcpus.as_ptr(), vcpus.len() as u32) })
    }
}

impl Drop for HvVm {
    fn drop(&mut self) {
        // SAFETY: Destroying the VM is always valid when one exists. We own
        // the sole VM handle so no other code can race this call.
        let ret = unsafe { ffi::hv_vm_destroy() };
        if let Err(e) = error::check(ret) {
            tracing::warn!("hv_vm_destroy failed: {e}");
        } else {
            debug!("hypervisor VM destroyed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Requires `com.apple.security.hypervisor` entitlement.
    /// Run with: `cargo test -p arcbox-hv -- --ignored`
    #[test]
    #[ignore = "requires com.apple.security.hypervisor entitlement"]
    fn create_and_destroy_vm() {
        let vm = HvVm::new().expect("hv_vm_create failed — is the entitlement set?");
        drop(vm);
    }

    #[test]
    #[ignore = "requires com.apple.security.hypervisor entitlement"]
    fn double_create_returns_busy() {
        let vm1 = HvVm::new().expect("first VM create failed");
        let result = HvVm::new();
        assert!(
            result.is_err(),
            "second VM create should fail with Busy or Error"
        );
        drop(vm1);
    }

    #[test]
    #[ignore = "requires com.apple.security.hypervisor entitlement"]
    fn exit_vcpus_empty_list_is_noop() {
        let vm = HvVm::new().expect("VM create failed");
        vm.exit_vcpus(&[])
            .expect("exit_vcpus with an empty list should succeed as a no-op");
    }

    /// Verifies that the `hv_vcpus_exit` FFI path is actually reached when a
    /// real vCPU handle is passed. The vCPU is not running, so the framework
    /// will arm a deferred-exit flag instead of interrupting a run loop — but
    /// the call must still succeed.
    #[test]
    #[ignore = "requires com.apple.security.hypervisor entitlement"]
    fn exit_vcpus_with_real_vcpu_succeeds() {
        let vm = HvVm::new().expect("VM create failed");
        let vcpu = crate::HvVcpu::new().expect("vCPU create failed");
        let handle = vcpu.raw_handle();

        // Calling exit_vcpus on an idle (not-running) vCPU must still return
        // Ok — the framework simply sets a flag so the next hv_vcpu_run
        // returns immediately rather than entering the guest.
        vm.exit_vcpus(&[handle])
            .expect("exit_vcpus with a valid idle vCPU should succeed");

        drop(vcpu);
        drop(vm);
    }

    #[test]
    #[ignore = "requires com.apple.security.hypervisor entitlement"]
    fn map_and_unmap_memory() {
        let vm = HvVm::new().expect("VM create failed");
        let size = 4096;
        let layout = std::alloc::Layout::from_size_align(size, 4096).unwrap();
        // SAFETY: Layout is valid and non-zero.
        let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
        assert!(!ptr.is_null());

        // SAFETY: ptr is a valid 4KB-aligned allocation.
        unsafe {
            vm.map_memory(ptr, 0x4000_0000, size, MemoryPermission::READ_WRITE)
                .expect("map failed");
        }
        vm.unmap_memory(0x4000_0000, size).expect("unmap failed");

        // SAFETY: ptr was allocated with layout.
        unsafe { std::alloc::dealloc(ptr, layout) };
    }
}
