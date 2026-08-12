#[cfg(test)]
mod tests {
    use super::super::virtio::{VIRTIO_MMIO_BASE, VIRTIO_MMIO_GAP, VIRTIO_MMIO_SIZE};
    use super::super::*;
    use crate::memory::PAGE_SIZE;
    use crate::traits::{Vcpu, VirtualMachine};
    use crate::types::{CpuArch, VirtioDeviceConfig, VirtioDeviceType};
    use std::sync::Arc;

    #[test]
    #[ignore] // Requires /dev/kvm
    fn test_vm_creation() {
        let kvm = Arc::new(KvmSystem::open().expect("Failed to open KVM"));
        let mmap_size = kvm.vcpu_mmap_size().expect("Failed to get mmap size");

        let config = VmConfig {
            vcpu_count: 2,
            memory_size: 128 * 1024 * 1024,
            arch: CpuArch::native(),
            ..Default::default()
        };

        let vm = KvmVm::new(kvm, mmap_size, config).unwrap();
        assert_eq!(vm.state(), VmState::Created);
        assert!(!vm.is_running());
    }

    #[test]
    #[ignore] // Requires /dev/kvm
    fn test_vcpu_creation() {
        let kvm = Arc::new(KvmSystem::open().expect("Failed to open KVM"));
        let mmap_size = kvm.vcpu_mmap_size().expect("Failed to get mmap size");

        let config = VmConfig {
            vcpu_count: 4,
            memory_size: 128 * 1024 * 1024,
            ..Default::default()
        };

        let mut vm = KvmVm::new(kvm, mmap_size, config).unwrap();

        // Create valid vCPUs
        let vcpu0 = vm.create_vcpu(0);
        assert!(vcpu0.is_ok());
        assert_eq!(vcpu0.unwrap().id(), 0);

        let vcpu1 = vm.create_vcpu(1);
        assert!(vcpu1.is_ok());

        // Try to create same vCPU again
        let vcpu0_again = vm.create_vcpu(0);
        assert!(vcpu0_again.is_err());

        // Try to create vCPU with invalid ID
        let vcpu99 = vm.create_vcpu(99);
        assert!(vcpu99.is_err());
    }

    #[test]
    #[ignore] // Requires /dev/kvm
    fn test_vm_lifecycle() {
        let kvm = Arc::new(KvmSystem::open().expect("Failed to open KVM"));
        let mmap_size = kvm.vcpu_mmap_size().expect("Failed to get mmap size");

        let config = VmConfig {
            vcpu_count: 1,
            memory_size: 64 * 1024 * 1024,
            ..Default::default()
        };

        let mut vm = KvmVm::new(kvm, mmap_size, config).unwrap();
        assert_eq!(vm.state(), VmState::Created);

        // Start
        vm.start().unwrap();
        assert_eq!(vm.state(), VmState::Running);
        assert!(vm.is_running());

        // Pause
        vm.pause().unwrap();
        assert_eq!(vm.state(), VmState::Paused);

        // Resume
        vm.resume().unwrap();
        assert_eq!(vm.state(), VmState::Running);

        // Stop
        vm.stop().unwrap();
        assert_eq!(vm.state(), VmState::Stopped);
        assert!(!vm.is_running());
    }

    #[test]
    #[ignore] // Requires /dev/kvm
    fn test_add_virtio_device() {
        let kvm = Arc::new(KvmSystem::open().expect("Failed to open KVM"));
        let mmap_size = kvm.vcpu_mmap_size().expect("Failed to get mmap size");

        let config = VmConfig {
            vcpu_count: 1,
            memory_size: 64 * 1024 * 1024,
            ..Default::default()
        };

        let mut vm = KvmVm::new(kvm, mmap_size, config).unwrap();
        assert_eq!(vm.state(), VmState::Created);

        // Add a block device.
        let blk_config = VirtioDeviceConfig::block("/dev/null", true);
        vm.add_virtio_device(blk_config).unwrap();

        // Verify device info.
        let devices = vm.virtio_devices().unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].device_type, VirtioDeviceType::Block);
        assert_eq!(devices[0].mmio_base, VIRTIO_MMIO_BASE);
        assert_eq!(devices[0].mmio_size, VIRTIO_MMIO_SIZE);
        assert!(devices[0].irq_fd >= 0);
        assert!(devices[0].notify_fd >= 0);

        // Add a network device.
        let net_config = VirtioDeviceConfig::network_with_mac("02:00:00:00:00:01");
        vm.add_virtio_device(net_config).unwrap();

        // Verify second device.
        let devices = vm.virtio_devices().unwrap();
        assert_eq!(devices.len(), 2);
        assert_eq!(devices[1].device_type, VirtioDeviceType::Net);
        assert_eq!(
            devices[1].mmio_base,
            VIRTIO_MMIO_BASE + VIRTIO_MMIO_SIZE + VIRTIO_MMIO_GAP
        );

        // Cannot add device after VM starts.
        vm.start().unwrap();
        let fs_config = VirtioDeviceConfig::filesystem("/share", "share", false);
        let result = vm.add_virtio_device(fs_config);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_dirty_bitmap_empty() {
        let bitmap: Vec<u64> = vec![0; 4];
        let pages = KvmVm::parse_dirty_bitmap(&bitmap, 0, 1024 * 1024);
        assert!(pages.is_empty());
    }

    #[test]
    fn test_parse_dirty_bitmap_all_dirty() {
        // 64 pages = 1 word, all bits set.
        let bitmap: Vec<u64> = vec![u64::MAX];
        let pages = KvmVm::parse_dirty_bitmap(&bitmap, 0, 64 * PAGE_SIZE);
        assert_eq!(pages.len(), 64);

        // Verify first and last page addresses.
        assert_eq!(pages[0].guest_addr, 0);
        assert_eq!(pages[0].size, PAGE_SIZE);
        assert_eq!(pages[63].guest_addr, 63 * PAGE_SIZE);
    }

    #[test]
    fn test_parse_dirty_bitmap_sparse() {
        // Only pages 0, 63, 64, and 127 are dirty (first and last of two words).
        let mut bitmap: Vec<u64> = vec![0; 2];
        bitmap[0] = 1 | (1 << 63); // Page 0 and 63.
        bitmap[1] = 1 | (1 << 63); // Page 64 and 127.

        let pages = KvmVm::parse_dirty_bitmap(&bitmap, 0x1000_0000, 128 * PAGE_SIZE);
        assert_eq!(pages.len(), 4);

        assert_eq!(pages[0].guest_addr, 0x1000_0000);
        assert_eq!(pages[1].guest_addr, 0x1000_0000 + 63 * PAGE_SIZE);
        assert_eq!(pages[2].guest_addr, 0x1000_0000 + 64 * PAGE_SIZE);
        assert_eq!(pages[3].guest_addr, 0x1000_0000 + 127 * PAGE_SIZE);
    }

    #[test]
    #[ignore] // Requires /dev/kvm
    fn test_dirty_tracking_enable_disable() {
        let kvm = Arc::new(KvmSystem::open().expect("Failed to open KVM"));
        let mmap_size = kvm.vcpu_mmap_size().expect("Failed to get mmap size");

        let config = VmConfig {
            vcpu_count: 1,
            memory_size: 16 * 1024 * 1024, // 16MB
            ..Default::default()
        };

        let vm = KvmVm::new(kvm, mmap_size, config).unwrap();

        // Initially disabled.
        assert!(!vm.is_dirty_tracking_enabled());

        // Cannot get dirty pages when not enabled.
        assert!(vm.get_dirty_pages().is_err());

        // Enable dirty tracking.
        vm.enable_dirty_tracking().unwrap();
        assert!(vm.is_dirty_tracking_enabled());

        // Re-enabling is a no-op.
        vm.enable_dirty_tracking().unwrap();
        assert!(vm.is_dirty_tracking_enabled());

        // Can get dirty pages (should be all pages initially).
        let pages = vm.get_dirty_pages().unwrap();
        // All pages might be marked dirty initially.
        println!("Initial dirty pages: {}", pages.len());

        // Disable dirty tracking.
        vm.disable_dirty_tracking().unwrap();
        assert!(!vm.is_dirty_tracking_enabled());

        // Cannot get dirty pages when disabled.
        assert!(vm.get_dirty_pages().is_err());
    }
}
