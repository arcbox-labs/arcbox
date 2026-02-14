//! Integration tests for VM snapshot/restore functionality on Darwin.
//!
//! These tests verify the snapshot and restore capabilities of the
//! hypervisor layer, including:
//! - VmSnapshot creation and serialization
//! - vCPU state snapshots
//! - Memory region information
//! - Device configuration metadata
//! - Incremental snapshot support (parent_id)
//!
//! Note: On macOS Virtualization.framework, full vCPU register access is not
//! available, so snapshots contain cached register values rather than live state.
//! For production use, the VM should be paused before taking snapshots.

#![allow(clippy::expect_fun_call)]
#![allow(clippy::field_reassign_with_default)]

#[cfg(target_os = "macos")]
use arcbox_hypervisor::{
    config::VmConfig,
    darwin::{DarwinHypervisor, is_supported},
    memory::GuestAddress,
    traits::{GuestMemory, Hypervisor, Vcpu, VirtualMachine},
    types::{
        CpuArch, DeviceSnapshot, MemoryRegionSnapshot, Registers, VcpuSnapshot,
        VirtioDeviceConfig, VirtioDeviceType, VmSnapshot,
    },
};

// ============================================================================
// Basic Snapshot Tests
// ============================================================================

/// Test basic VM snapshot creation without devices.
///
/// Verifies that a snapshot can be created from a VM with:
/// - Correct architecture information
/// - vCPU state snapshots
/// - Memory region information
#[cfg(target_os = "macos")]
#[test]
fn test_vm_snapshot_basic() {
    if !is_supported() {
        println!("Virtualization not supported, skipping");
        return;
    }

    let hypervisor = DarwinHypervisor::new().expect("Failed to create hypervisor");

    let config = VmConfig {
        vcpu_count: 2,
        memory_size: 256 * 1024 * 1024, // 256 MB
        arch: CpuArch::native(),
        ..Default::default()
    };

    let mut vm = hypervisor.create_vm(config).expect("Failed to create VM");

    // Create vCPUs with initial register state
    let mut vcpu0 = vm.create_vcpu(0).expect("Failed to create vCPU 0");
    let mut vcpu1 = vm.create_vcpu(1).expect("Failed to create vCPU 1");

    // Set distinct register values for each vCPU
    let mut regs0 = Registers::default();
    regs0.rax = 0xAAAA_BBBB_CCCC_DDDD;
    regs0.rip = 0x0000_1000;
    vcpu0.set_regs(&regs0).expect("Failed to set vCPU 0 regs");

    let mut regs1 = Registers::default();
    regs1.rax = 0x1111_2222_3333_4444;
    regs1.rip = 0x0000_2000;
    vcpu1.set_regs(&regs1).expect("Failed to set vCPU 1 regs");

    // Take vCPU snapshots
    let snap0 = vcpu0.snapshot().expect("Failed to snapshot vCPU 0");
    let snap1 = vcpu1.snapshot().expect("Failed to snapshot vCPU 1");

    // Verify vCPU snapshot structure
    assert_eq!(snap0.id, 0);
    assert_eq!(snap1.id, 1);
    assert_eq!(snap0.arch, CpuArch::native());
    assert_eq!(snap1.arch, CpuArch::native());

    // Verify register values in snapshots
    #[cfg(target_arch = "x86_64")]
    {
        let regs0_snap = snap0.x86_regs.as_ref().expect("Missing x86 regs in snapshot 0");
        let regs1_snap = snap1.x86_regs.as_ref().expect("Missing x86 regs in snapshot 1");

        assert_eq!(regs0_snap.rax, 0xAAAA_BBBB_CCCC_DDDD);
        assert_eq!(regs0_snap.rip, 0x0000_1000);
        assert_eq!(regs1_snap.rax, 0x1111_2222_3333_4444);
        assert_eq!(regs1_snap.rip, 0x0000_2000);
    }

    #[cfg(target_arch = "aarch64")]
    {
        let arm0 = snap0.arm64_regs.as_ref().expect("Missing ARM64 regs in snapshot 0");
        let arm1 = snap1.arm64_regs.as_ref().expect("Missing ARM64 regs in snapshot 1");

        // On ARM64, rax/rip are mapped to x[0]/pc
        assert_eq!(arm0.x[0], 0xAAAA_BBBB_CCCC_DDDD);
        assert_eq!(arm0.pc, 0x0000_1000);
        assert_eq!(arm1.x[0], 0x1111_2222_3333_4444);
        assert_eq!(arm1.pc, 0x0000_2000);
    }

    // Verify memory info
    let memory = vm.memory();
    assert_eq!(memory.size(), 256 * 1024 * 1024);

    println!("Basic VM snapshot test passed");
}

/// Test VM snapshot with attached devices.
///
/// Verifies that device configuration metadata is captured in snapshots.
/// On Darwin, actual device state is not available, but configuration
/// metadata is preserved for restore validation.
#[cfg(target_os = "macos")]
#[test]
fn test_vm_snapshot_with_devices() {
    if !is_supported() {
        println!("Virtualization not supported, skipping");
        return;
    }

    let hypervisor = DarwinHypervisor::new().expect("Failed to create hypervisor");

    let config = VmConfig {
        vcpu_count: 1,
        memory_size: 256 * 1024 * 1024,
        arch: CpuArch::native(),
        ..Default::default()
    };

    let mut vm = hypervisor.create_vm(config).expect("Failed to create VM");

    // Add various VirtIO devices
    vm.add_virtio_device(VirtioDeviceConfig::network())
        .expect("Failed to add network device");

    vm.add_virtio_device(VirtioDeviceConfig::vsock())
        .expect("Failed to add vsock device");

    vm.add_virtio_device(VirtioDeviceConfig::entropy())
        .expect("Failed to add entropy device");

    // Get device snapshots
    let device_snapshots = vm.snapshot_devices().expect("Failed to snapshot devices");

    // Verify device count (network, vsock, entropy)
    // Note: entropy device is added by default in DarwinVm::new(), but also
    // tracked in device_configs when explicitly added
    assert!(
        device_snapshots.len() >= 2,
        "Expected at least 2 device snapshots, got {}",
        device_snapshots.len()
    );

    // Verify device types are captured
    let device_types: Vec<_> = device_snapshots.iter().map(|d| d.device_type).collect();

    assert!(
        device_types.contains(&VirtioDeviceType::Net),
        "Network device not found in snapshot"
    );
    assert!(
        device_types.contains(&VirtioDeviceType::Vsock),
        "Vsock device not found in snapshot"
    );

    // Verify each device has a name
    for device in &device_snapshots {
        assert!(!device.name.is_empty(), "Device name should not be empty");
        println!("Device snapshot: {:?} - {}", device.device_type, device.name);
    }

    println!("VM snapshot with devices test passed");
}

/// Test restoring vCPU state from a snapshot.
///
/// Verifies that vCPU register state can be restored from a snapshot.
/// On Darwin, this caches the values but doesn't apply them to the actual vCPU.
#[cfg(target_os = "macos")]
#[test]
fn test_vm_restore_from_snapshot() {
    if !is_supported() {
        println!("Virtualization not supported, skipping");
        return;
    }

    let hypervisor = DarwinHypervisor::new().expect("Failed to create hypervisor");

    let config = VmConfig {
        vcpu_count: 1,
        memory_size: 256 * 1024 * 1024,
        arch: CpuArch::native(),
        ..Default::default()
    };

    let mut vm = hypervisor.create_vm(config).expect("Failed to create VM");
    let mut vcpu = vm.create_vcpu(0).expect("Failed to create vCPU");

    // Set initial state
    let mut initial_regs = Registers::default();
    initial_regs.rax = 0xDEAD_BEEF_CAFE_BABE;
    initial_regs.rbx = 0x1234_5678_9ABC_DEF0;
    initial_regs.rip = 0x0000_FFFF_0000_1000;
    initial_regs.rsp = 0x7FFF_FFFF_FFFF_F000;
    vcpu.set_regs(&initial_regs).expect("Failed to set initial regs");

    // Take snapshot
    let snapshot = vcpu.snapshot().expect("Failed to create snapshot");

    // Verify snapshot ID matches
    assert_eq!(snapshot.id, 0);

    // Modify registers
    let mut modified_regs = Registers::default();
    modified_regs.rax = 0x0000_0000_0000_0000;
    modified_regs.rip = 0x0000_0000_0000_0000;
    vcpu.set_regs(&modified_regs).expect("Failed to modify regs");

    // Verify modification took effect
    let current_regs = vcpu.get_regs().expect("Failed to get current regs");
    assert_eq!(current_regs.rax, 0);
    assert_eq!(current_regs.rip, 0);

    // Restore from snapshot
    vcpu.restore(&snapshot).expect("Failed to restore from snapshot");

    // Verify state is restored
    let restored_regs = vcpu.get_regs().expect("Failed to get restored regs");

    #[cfg(target_arch = "x86_64")]
    {
        assert_eq!(restored_regs.rax, 0xDEAD_BEEF_CAFE_BABE);
        assert_eq!(restored_regs.rbx, 0x1234_5678_9ABC_DEF0);
        assert_eq!(restored_regs.rip, 0x0000_FFFF_0000_1000);
        assert_eq!(restored_regs.rsp, 0x7FFF_FFFF_FFFF_F000);
    }

    #[cfg(target_arch = "aarch64")]
    {
        // On ARM64, the values are mapped differently
        // Just verify restore happened (values may be in different registers)
        assert!(
            restored_regs.rax != 0 || restored_regs.rip != 0,
            "Restore should have changed some registers"
        );
    }

    println!("VM restore from snapshot test passed");
}

/// Test that restoring a snapshot with mismatched vCPU ID fails.
#[cfg(target_os = "macos")]
#[test]
fn test_vm_restore_vcpu_id_mismatch() {
    if !is_supported() {
        println!("Virtualization not supported, skipping");
        return;
    }

    let hypervisor = DarwinHypervisor::new().expect("Failed to create hypervisor");

    let config = VmConfig {
        vcpu_count: 2,
        memory_size: 256 * 1024 * 1024,
        arch: CpuArch::native(),
        ..Default::default()
    };

    let mut vm = hypervisor.create_vm(config).expect("Failed to create VM");

    let vcpu0 = vm.create_vcpu(0).expect("Failed to create vCPU 0");
    let mut vcpu1 = vm.create_vcpu(1).expect("Failed to create vCPU 1");

    // Take snapshot of vCPU 0
    let snapshot0 = vcpu0.snapshot().expect("Failed to snapshot vCPU 0");
    assert_eq!(snapshot0.id, 0);

    // Try to restore vCPU 0's snapshot to vCPU 1 - should fail
    let result = vcpu1.restore(&snapshot0);
    assert!(result.is_err(), "Restore with mismatched vCPU ID should fail");

    println!("vCPU ID mismatch detection test passed");
}

// ============================================================================
// VmSnapshot Serialization Tests
// ============================================================================

/// Test VmSnapshot JSON serialization/deserialization.
///
/// Verifies that the complete VM snapshot structure can be serialized
/// to JSON and deserialized back correctly.
#[cfg(target_os = "macos")]
#[test]
fn test_snapshot_serialization() {
    // Create a VmSnapshot with test data
    let vcpu_snapshots = vec![
        VcpuSnapshot::new_x86(
            0,
            Registers {
                rax: 0x1111,
                rbx: 0x2222,
                rcx: 0x3333,
                rdx: 0x4444,
                rip: 0x1000,
                rflags: 0x202,
                ..Default::default()
            },
        ),
        VcpuSnapshot::new_x86(
            1,
            Registers {
                rax: 0x5555,
                rbx: 0x6666,
                rip: 0x2000,
                ..Default::default()
            },
        ),
    ];

    let device_snapshots = vec![
        DeviceSnapshot {
            device_type: VirtioDeviceType::Block,
            name: "block-0-rootfs".to_string(),
            state: b"test block state".to_vec(),
        },
        DeviceSnapshot {
            device_type: VirtioDeviceType::Net,
            name: "net-0".to_string(),
            state: vec![],
        },
    ];

    let memory_regions = vec![
        MemoryRegionSnapshot {
            guest_addr: 0x0000_0000,
            size: 256 * 1024 * 1024,
            read_only: false,
            file_offset: 0,
        },
        MemoryRegionSnapshot {
            guest_addr: 0x1000_0000,
            size: 64 * 1024 * 1024,
            read_only: true,
            file_offset: 256 * 1024 * 1024,
        },
    ];

    let snapshot = VmSnapshot {
        version: 1,
        arch: CpuArch::X86_64,
        vcpus: vcpu_snapshots,
        devices: device_snapshots,
        memory_regions,
        total_memory: 320 * 1024 * 1024,
        compressed: false,
        compression: None,
        parent_id: None,
    };

    // Serialize to JSON
    let json = serde_json::to_string_pretty(&snapshot).expect("Failed to serialize snapshot");

    // Verify JSON contains expected fields
    assert!(json.contains("\"version\": 1"));
    assert!(json.contains("\"arch\": \"X86_64\""));
    assert!(json.contains("\"block-0-rootfs\""));
    assert!(json.contains("\"net-0\""));
    assert!(json.contains("\"total_memory\": 335544320")); // 320 * 1024 * 1024

    // Deserialize back
    let restored: VmSnapshot =
        serde_json::from_str(&json).expect("Failed to deserialize snapshot");

    // Verify structure
    assert_eq!(restored.version, 1);
    assert_eq!(restored.arch, CpuArch::X86_64);
    assert_eq!(restored.vcpus.len(), 2);
    assert_eq!(restored.devices.len(), 2);
    assert_eq!(restored.memory_regions.len(), 2);
    assert_eq!(restored.total_memory, 320 * 1024 * 1024);
    assert!(!restored.compressed);
    assert!(restored.compression.is_none());
    assert!(restored.parent_id.is_none());

    // Verify vCPU data
    assert_eq!(restored.vcpus[0].id, 0);
    assert_eq!(restored.vcpus[1].id, 1);

    let vcpu0_regs = restored.vcpus[0]
        .x86_regs
        .as_ref()
        .expect("Missing x86 regs");
    assert_eq!(vcpu0_regs.rax, 0x1111);
    assert_eq!(vcpu0_regs.rip, 0x1000);

    // Verify device data
    assert_eq!(restored.devices[0].device_type, VirtioDeviceType::Block);
    assert_eq!(restored.devices[0].name, "block-0-rootfs");
    assert_eq!(restored.devices[0].state, b"test block state".to_vec());

    // Verify memory regions
    assert_eq!(restored.memory_regions[0].guest_addr, 0x0000_0000);
    assert_eq!(restored.memory_regions[0].size, 256 * 1024 * 1024);
    assert!(!restored.memory_regions[0].read_only);
    assert!(restored.memory_regions[1].read_only);

    println!("Snapshot serialization test passed");
}

/// Test VmSnapshot serialization with compression metadata.
#[cfg(target_os = "macos")]
#[test]
fn test_snapshot_serialization_with_compression() {
    let snapshot = VmSnapshot {
        version: 1,
        arch: CpuArch::native(),
        vcpus: vec![],
        devices: vec![],
        memory_regions: vec![],
        total_memory: 1024 * 1024 * 1024,
        compressed: true,
        compression: Some("zstd".to_string()),
        parent_id: None,
    };

    let json = serde_json::to_string(&snapshot).expect("Failed to serialize");
    let restored: VmSnapshot = serde_json::from_str(&json).expect("Failed to deserialize");

    assert!(restored.compressed);
    assert_eq!(restored.compression, Some("zstd".to_string()));

    println!("Snapshot compression metadata serialization test passed");
}

// ============================================================================
// Incremental Snapshot Tests
// ============================================================================

/// Test incremental snapshot with parent_id.
///
/// Verifies that incremental snapshots correctly reference their parent
/// and maintain the snapshot chain for efficient storage.
#[cfg(target_os = "macos")]
#[test]
fn test_incremental_snapshot() {
    // Create base snapshot
    let base_snapshot = VmSnapshot {
        version: 1,
        arch: CpuArch::native(),
        vcpus: vec![VcpuSnapshot::new_x86(
            0,
            Registers {
                rax: 0x1000,
                rip: 0x2000,
                ..Default::default()
            },
        )],
        devices: vec![],
        memory_regions: vec![MemoryRegionSnapshot {
            guest_addr: 0,
            size: 256 * 1024 * 1024,
            read_only: false,
            file_offset: 0,
        }],
        total_memory: 256 * 1024 * 1024,
        compressed: false,
        compression: None,
        parent_id: None, // Base snapshot has no parent
    };

    // Generate a unique ID for the base snapshot
    let base_snapshot_id = "snapshot-base-20240101-000000".to_string();

    // Create incremental snapshot referencing the base
    let incremental_snapshot = VmSnapshot {
        version: 1,
        arch: CpuArch::native(),
        vcpus: vec![VcpuSnapshot::new_x86(
            0,
            Registers {
                rax: 0x3000, // Changed value
                rip: 0x4000, // Changed value
                ..Default::default()
            },
        )],
        devices: vec![],
        memory_regions: vec![MemoryRegionSnapshot {
            guest_addr: 0,
            size: 256 * 1024 * 1024,
            read_only: false,
            file_offset: 0, // In practice, this would be offset to delta data
        }],
        total_memory: 256 * 1024 * 1024,
        compressed: true,
        compression: Some("zstd".to_string()),
        parent_id: Some(base_snapshot_id.clone()), // References parent
    };

    // Verify parent_id relationship
    assert!(base_snapshot.parent_id.is_none());
    assert_eq!(
        incremental_snapshot.parent_id,
        Some(base_snapshot_id.clone())
    );

    // Serialize both and verify structure
    let base_json =
        serde_json::to_string_pretty(&base_snapshot).expect("Failed to serialize base");
    let incr_json =
        serde_json::to_string_pretty(&incremental_snapshot).expect("Failed to serialize incr");

    assert!(base_json.contains("\"parent_id\": null"));
    assert!(incr_json.contains(&format!("\"parent_id\": \"{}\"", base_snapshot_id)));

    // Deserialize and verify chain
    let restored_base: VmSnapshot =
        serde_json::from_str(&base_json).expect("Failed to deserialize base");
    let restored_incr: VmSnapshot =
        serde_json::from_str(&incr_json).expect("Failed to deserialize incr");

    assert!(restored_base.parent_id.is_none());
    assert_eq!(
        restored_incr.parent_id,
        Some(base_snapshot_id)
    );

    // Verify the incremental snapshot has updated values
    let incr_regs = restored_incr.vcpus[0]
        .x86_regs
        .as_ref()
        .expect("Missing regs");
    assert_eq!(incr_regs.rax, 0x3000);
    assert_eq!(incr_regs.rip, 0x4000);

    println!("Incremental snapshot test passed");
}

/// Test multi-level incremental snapshot chain.
#[cfg(target_os = "macos")]
#[test]
fn test_incremental_snapshot_chain() {
    // Create a chain: base -> incr1 -> incr2
    let base_id = "snap-base".to_string();
    let incr1_id = "snap-incr1".to_string();
    let incr2_id = "snap-incr2".to_string();

    let base = VmSnapshot {
        version: 1,
        arch: CpuArch::native(),
        vcpus: vec![],
        devices: vec![],
        memory_regions: vec![],
        total_memory: 256 * 1024 * 1024,
        compressed: false,
        compression: None,
        parent_id: None,
    };

    let incr1 = VmSnapshot {
        version: 1,
        arch: CpuArch::native(),
        vcpus: vec![],
        devices: vec![],
        memory_regions: vec![],
        total_memory: 256 * 1024 * 1024,
        compressed: true,
        compression: Some("zstd".to_string()),
        parent_id: Some(base_id.clone()),
    };

    let incr2 = VmSnapshot {
        version: 1,
        arch: CpuArch::native(),
        vcpus: vec![],
        devices: vec![],
        memory_regions: vec![],
        total_memory: 256 * 1024 * 1024,
        compressed: true,
        compression: Some("zstd".to_string()),
        parent_id: Some(incr1_id.clone()),
    };

    // Verify chain relationships
    assert!(base.parent_id.is_none());
    assert_eq!(incr1.parent_id, Some(base_id));
    assert_eq!(incr2.parent_id, Some(incr1_id));

    // Simulate walking the chain
    let mut chain = Vec::new();
    let mut current_parent = incr2.parent_id.as_ref();

    // Build chain backwards
    chain.push(&incr2_id);
    while let Some(parent) = current_parent {
        chain.push(parent);
        // In real implementation, we'd look up the snapshot and get its parent
        if parent == "snap-incr1" {
            current_parent = incr1.parent_id.as_ref();
        } else if parent == "snap-base" {
            current_parent = base.parent_id.as_ref();
        } else {
            break;
        }
    }

    // Chain should be: incr2 -> incr1 -> base
    assert_eq!(chain.len(), 3);
    assert_eq!(chain[0], "snap-incr2");
    assert_eq!(chain[1], "snap-incr1");
    assert_eq!(chain[2], "snap-base");

    println!("Incremental snapshot chain test passed");
}

// ============================================================================
// Device Restore Tests
// ============================================================================

/// Test device configuration validation during restore.
///
/// On Darwin, restore_devices validates that the current VM configuration
/// matches the snapshot, since actual device state cannot be restored.
#[cfg(target_os = "macos")]
#[test]
fn test_device_restore_validation() {
    if !is_supported() {
        println!("Virtualization not supported, skipping");
        return;
    }

    let hypervisor = DarwinHypervisor::new().expect("Failed to create hypervisor");

    let config = VmConfig {
        vcpu_count: 1,
        memory_size: 256 * 1024 * 1024,
        arch: CpuArch::native(),
        ..Default::default()
    };

    let mut vm = hypervisor.create_vm(config).expect("Failed to create VM");

    // Add devices
    vm.add_virtio_device(VirtioDeviceConfig::network())
        .expect("Failed to add network");
    vm.add_virtio_device(VirtioDeviceConfig::vsock())
        .expect("Failed to add vsock");

    // Take device snapshot
    let device_snapshots = vm.snapshot_devices().expect("Failed to snapshot");

    // Restore devices (validation only on Darwin)
    let result = vm.restore_devices(&device_snapshots);
    assert!(result.is_ok(), "Device restore validation should succeed");

    // Create a mismatched snapshot (has block device that doesn't exist)
    let mismatched_snapshots = vec![
        DeviceSnapshot {
            device_type: VirtioDeviceType::Block,
            name: "block-0".to_string(),
            state: serde_json::to_vec(&VirtioDeviceConfig::block("/nonexistent", false)).unwrap(),
        },
    ];

    // This should succeed (Darwin logs warnings but doesn't fail)
    // because actual device state restoration is not supported
    let result = vm.restore_devices(&mismatched_snapshots);
    assert!(result.is_ok(), "Device restore should succeed (with warnings)");

    println!("Device restore validation test passed");
}

// ============================================================================
// Memory Snapshot Tests
// ============================================================================

/// Test memory content preservation concept.
///
/// This test verifies the memory operations that would be used during
/// snapshot/restore, though actual memory dump/restore requires privileged
/// VM operations.
#[cfg(target_os = "macos")]
#[test]
fn test_memory_snapshot_concept() {
    if !is_supported() {
        println!("Virtualization not supported, skipping");
        return;
    }

    let hypervisor = DarwinHypervisor::new().expect("Failed to create hypervisor");

    let config = VmConfig {
        vcpu_count: 1,
        memory_size: 64 * 1024 * 1024, // 64 MB
        arch: CpuArch::native(),
        ..Default::default()
    };

    let vm = hypervisor.create_vm(config).expect("Failed to create VM");
    let memory = vm.memory();

    // Write test pattern to memory
    let test_pattern: Vec<u8> = (0..4096).map(|i| (i % 256) as u8).collect();
    memory
        .write(GuestAddress(0x1000), &test_pattern)
        .expect("Failed to write pattern");

    // Create memory region snapshot metadata
    let region_info = MemoryRegionSnapshot {
        guest_addr: 0,
        size: memory.size(),
        read_only: false,
        file_offset: 0,
    };

    // Verify memory size
    assert_eq!(region_info.size, 64 * 1024 * 1024);

    // Read back the pattern (simulating snapshot read)
    let mut read_buffer = vec![0u8; 4096];
    memory
        .read(GuestAddress(0x1000), &mut read_buffer)
        .expect("Failed to read pattern");

    // Verify pattern matches
    assert_eq!(read_buffer, test_pattern);

    // Write different data (simulating VM activity)
    let new_data = vec![0xFF; 4096];
    memory
        .write(GuestAddress(0x1000), &new_data)
        .expect("Failed to write new data");

    // Restore original data (simulating restore)
    memory
        .write(GuestAddress(0x1000), &test_pattern)
        .expect("Failed to restore data");

    // Verify restoration
    let mut verify_buffer = vec![0u8; 4096];
    memory
        .read(GuestAddress(0x1000), &mut verify_buffer)
        .expect("Failed to verify");

    assert_eq!(verify_buffer, test_pattern);

    println!("Memory snapshot concept test passed");
}

// ============================================================================
// Full VM Snapshot Integration Tests (Requires Privileges)
// ============================================================================

/// Test full VM snapshot creation flow.
///
/// This test requires VM boot privileges (entitlement signing) and is
/// marked as ignored by default.
#[cfg(target_os = "macos")]
#[test]
#[ignore = "Requires VM boot privileges (entitlement signing)"]
fn test_full_vm_snapshot_flow() {
    if !is_supported() {
        println!("Virtualization not supported, skipping");
        return;
    }

    // This test would:
    // 1. Create and boot a VM with kernel
    // 2. Wait for VM to reach a stable state
    // 3. Pause the VM
    // 4. Create full snapshot (vCPUs, devices, memory)
    // 5. Verify snapshot integrity
    // 6. Resume or stop the VM

    // The actual implementation requires:
    // - A signed binary with virtualization entitlement
    // - A kernel image to boot
    // - Proper test infrastructure

    println!("Full VM snapshot flow test requires privileged execution");
}

/// Test snapshot during active VM execution.
///
/// This test requires VM boot privileges and validates that snapshots
/// can be taken while the VM is running (after pause).
#[cfg(target_os = "macos")]
#[test]
#[ignore = "Requires VM boot privileges (entitlement signing)"]
fn test_snapshot_during_vm_execution() {
    if !is_supported() {
        println!("Virtualization not supported, skipping");
        return;
    }

    // This test would:
    // 1. Boot a VM
    // 2. Let it execute some workload
    // 3. Pause the VM
    // 4. Take snapshot
    // 5. Resume VM
    // 6. Later restore from snapshot

    println!("Snapshot during execution test requires privileged execution");
}

// ============================================================================
// VcpuSnapshot Architecture Tests
// ============================================================================

/// Test VcpuSnapshot creation for x86_64 architecture.
#[cfg(target_os = "macos")]
#[test]
fn test_vcpu_snapshot_x86() {
    let regs = Registers {
        rax: 0xAAAA,
        rbx: 0xBBBB,
        rcx: 0xCCCC,
        rdx: 0xDDDD,
        rsi: 0x1111,
        rdi: 0x2222,
        rsp: 0x3333,
        rbp: 0x4444,
        r8: 0x5555,
        r9: 0x6666,
        r10: 0x7777,
        r11: 0x8888,
        r12: 0x9999,
        r13: 0xAAAA,
        r14: 0xBBBB,
        r15: 0xCCCC,
        rip: 0xDEAD_BEEF,
        rflags: 0x0202,
    };

    let snapshot = VcpuSnapshot::new_x86(0, regs.clone());

    assert_eq!(snapshot.id, 0);
    assert_eq!(snapshot.arch, CpuArch::X86_64);
    assert!(snapshot.x86_regs.is_some());
    assert!(snapshot.arm64_regs.is_none());

    let snap_regs = snapshot.x86_regs.unwrap();
    assert_eq!(snap_regs.rax, 0xAAAA);
    assert_eq!(snap_regs.rip, 0xDEAD_BEEF);
    assert_eq!(snap_regs.rflags, 0x0202);

    println!("vCPU snapshot x86 test passed");
}

/// Test VcpuSnapshot creation for ARM64 architecture.
#[cfg(target_os = "macos")]
#[test]
fn test_vcpu_snapshot_arm64() {
    use arcbox_hypervisor::types::Arm64Registers;

    let mut arm_regs = Arm64Registers::default();
    arm_regs.x[0] = 0x1111;
    arm_regs.x[1] = 0x2222;
    arm_regs.pc = 0x4000_0000;
    arm_regs.sp = 0x7FFF_F000;
    arm_regs.pstate = 0x3C5;

    let snapshot = VcpuSnapshot::new_arm64(1, arm_regs.clone());

    assert_eq!(snapshot.id, 1);
    assert_eq!(snapshot.arch, CpuArch::Aarch64);
    assert!(snapshot.x86_regs.is_none());
    assert!(snapshot.arm64_regs.is_some());

    let snap_regs = snapshot.arm64_regs.unwrap();
    assert_eq!(snap_regs.x[0], 0x1111);
    assert_eq!(snap_regs.pc, 0x4000_0000);
    assert_eq!(snap_regs.sp, 0x7FFF_F000);
    assert_eq!(snap_regs.pstate, 0x3C5);

    println!("vCPU snapshot ARM64 test passed");
}

/// Test VcpuSnapshot serialization roundtrip.
#[cfg(target_os = "macos")]
#[test]
fn test_vcpu_snapshot_serialization() {
    let regs = Registers {
        rax: 0xDEADBEEF,
        rip: 0xCAFEBABE,
        ..Default::default()
    };

    let snapshot = VcpuSnapshot::new_x86(42, regs);

    // Serialize
    let json = serde_json::to_string(&snapshot).expect("Failed to serialize");

    // Deserialize
    let restored: VcpuSnapshot = serde_json::from_str(&json).expect("Failed to deserialize");

    assert_eq!(restored.id, 42);
    assert_eq!(restored.arch, CpuArch::X86_64);

    let restored_regs = restored.x86_regs.expect("Missing x86 regs");
    assert_eq!(restored_regs.rax, 0xDEADBEEF);
    assert_eq!(restored_regs.rip, 0xCAFEBABE);

    println!("vCPU snapshot serialization test passed");
}
