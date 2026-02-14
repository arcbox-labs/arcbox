//! Integration tests for Darwin vCPU implementation.
//!
//! These tests verify the interaction between DarwinVm and DarwinVcpu,
//! testing the managed execution model of Virtualization.framework.

#![allow(clippy::expect_fun_call)]
#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::unnecessary_cast)]

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::thread;

#[cfg(target_os = "macos")]
use arcbox_hypervisor::{
    config::VmConfig,
    darwin::{DarwinHypervisor, is_supported},
    traits::{Hypervisor, Vcpu, VirtualMachine},
    types::{CpuArch, VcpuExit},
};

// ============================================================================
// VM-vCPU Integration Tests
// ============================================================================

/// Test that vCPUs can be created from a VM.
#[cfg(target_os = "macos")]
#[test]
fn test_vcpu_creation_from_vm() {
    if !is_supported() {
        println!("Virtualization not supported, skipping");
        return;
    }

    let hypervisor = DarwinHypervisor::new().expect("Failed to create hypervisor");

    let config = VmConfig {
        vcpu_count: 4,
        memory_size: 256 * 1024 * 1024,
        arch: CpuArch::native(),
        ..Default::default()
    };

    let mut vm = hypervisor.create_vm(config).expect("Failed to create VM");

    // Create multiple vCPUs
    for i in 0..4 {
        let vcpu = vm
            .create_vcpu(i)
            .expect(&format!("Failed to create vCPU {}", i));
        assert_eq!(vcpu.id(), i);
    }

    println!("Successfully created 4 vCPUs");
}

/// Test that duplicate vCPU creation fails.
#[cfg(target_os = "macos")]
#[test]
fn test_vcpu_duplicate_creation_fails() {
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

    // First creation should succeed
    let _vcpu0 = vm.create_vcpu(0).expect("Failed to create first vCPU 0");

    // Second creation with same ID should fail
    let result = vm.create_vcpu(0);
    assert!(result.is_err(), "Duplicate vCPU creation should fail");

    println!("Duplicate vCPU creation correctly rejected");
}

/// Test that vCPU creation with invalid ID fails.
#[cfg(target_os = "macos")]
#[test]
fn test_vcpu_invalid_id_fails() {
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

    // ID exceeding vcpu_count should fail
    let result = vm.create_vcpu(2);
    assert!(result.is_err(), "vCPU ID 2 should fail for vcpu_count=2");

    let result = vm.create_vcpu(99);
    assert!(result.is_err(), "vCPU ID 99 should fail for vcpu_count=2");

    println!("Invalid vCPU ID correctly rejected");
}

/// Test that vCPU run() returns Halt when VM is not started.
#[cfg(target_os = "macos")]
#[test]
fn test_vcpu_run_before_vm_start() {
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

    // Create vCPU before VM is started (no VZ VM created yet)
    let mut vcpu = vm.create_vcpu(0).expect("Failed to create vCPU");

    // run() should return Halt immediately since VM is not started
    // (vz_vm pointer is null before finalize_configuration)
    let exit = vcpu.run().expect("run() should succeed");
    assert!(
        matches!(exit, VcpuExit::Halt),
        "Expected Halt exit before VM start, got {:?}",
        exit
    );

    println!("vCPU run() correctly returns Halt before VM start");
}

/// Test that is_managed_execution returns true for Darwin VM.
#[cfg(target_os = "macos")]
#[test]
fn test_vm_is_managed_execution() {
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

    let vm = hypervisor.create_vm(config).expect("Failed to create VM");

    // Darwin VM should use managed execution
    assert!(
        vm.is_managed_execution(),
        "Darwin VM should report managed execution"
    );

    println!("Darwin VM correctly reports managed execution");
}

/// Test vCPU register operations through the VM interface.
#[cfg(target_os = "macos")]
#[test]
fn test_vcpu_registers_through_vm() {
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

    // Create two vCPUs and test independent register state
    let mut vcpu0 = vm.create_vcpu(0).expect("Failed to create vCPU 0");
    let mut vcpu1 = vm.create_vcpu(1).expect("Failed to create vCPU 1");

    // Set different registers for each vCPU
    let mut regs0 = arcbox_hypervisor::types::Registers::default();
    regs0.rax = 0x1111;
    regs0.rip = 0x2222;

    let mut regs1 = arcbox_hypervisor::types::Registers::default();
    regs1.rax = 0x3333;
    regs1.rip = 0x4444;

    vcpu0.set_regs(&regs0).expect("Failed to set vCPU 0 regs");
    vcpu1.set_regs(&regs1).expect("Failed to set vCPU 1 regs");

    // Verify registers are independent
    let read0 = vcpu0.get_regs().expect("Failed to get vCPU 0 regs");
    let read1 = vcpu1.get_regs().expect("Failed to get vCPU 1 regs");

    assert_eq!(read0.rax, 0x1111);
    assert_eq!(read0.rip, 0x2222);
    assert_eq!(read1.rax, 0x3333);
    assert_eq!(read1.rip, 0x4444);

    println!("vCPU registers are correctly independent");
}

/// Test multiple vCPU run() calls don't interfere with each other.
#[cfg(target_os = "macos")]
#[test]
fn test_multiple_vcpu_run_independent() {
    if !is_supported() {
        println!("Virtualization not supported, skipping");
        return;
    }

    let hypervisor = DarwinHypervisor::new().expect("Failed to create hypervisor");

    let config = VmConfig {
        vcpu_count: 4,
        memory_size: 256 * 1024 * 1024,
        arch: CpuArch::native(),
        ..Default::default()
    };

    let mut vm = hypervisor.create_vm(config).expect("Failed to create VM");

    // Create all vCPUs
    let mut vcpus: Vec<_> = (0..4)
        .map(|i| {
            vm.create_vcpu(i)
                .expect(&format!("Failed to create vCPU {}", i))
        })
        .collect();

    // Call run() on each vCPU - should all return Halt immediately
    for (i, vcpu) in vcpus.iter_mut().enumerate() {
        let exit = vcpu.run().expect(&format!("vCPU {} run() failed", i));
        assert!(
            matches!(exit, VcpuExit::Halt),
            "vCPU {} expected Halt, got {:?}",
            i,
            exit
        );
    }

    println!("Multiple vCPU run() calls are independent");
}

// ============================================================================
// vCPU Threading Tests
// ============================================================================

/// Test that vCPU can be moved to another thread.
#[cfg(target_os = "macos")]
#[test]
fn test_vcpu_send_to_thread() {
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

    // Move vCPU to another thread and run it
    let handle = thread::spawn(move || {
        let exit = vcpu.run().expect("run() failed in thread");
        assert!(matches!(exit, VcpuExit::Halt));
        vcpu.id()
    });

    let id = handle.join().expect("Thread panicked");
    assert_eq!(id, 0);

    println!("vCPU successfully moved to and executed in another thread");
}

/// Test running multiple vCPUs in parallel threads.
#[cfg(target_os = "macos")]
#[test]
fn test_multiple_vcpus_parallel_threads() {
    if !is_supported() {
        println!("Virtualization not supported, skipping");
        return;
    }

    let hypervisor = DarwinHypervisor::new().expect("Failed to create hypervisor");

    let config = VmConfig {
        vcpu_count: 4,
        memory_size: 256 * 1024 * 1024,
        arch: CpuArch::native(),
        ..Default::default()
    };

    let mut vm = hypervisor.create_vm(config).expect("Failed to create VM");

    // Create vCPUs
    let vcpus: Vec<_> = (0..4)
        .map(|i| {
            vm.create_vcpu(i)
                .expect(&format!("Failed to create vCPU {}", i))
        })
        .collect();

    // Run each vCPU in its own thread
    let handles: Vec<_> = vcpus
        .into_iter()
        .map(|mut vcpu| {
            thread::spawn(move || {
                let id = vcpu.id();
                let exit = vcpu.run().expect(&format!("vCPU {} run() failed", id));
                (id, exit)
            })
        })
        .collect();

    // Collect results
    let mut results: Vec<_> = handles
        .into_iter()
        .map(|h| h.join().expect("Thread panicked"))
        .collect();

    results.sort_by_key(|(id, _)| *id);

    for (id, exit) in &results {
        assert!(
            matches!(exit, VcpuExit::Halt),
            "vCPU {} expected Halt, got {:?}",
            id,
            exit
        );
    }

    println!("4 vCPUs successfully ran in parallel threads");
}

/// Test vCPU running flag is visible from other threads.
#[cfg(target_os = "macos")]
#[test]
fn test_vcpu_running_flag_cross_thread() {
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
    let vcpu = vm.create_vcpu(0).expect("Failed to create vCPU");

    // Get the running flag before moving vCPU
    let running_flag = vcpu.running_flag();

    // Initially not running
    assert!(!running_flag.load(Ordering::SeqCst));

    // Note: With null VZ VM pointer, run() returns immediately so we can't
    // test the running=true state from another thread. This test verifies
    // that the flag is accessible across threads.

    let flag_clone = Arc::clone(&running_flag);
    let handle = thread::spawn(move || {
        // Check flag from another thread
        assert!(!flag_clone.load(Ordering::SeqCst));
    });

    handle.join().expect("Thread panicked");

    println!("vCPU running flag is correctly shared across threads");
}

// ============================================================================
// I/O and MMIO Tests (No-op on Darwin)
// ============================================================================

/// Test that I/O result setting is a no-op but doesn't error.
#[cfg(target_os = "macos")]
#[test]
fn test_vcpu_io_result_noop_integration() {
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

    // These should all succeed (no-op on Darwin)
    vcpu.set_io_result(0x00).expect("set_io_result failed");
    vcpu.set_io_result(0xFF).expect("set_io_result failed");
    vcpu.set_io_result(0xFFFF_FFFF_FFFF_FFFF)
        .expect("set_io_result failed");

    vcpu.set_mmio_result(0x00).expect("set_mmio_result failed");
    vcpu.set_mmio_result(0xFF).expect("set_mmio_result failed");
    vcpu.set_mmio_result(0xFFFF_FFFF_FFFF_FFFF)
        .expect("set_mmio_result failed");

    println!("I/O and MMIO result setting correctly succeeds (no-op on Darwin)");
}

// ============================================================================
// Memory Access Tests
// ============================================================================

/// Test that vCPU can access VM memory through the memory() method.
#[cfg(target_os = "macos")]
#[test]
fn test_vcpu_memory_access() {
    use arcbox_hypervisor::memory::GuestAddress;
    use arcbox_hypervisor::traits::GuestMemory;

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

    // Access memory through VM
    let memory = vm.memory();

    // Write some data
    let test_data = [0xDE, 0xAD, 0xBE, 0xEF];
    memory
        .write(GuestAddress(0x1000), &test_data)
        .expect("Memory write failed");

    // Read it back
    let mut read_buf = [0u8; 4];
    memory
        .read(GuestAddress(0x1000), &mut read_buf)
        .expect("Memory read failed");

    assert_eq!(read_buf, test_data);

    // Create vCPU after memory setup
    let _vcpu = vm.create_vcpu(0).expect("Failed to create vCPU");

    // Memory should still be accessible
    let mut verify_buf = [0u8; 4];
    vm.memory()
        .read(GuestAddress(0x1000), &mut verify_buf)
        .expect("Memory read after vCPU creation failed");

    assert_eq!(verify_buf, test_data);

    println!("VM memory access works correctly with vCPU");
}
