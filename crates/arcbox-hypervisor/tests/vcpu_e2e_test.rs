//! End-to-end tests for Darwin vCPU managed execution.
//!
//! These tests verify the complete VM lifecycle with vCPU execution,
//! testing how vCPUs behave with real VM start/stop operations.
//!
//! Note: Some tests require a valid kernel to run. They will be skipped
//! if the kernel is not available.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(target_os = "macos")]
use std::path::PathBuf;

#[cfg(target_os = "macos")]
use arcbox_hypervisor::{
    config::VmConfig,
    darwin::{DarwinHypervisor, is_supported},
    traits::{Hypervisor, Vcpu, VirtualMachine},
    types::{CpuArch, VcpuExit},
};

/// Gets the path to test resources.
fn test_resources_dir() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests")
        .join("resources")
}

/// Checks if test kernel is available.
fn kernel_available() -> bool {
    let kernel_path = test_resources_dir().join("vmlinuz-arm64");
    kernel_path.exists()
}

/// Checks if initramfs is available.
fn initramfs_available() -> bool {
    let initrd_path = test_resources_dir().join("initramfs-arm64");
    initrd_path.exists()
}

// ============================================================================
// E2E Tests: vCPU with VM Lifecycle
// ============================================================================

/// Test vCPU behavior during VM creation and destruction.
#[cfg(target_os = "macos")]
#[test]
fn test_vcpu_lifecycle_without_kernel() {
    if !is_supported() {
        println!("Virtualization not supported, skipping");
        return;
    }

    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer()
        .try_init();

    let hypervisor = DarwinHypervisor::new().expect("Failed to create hypervisor");

    let config = VmConfig {
        vcpu_count: 2,
        memory_size: 256 * 1024 * 1024,
        arch: CpuArch::native(),
        ..Default::default()
    };

    let mut vm = hypervisor.create_vm(config).expect("Failed to create VM");

    println!("VM created: ID={}", vm.id());
    println!("VM state: {:?}", vm.state());

    // Create vCPUs
    let mut vcpu0 = vm.create_vcpu(0).expect("Failed to create vCPU 0");
    let mut vcpu1 = vm.create_vcpu(1).expect("Failed to create vCPU 1");

    println!("vCPUs created: 0 and 1");

    // Without kernel, VM cannot start, but vCPUs should handle this gracefully
    // run() should return Halt immediately since VZ VM is not fully configured
    let exit0 = vcpu0.run().expect("vCPU 0 run failed");
    let exit1 = vcpu1.run().expect("vCPU 1 run failed");

    assert!(matches!(exit0, VcpuExit::Halt));
    assert!(matches!(exit1, VcpuExit::Halt));

    println!("vCPUs correctly returned Halt without kernel");

    // VM cleanup
    drop(vm);
    println!("VM destroyed successfully");
}

/// Test vCPU in a background thread waiting for VM events.
#[cfg(target_os = "macos")]
#[test]
fn test_vcpu_background_thread_pattern() {
    if !is_supported() {
        println!("Virtualization not supported, skipping");
        return;
    }

    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer()
        .try_init();

    let hypervisor = DarwinHypervisor::new().expect("Failed to create hypervisor");

    let config = VmConfig {
        vcpu_count: 1,
        memory_size: 256 * 1024 * 1024,
        arch: CpuArch::native(),
        ..Default::default()
    };

    let mut vm = hypervisor.create_vm(config).expect("Failed to create VM");
    let vcpu = vm.create_vcpu(0).expect("Failed to create vCPU");

    // Get the running flag for monitoring (can be used to observe state from other threads)
    let _running_flag = vcpu.running_flag();

    // Track whether run() completed
    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = Arc::clone(&completed);

    // Spawn vCPU run in background thread
    let handle = thread::spawn(move || {
        let mut vcpu = vcpu;
        let start = Instant::now();

        let exit = vcpu.run().expect("vCPU run failed");

        let elapsed = start.elapsed();
        completed_clone.store(true, Ordering::SeqCst);

        (exit, elapsed)
    });

    // Without a real VZ VM (no kernel), run() returns immediately
    // Wait for completion with timeout
    let timeout = Duration::from_secs(5);
    let start = Instant::now();

    while !completed.load(Ordering::SeqCst) {
        if start.elapsed() > timeout {
            panic!("vCPU run() did not complete within timeout");
        }
        thread::sleep(Duration::from_millis(10));
    }

    let (exit, elapsed) = handle.join().expect("vCPU thread panicked");

    println!(
        "vCPU run() completed in {:?} with exit: {:?}",
        elapsed, exit
    );

    assert!(matches!(exit, VcpuExit::Halt));

    // Should have completed quickly (no real VM to wait for)
    assert!(
        elapsed < Duration::from_secs(1),
        "run() should complete quickly without VM, took {:?}",
        elapsed
    );

    println!("Background thread pattern test passed");
}

/// Test multiple vCPUs in background threads simulating real workload pattern.
#[cfg(target_os = "macos")]
#[test]
fn test_multiple_vcpus_workload_pattern() {
    if !is_supported() {
        println!("Virtualization not supported, skipping");
        return;
    }

    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer()
        .try_init();

    let hypervisor = DarwinHypervisor::new().expect("Failed to create hypervisor");
    let num_vcpus: u32 = 4;

    let config = VmConfig {
        vcpu_count: num_vcpus,
        memory_size: 512 * 1024 * 1024,
        arch: CpuArch::native(),
        ..Default::default()
    };

    let mut vm = hypervisor.create_vm(config).expect("Failed to create VM");

    println!("Created VM with {} vCPUs", num_vcpus);

    // Create all vCPUs
    let vcpus: Vec<_> = (0..num_vcpus as u32)
        .map(|i| {
            vm.create_vcpu(i)
                .expect(&format!("Failed to create vCPU {}", i))
        })
        .collect();

    // Spawn threads for each vCPU - simulating real VMM workload pattern
    let handles: Vec<_> = vcpus
        .into_iter()
        .enumerate()
        .map(|(i, vcpu)| {
            thread::Builder::new()
                .name(format!("vcpu-{}", i))
                .spawn(move || {
                    let mut vcpu = vcpu;
                    let id = vcpu.id();
                    let start = Instant::now();

                    println!("vCPU {} thread starting run()", id);

                    let exit = vcpu.run().expect(&format!("vCPU {} run failed", id));

                    let elapsed = start.elapsed();
                    println!("vCPU {} completed in {:?}: {:?}", id, elapsed, exit);

                    (id, exit, elapsed)
                })
                .expect("Failed to spawn thread")
        })
        .collect();

    // Wait for all vCPUs to complete
    let mut results: Vec<_> = handles
        .into_iter()
        .map(|h| h.join().expect("vCPU thread panicked"))
        .collect();

    results.sort_by_key(|(id, _, _)| *id);

    // Verify all completed with Halt
    for (id, exit, elapsed) in &results {
        assert!(
            matches!(exit, VcpuExit::Halt),
            "vCPU {} expected Halt, got {:?}",
            id,
            exit
        );
        assert!(
            *elapsed < Duration::from_secs(5),
            "vCPU {} took too long: {:?}",
            id,
            elapsed
        );
    }

    println!("All {} vCPUs completed successfully", num_vcpus);
}

/// Test vCPU behavior with VM state checking.
#[cfg(target_os = "macos")]
#[test]
fn test_vcpu_vm_state_awareness() {
    if !is_supported() {
        println!("Virtualization not supported, skipping");
        return;
    }

    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer()
        .try_init();

    let hypervisor = DarwinHypervisor::new().expect("Failed to create hypervisor");

    let config = VmConfig {
        vcpu_count: 1,
        memory_size: 256 * 1024 * 1024,
        arch: CpuArch::native(),
        ..Default::default()
    };

    let mut vm = hypervisor.create_vm(config).expect("Failed to create VM");

    // Check initial VM state
    let initial_state = vm.state();
    println!("Initial VM state: {:?}", initial_state);

    let mut vcpu = vm.create_vcpu(0).expect("Failed to create vCPU");

    // VM state should still be Created (not started)
    assert!(!vm.is_running(), "VM should not be running before start()");

    // vCPU run should return immediately
    let exit = vcpu.run().expect("vCPU run failed");
    assert!(matches!(exit, VcpuExit::Halt));

    println!("vCPU correctly handles non-running VM state");
}

// ============================================================================
// E2E Tests: With Kernel (requires kernel file)
// ============================================================================

/// Test vCPU execution with a real kernel.
///
/// This test requires:
/// - tests/resources/vmlinuz-arm64
/// - tests/resources/initramfs-arm64 (optional)
#[cfg(target_os = "macos")]
#[test]
#[ignore = "Requires kernel and entitlement"]
fn test_vcpu_with_running_vm() {
    if !is_supported() {
        println!("Virtualization not supported, skipping");
        return;
    }

    if !kernel_available() {
        println!("Kernel not available, skipping");
        return;
    }

    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer()
        .try_init();

    let kernel_path = test_resources_dir().join("vmlinuz-arm64");
    let initrd_path = test_resources_dir().join("initramfs-arm64");

    println!("Using kernel: {:?}", kernel_path);

    let hypervisor = DarwinHypervisor::new().expect("Failed to create hypervisor");

    let mut config = VmConfig {
        vcpu_count: 2,
        memory_size: 512 * 1024 * 1024,
        arch: CpuArch::native(),
        kernel_path: Some(kernel_path.to_string_lossy().to_string()),
        kernel_cmdline: Some(
            "console=hvc0 earlycon=pl011,0x09000000 root=/dev/ram0 rdinit=/bin/sh".to_string(),
        ),
        ..Default::default()
    };

    if initramfs_available() {
        config.initrd_path = Some(initrd_path.to_string_lossy().to_string());
    }

    let mut vm = hypervisor.create_vm(config).expect("Failed to create VM");

    println!("VM created with kernel");

    // Create vCPU
    let vcpu = vm.create_vcpu(0).expect("Failed to create vCPU");
    let _running_flag = vcpu.running_flag();

    // Spawn vCPU in background thread
    let vcpu_completed = Arc::new(AtomicBool::new(false));
    let vcpu_completed_clone = Arc::clone(&vcpu_completed);

    let vcpu_handle = thread::spawn(move || {
        let mut vcpu = vcpu;
        println!("vCPU thread: starting run()");

        let exit = vcpu.run();

        vcpu_completed_clone.store(true, Ordering::SeqCst);
        println!("vCPU thread: run() returned: {:?}", exit);

        exit
    });

    // Start VM
    println!("Starting VM...");
    match vm.start() {
        Ok(()) => {
            println!("VM started successfully");

            // Let it run for a while
            thread::sleep(Duration::from_secs(3));

            println!("Stopping VM...");
            let _ = vm.stop();

            // Wait for vCPU thread to exit
            let timeout = Duration::from_secs(10);
            let start = Instant::now();

            while !vcpu_completed.load(Ordering::SeqCst) {
                if start.elapsed() > timeout {
                    println!("Warning: vCPU did not complete within timeout");
                    break;
                }
                thread::sleep(Duration::from_millis(100));
            }

            if let Ok(exit) = vcpu_handle.join().expect("vCPU thread panicked") {
                println!("vCPU exit: {:?}", exit);
                // Should be Shutdown or Halt after stop
                assert!(
                    matches!(exit, VcpuExit::Shutdown | VcpuExit::Halt),
                    "Expected Shutdown or Halt after stop, got {:?}",
                    exit
                );
            }
        }
        Err(e) => {
            println!("Failed to start VM (expected without entitlement): {}", e);
            // vCPU thread should complete quickly
            let _ = vcpu_handle.join();
        }
    }

    println!("vCPU with running VM test completed");
}

/// Test vCPU state transitions during VM pause/resume.
#[cfg(target_os = "macos")]
#[test]
#[ignore = "Requires kernel and entitlement"]
fn test_vcpu_pause_resume() {
    if !is_supported() || !kernel_available() {
        println!("Prerequisites not met, skipping");
        return;
    }

    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer()
        .try_init();

    let kernel_path = test_resources_dir().join("vmlinuz-arm64");

    let hypervisor = DarwinHypervisor::new().expect("Failed to create hypervisor");

    let config = VmConfig {
        vcpu_count: 1,
        memory_size: 256 * 1024 * 1024,
        arch: CpuArch::native(),
        kernel_path: Some(kernel_path.to_string_lossy().to_string()),
        kernel_cmdline: Some("console=hvc0".to_string()),
        ..Default::default()
    };

    let mut vm = hypervisor.create_vm(config).expect("Failed to create VM");
    let vcpu = vm.create_vcpu(0).expect("Failed to create vCPU");

    let vcpu_exit = Arc::new(std::sync::Mutex::new(None));
    let vcpu_exit_clone = Arc::clone(&vcpu_exit);

    let vcpu_handle = thread::spawn(move || {
        let mut vcpu = vcpu;
        let exit = vcpu.run();
        *vcpu_exit_clone.lock().unwrap() = Some(exit);
    });

    match vm.start() {
        Ok(()) => {
            // Let it run
            thread::sleep(Duration::from_secs(1));

            // Pause
            println!("Pausing VM...");
            if let Err(e) = vm.pause() {
                println!("Pause failed: {}", e);
            } else {
                thread::sleep(Duration::from_millis(500));

                // vCPU should have received Halt exit from pause
                // (Note: This depends on timing, might still be in run loop)

                // Resume
                println!("Resuming VM...");
                if let Err(e) = vm.resume() {
                    println!("Resume failed: {}", e);
                }

                thread::sleep(Duration::from_secs(1));
            }

            // Stop
            let _ = vm.stop();
        }
        Err(e) => {
            println!("Start failed (expected without entitlement): {}", e);
        }
    }

    let _ = vcpu_handle.join();

    if let Some(exit) = vcpu_exit.lock().unwrap().take() {
        println!("Final vCPU exit: {:?}", exit);
    }

    println!("Pause/resume test completed");
}

// ============================================================================
// Stress Tests
// ============================================================================

/// Stress test: Create and destroy many VMs with vCPUs.
#[cfg(target_os = "macos")]
#[test]
fn test_vcpu_stress_create_destroy() {
    if !is_supported() {
        println!("Virtualization not supported, skipping");
        return;
    }

    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();

    let hypervisor = DarwinHypervisor::new().expect("Failed to create hypervisor");
    let iterations = 10;

    println!(
        "Running {} iterations of VM/vCPU create/destroy",
        iterations
    );

    for i in 0..iterations {
        let config = VmConfig {
            vcpu_count: 4,
            memory_size: 256 * 1024 * 1024,
            arch: CpuArch::native(),
            ..Default::default()
        };

        let mut vm = hypervisor
            .create_vm(config)
            .expect(&format!("Failed to create VM in iteration {}", i));

        // Create vCPUs
        let vcpus: Vec<_> = (0..4)
            .map(|j| {
                vm.create_vcpu(j)
                    .expect(&format!("Failed to create vCPU {} in iteration {}", j, i))
            })
            .collect();

        // Run each briefly
        for mut vcpu in vcpus {
            let _ = vcpu.run();
        }

        // VM dropped here
        if (i + 1) % 5 == 0 {
            println!("Completed {} iterations", i + 1);
        }
    }

    println!(
        "Stress test completed: {} iterations successful",
        iterations
    );
}

/// Stress test: Rapid vCPU run() calls.
#[cfg(target_os = "macos")]
#[test]
fn test_vcpu_stress_rapid_run() {
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

    let iterations = 100;

    println!("Running {} rapid run() calls", iterations);

    let start = Instant::now();

    for _ in 0..iterations {
        let exit = vcpu.run().expect("run() failed");
        assert!(matches!(exit, VcpuExit::Halt));
    }

    let elapsed = start.elapsed();
    let per_call = elapsed / iterations;

    println!(
        "Completed {} run() calls in {:?} ({:?} per call)",
        iterations, elapsed, per_call
    );

    // Should be very fast (no actual VM running)
    assert!(
        per_call < Duration::from_millis(10),
        "run() too slow: {:?} per call",
        per_call
    );
}
