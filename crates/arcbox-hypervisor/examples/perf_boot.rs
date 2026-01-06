//! Performance measurement: Boot time
//!
//! Measures VM creation and boot time for performance benchmarking.
//!
//! Usage:
//! 1. Build: cargo build --example perf_boot -p arcbox-hypervisor --release
//! 2. Sign: codesign --entitlements tests/resources/entitlements.plist -s - target/release/examples/perf_boot
//! 3. Run: ./target/release/examples/perf_boot tests/resources/Image-arm64 tests/resources/initramfs-arm64

use std::env;
use std::time::Instant;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <kernel_path> [initrd_path]", args[0]);
        std::process::exit(1);
    }

    let kernel_path = &args[1];
    let initrd_path = args.get(2).cloned();

    println!("=== ArcBox Boot Performance Test ===\n");

    #[cfg(target_os = "macos")]
    {
        use arcbox_hypervisor::{
            config::VmConfig,
            darwin::{is_supported, DarwinHypervisor},
            traits::{Hypervisor, VirtualMachine},
            types::CpuArch,
        };

        if !is_supported() {
            eprintln!("Virtualization not supported");
            std::process::exit(1);
        }

        // Measure hypervisor creation
        let t0 = Instant::now();
        let hypervisor = DarwinHypervisor::new().expect("Failed to create hypervisor");
        let hypervisor_time = t0.elapsed();

        // Measure VM configuration
        let t1 = Instant::now();
        let config = VmConfig {
            vcpu_count: 2,
            memory_size: 512 * 1024 * 1024,
            arch: CpuArch::native(),
            kernel_path: Some(kernel_path.clone()),
            kernel_cmdline: Some("console=hvc0 earlycon root=/dev/ram0 rdinit=/bin/sh".to_string()),
            initrd_path,
            ..Default::default()
        };
        let config_time = t1.elapsed();

        // Measure VM creation
        let t2 = Instant::now();
        let mut vm = hypervisor.create_vm(config).expect("Failed to create VM");
        let vm_create_time = t2.elapsed();

        // Measure console setup
        let t3 = Instant::now();
        let _ = vm.setup_serial_console();
        let console_time = t3.elapsed();

        // Measure VM start
        let t4 = Instant::now();
        vm.start().expect("Failed to start VM");
        let start_time = t4.elapsed();

        // Total time
        let total_time = t0.elapsed();

        println!("Performance Results:");
        println!("  Hypervisor init:  {:>8.2}ms", hypervisor_time.as_secs_f64() * 1000.0);
        println!("  Config creation:  {:>8.2}ms", config_time.as_secs_f64() * 1000.0);
        println!("  VM creation:      {:>8.2}ms", vm_create_time.as_secs_f64() * 1000.0);
        println!("  Console setup:    {:>8.2}ms", console_time.as_secs_f64() * 1000.0);
        println!("  VM start:         {:>8.2}ms", start_time.as_secs_f64() * 1000.0);
        println!("  ────────────────────────────");
        println!("  Total boot time:  {:>8.2}ms", total_time.as_secs_f64() * 1000.0);
        println!();

        // Target comparison
        println!("Target Comparison (vs OrbStack):");
        let boot_ms = total_time.as_secs_f64() * 1000.0;
        let target_ms = 1500.0; // 1.5s target
        if boot_ms <= target_ms {
            println!("  ✓ Boot time {:.0}ms <= {:.0}ms target", boot_ms, target_ms);
        } else {
            println!("  ✗ Boot time {:.0}ms > {:.0}ms target (need {:.0}ms improvement)",
                boot_ms, target_ms, boot_ms - target_ms);
        }

        let create_ms = vm_create_time.as_secs_f64() * 1000.0;
        let create_target = 500.0; // 500ms target
        if create_ms <= create_target {
            println!("  ✓ VM creation {:.0}ms <= {:.0}ms target", create_ms, create_target);
        } else {
            println!("  ✗ VM creation {:.0}ms > {:.0}ms target", create_ms, create_target);
        }

        println!();

        // Let VM run briefly then stop
        std::thread::sleep(std::time::Duration::from_secs(2));
        let _ = vm.stop();
        println!("VM stopped.");
    }

    #[cfg(not(target_os = "macos"))]
    {
        eprintln!("This test only works on macOS");
        std::process::exit(1);
    }
}
