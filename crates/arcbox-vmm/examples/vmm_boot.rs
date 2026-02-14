//! Example: Boot a Linux VM using arcbox-vmm
//!
//! This demonstrates using the VMM layer on top of arcbox-hypervisor.
//!
//! Usage:
//! 1. Build: cargo build --example vmm_boot -p arcbox-vmm
//! 2. Sign: codesign --entitlements entitlements.plist --force -s - target/debug/examples/vmm_boot
//! 3. Run: ./target/debug/examples/vmm_boot

use std::path::PathBuf;
use std::time::Duration;

fn main() {
    println!("=== ArcBox VMM Boot Example ===");
    println!();

    // Check for kernel files
    let kernel_path = PathBuf::from("tests/resources/Image-arm64");
    let initrd_path = PathBuf::from("tests/resources/initramfs-arm64");

    if !kernel_path.exists() {
        eprintln!("Error: Kernel not found at {:?}", kernel_path);
        eprintln!("Please run from the arcbox root directory");
        std::process::exit(1);
    }

    if !initrd_path.exists() {
        eprintln!("Warning: Initrd not found at {:?}", initrd_path);
    }

    // Create VMM configuration
    let config = arcbox_vmm::VmmConfig {
        vcpu_count: 2,
        memory_size: 512 * 1024 * 1024, // 512MB
        kernel_path: kernel_path.clone(),
        kernel_cmdline: "console=hvc0 earlycon root=/dev/ram0 rdinit=/bin/sh".to_string(),
        initrd_path: if initrd_path.exists() {
            Some(initrd_path)
        } else {
            None
        },
        enable_rosetta: false,
        serial_console: true,
        virtio_console: true,
        shared_dirs: Vec::new(),
        networking: false,
        vsock: false,
        guest_cid: None,
        balloon: false,
    };

    println!("VMM Configuration:");
    println!("  Kernel: {:?}", config.kernel_path);
    println!("  Initrd: {:?}", config.initrd_path);
    println!("  vCPUs: {}", config.vcpu_count);
    println!("  Memory: {} MB", config.memory_size / (1024 * 1024));
    println!();

    // Create VMM
    println!("Creating VMM...");
    let mut vmm = match arcbox_vmm::Vmm::new(config) {
        Ok(vmm) => vmm,
        Err(e) => {
            eprintln!("Failed to create VMM: {}", e);
            std::process::exit(1);
        }
    };

    println!("VMM state: {:?}", vmm.state());

    // Start VMM
    println!("Starting VMM...");
    match vmm.start() {
        Ok(()) => {
            println!("VMM started successfully!");
            println!("VMM state: {:?}", vmm.state());
            println!();
            println!("VM is running. Press Ctrl+C to stop.");
            println!();

            // Run for a while
            for i in 0..15 {
                std::thread::sleep(Duration::from_secs(1));
                println!(
                    "[{}s] VMM state: {:?}, running: {}",
                    i + 1,
                    vmm.state(),
                    vmm.is_running()
                );
            }

            println!();
            println!("Stopping VMM...");
            match vmm.stop() {
                Ok(()) => println!("VMM stopped successfully"),
                Err(e) => println!("Error stopping VMM: {}", e),
            }
        }
        Err(e) => {
            eprintln!("Failed to start VMM: {}", e);
            eprintln!();
            eprintln!("Common issues:");
            eprintln!("  1. Binary not signed with com.apple.security.virtualization entitlement");
            eprintln!("  2. Kernel format not compatible (needs uncompressed ARM64 Image)");
            std::process::exit(1);
        }
    }

    println!();
    println!("Final VMM state: {:?}", vmm.state());
}
