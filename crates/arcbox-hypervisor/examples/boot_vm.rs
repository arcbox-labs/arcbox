//! Example: Boot a Linux VM using Virtualization.framework
//!
//! Usage:
//! 1. Build: cargo build --example boot_vm -p arcbox-hypervisor
//! 2. Sign: codesign --entitlements tests/resources/entitlements.plist --force -s - target/debug/examples/boot_vm
//! 3. Run: ./target/debug/examples/boot_vm <kernel_path> [initrd_path] [options]
//!
//! Options:
//!   --disk <path>    Attach a block device
//!   --net            Enable NAT networking
//!   --vsock          Enable vsock device

use std::env;
use std::time::Duration;

fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <kernel_path> [initrd_path] [options]", args[0]);
        eprintln!();
        eprintln!("Options:");
        eprintln!("  --disk <path>    Attach a block device");
        eprintln!("  --net            Enable NAT networking");
        eprintln!("  --vsock          Enable vsock device");
        eprintln!();
        eprintln!("Example:");
        eprintln!("  {} tests/resources/Image-arm64 tests/resources/initramfs-arm64", args[0]);
        eprintln!("  {} tests/resources/Image-arm64 tests/resources/initramfs-arm64 --disk test.img --net", args[0]);
        std::process::exit(1);
    }

    let kernel_path = &args[1];

    // Parse optional arguments
    let mut initrd_path = None;
    let mut disk_path = None;
    let mut enable_net = false;
    let mut enable_vsock = false;
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--disk" if i + 1 < args.len() => {
                disk_path = Some(args[i + 1].clone());
                i += 2;
            }
            "--net" => {
                enable_net = true;
                i += 1;
            }
            "--vsock" => {
                enable_vsock = true;
                i += 1;
            }
            _ if initrd_path.is_none() && !args[i].starts_with("--") => {
                initrd_path = Some(args[i].clone());
                i += 1;
            }
            _ => {
                i += 1;
            }
        }
    }

    println!("=== ArcBox VM Boot Example ===");
    println!();

    #[cfg(target_os = "macos")]
    {
        use arcbox_hypervisor::{
            config::VmConfig,
            darwin::{is_supported, DarwinHypervisor},
            traits::{Hypervisor, VirtualMachine},
            types::{CpuArch, VirtioDeviceConfig},
        };

        // Check support
        if !is_supported() {
            eprintln!("Error: Virtualization.framework not supported on this system");
            std::process::exit(1);
        }

        // Create hypervisor
        let hypervisor = DarwinHypervisor::new().expect("Failed to create hypervisor");
        let caps = hypervisor.capabilities();

        println!("Hypervisor capabilities:");
        println!("  Max vCPUs: {}", caps.max_vcpus);
        println!("  Max memory: {} GB", caps.max_memory / (1024 * 1024 * 1024));
        println!("  Rosetta: {}", caps.rosetta);
        println!();

        // Create VM config
        let config = VmConfig {
            vcpu_count: 2,
            memory_size: 512 * 1024 * 1024, // 512MB
            arch: CpuArch::native(),
            kernel_path: Some(kernel_path.clone()),
            kernel_cmdline: Some("console=hvc0 earlycon root=/dev/ram0 rdinit=/bin/sh".to_string()),
            initrd_path,
            ..Default::default()
        };

        println!("VM Configuration:");
        println!("  Kernel: {}", kernel_path);
        if let Some(ref initrd) = config.initrd_path {
            println!("  Initrd: {}", initrd);
        }
        if let Some(ref disk) = disk_path {
            println!("  Disk: {}", disk);
        }
        println!("  Network: {}", if enable_net { "enabled (NAT)" } else { "disabled" });
        println!("  Vsock: {}", if enable_vsock { "enabled" } else { "disabled" });
        println!("  vCPUs: {}", config.vcpu_count);
        println!("  Memory: {} MB", config.memory_size / (1024 * 1024));
        println!("  Cmdline: {:?}", config.kernel_cmdline);
        println!();

        // Create VM
        println!("Creating VM...");
        let mut vm = hypervisor.create_vm(config).expect("Failed to create VM");
        println!("VM created: ID={}", vm.id());

        // Add block device if specified
        if let Some(ref disk) = disk_path {
            println!("Adding block device: {}", disk);
            let block_config = VirtioDeviceConfig::block(disk, false);
            match vm.add_virtio_device(block_config) {
                Ok(()) => println!("Block device added successfully"),
                Err(e) => eprintln!("Warning: Failed to add block device: {}", e),
            }
        }

        // Add network device if requested
        if enable_net {
            println!("Adding network device (NAT)...");
            let net_config = VirtioDeviceConfig::network();
            match vm.add_virtio_device(net_config) {
                Ok(()) => println!("Network device added successfully"),
                Err(e) => eprintln!("Warning: Failed to add network device: {}", e),
            }
        }

        // Add vsock device if requested
        if enable_vsock {
            println!("Adding vsock device...");
            let vsock_config = VirtioDeviceConfig::vsock();
            match vm.add_virtio_device(vsock_config) {
                Ok(()) => println!("Vsock device added successfully"),
                Err(e) => eprintln!("Warning: Failed to add vsock device: {}", e),
            }
        }

        // Set up serial console for kernel output
        println!("Setting up serial console...");
        match vm.setup_serial_console() {
            Ok(slave_path) => println!("Serial console available at: {}", slave_path),
            Err(e) => eprintln!("Warning: Failed to setup serial console: {}", e),
        }

        // Note: VZVirtualMachine requires operations to be performed on a dispatch queue
        // with a running CFRunLoop. For CLI applications, this requires special handling.
        // The current implementation demonstrates VM configuration but actual VM execution
        // requires integration with CFRunLoop (e.g., using Cocoa/AppKit run loop).
        //
        // For a full working example, the application would need to:
        // 1. Run on the main thread with CFRunLoopRun()
        // 2. Dispatch VM operations to the main queue
        //
        // Attempting to start VM (may require run loop)...
        println!("Starting VM (requires CFRunLoop for completion handlers)...");
        match vm.start() {
            Ok(()) => {
                println!("VM started successfully!");
                println!();
                println!("VM is running. Press Ctrl+C to stop.");
                println!();

                // Run for a while, reading console output
                for i in 0..30 {
                    std::thread::sleep(Duration::from_secs(1));

                    // Read and print console output
                    match vm.read_console_output() {
                        Ok(output) if !output.is_empty() => {
                            print!("{}", output);
                        }
                        _ => {}
                    }

                    println!("[{}s] VM state: {:?}, running: {}", i + 1, vm.state(), vm.is_running());
                }

                println!();
                println!("Stopping VM...");
                match vm.stop() {
                    Ok(()) => println!("VM stopped successfully"),
                    Err(e) => println!("Error stopping VM: {}", e),
                }
            }
            Err(e) => {
                eprintln!("Failed to start VM: {}", e);
                eprintln!();
                eprintln!("Common issues:");
                eprintln!("  1. Binary not signed with com.apple.security.virtualization entitlement");
                eprintln!("  2. Kernel format not compatible (needs uncompressed ARM64 Image)");
                eprintln!("  3. Insufficient memory or CPU count");
                std::process::exit(1);
            }
        }
    }

    #[cfg(not(target_os = "macos"))]
    {
        eprintln!("This example only works on macOS");
        std::process::exit(1);
    }
}
