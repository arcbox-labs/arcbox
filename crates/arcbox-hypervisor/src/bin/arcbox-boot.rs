//! Boot a Linux VM using Virtualization.framework
//!
//! Usage:
//! 1. Build: cargo build --bin arcbox-boot -p arcbox-hypervisor
//! 2. Sign: codesign --entitlements tests/resources/entitlements.plist --force -s - target/debug/arcbox-boot
//! 3. Run: arcbox-boot <kernel_path> [initrd_path] [options]

use clap::Parser;
use std::path::PathBuf;
use std::time::Duration;

/// Boot a Linux VM using Virtualization.framework
#[derive(Parser, Debug)]
#[command(name = "arcbox-boot")]
#[command(about = "Boot a Linux VM using ArcBox hypervisor")]
#[command(version)]
struct Args {
    /// Path to the Linux kernel image
    #[arg(value_name = "KERNEL")]
    kernel: PathBuf,

    /// Path to the initrd/initramfs image
    #[arg(value_name = "INITRD")]
    initrd: Option<PathBuf>,

    /// Attach a block device
    #[arg(long, value_name = "PATH")]
    disk: Option<PathBuf>,

    /// Enable NAT networking
    #[arg(long)]
    net: bool,

    /// Enable vsock device
    #[arg(long)]
    vsock: bool,

    /// Enable VirtioFS sharing (path to share)
    #[arg(long, value_name = "PATH")]
    virtiofs: Option<PathBuf>,

    /// Custom kernel command line
    #[arg(long, value_name = "CMDLINE")]
    cmdline: Option<String>,

    /// Number of vCPUs
    #[arg(long, default_value = "2")]
    vcpus: u32,

    /// Memory size in MB
    #[arg(long, default_value = "512")]
    memory: u64,
}

fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    let args = Args::parse();

    println!("=== ArcBox VM Boot ===");
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
        println!(
            "  Max memory: {} GB",
            caps.max_memory / (1024 * 1024 * 1024)
        );
        println!("  Rosetta: {}", caps.rosetta);
        println!();

        // Create VM config
        let cmdline = args
            .cmdline
            .unwrap_or_else(|| "console=hvc0 loglevel=8 root=/dev/ram0 rdinit=/init".to_string());
        let memory_bytes = args.memory * 1024 * 1024;

        let config = VmConfig {
            vcpu_count: args.vcpus,
            memory_size: memory_bytes,
            arch: CpuArch::native(),
            kernel_path: Some(args.kernel.to_string_lossy().into_owned()),
            kernel_cmdline: Some(cmdline.clone()),
            initrd_path: args.initrd.map(|p| p.to_string_lossy().into_owned()),
            ..Default::default()
        };

        println!("VM Configuration:");
        println!("  Kernel: {}", args.kernel.display());
        if let Some(ref initrd) = config.initrd_path {
            println!("  Initrd: {}", initrd);
        }
        if let Some(ref disk) = args.disk {
            println!("  Disk: {}", disk.display());
        }
        println!(
            "  Network: {}",
            if args.net {
                "enabled (NAT)"
            } else {
                "disabled"
            }
        );
        println!(
            "  Vsock: {}",
            if args.vsock { "enabled" } else { "disabled" }
        );
        if let Some(ref fs_path) = args.virtiofs {
            println!("  VirtioFS: {} -> arcbox", fs_path.display());
        } else {
            println!("  VirtioFS: disabled");
        }
        println!("  vCPUs: {}", config.vcpu_count);
        println!("  Memory: {} MB", args.memory);
        println!("  Cmdline: {:?}", cmdline);
        println!();

        // Create VM
        println!("Creating VM...");
        let mut vm = hypervisor.create_vm(config).expect("Failed to create VM");
        println!("VM created: ID={}", vm.id());

        // Add block device if specified
        if let Some(ref disk) = args.disk {
            println!("Adding block device: {}", disk.display());
            let block_config = VirtioDeviceConfig::block(disk.to_string_lossy().into_owned(), false);
            match vm.add_virtio_device(block_config) {
                Ok(()) => println!("Block device added successfully"),
                Err(e) => eprintln!("Warning: Failed to add block device: {}", e),
            }
        }

        // Add network device if requested
        if args.net {
            println!("Adding network device (NAT)...");
            let net_config = VirtioDeviceConfig::network();
            match vm.add_virtio_device(net_config) {
                Ok(()) => println!("Network device added successfully"),
                Err(e) => eprintln!("Warning: Failed to add network device: {}", e),
            }
        }

        // Add vsock device if requested
        if args.vsock {
            println!("Adding vsock device...");
            let vsock_config = VirtioDeviceConfig::vsock();
            match vm.add_virtio_device(vsock_config) {
                Ok(()) => println!("Vsock device added successfully"),
                Err(e) => eprintln!("Warning: Failed to add vsock device: {}", e),
            }
        }

        // Add VirtioFS device if requested
        if let Some(ref fs_path) = args.virtiofs {
            println!("Adding VirtioFS device: {} -> arcbox", fs_path.display());
            let fs_config = VirtioDeviceConfig::filesystem(fs_path.to_string_lossy().into_owned(), "arcbox", false);
            match vm.add_virtio_device(fs_config) {
                Ok(()) => println!("VirtioFS device added successfully"),
                Err(e) => eprintln!("Warning: Failed to add VirtioFS device: {}", e),
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
                // Read more frequently at the start to catch early boot messages
                println!("Reading console output...");
                for i in 0..30 {
                    std::thread::sleep(Duration::from_millis(500));

                    // Read and print console output
                    match vm.read_console_output() {
                        Ok(output) => {
                            if !output.is_empty() {
                                print!("{}", output);
                            }
                        }
                        Err(e) => {
                            println!("[console read error: {}]", e);
                        }
                    }

                    if i % 2 == 1 {
                        println!(
                            "[{}s] VM state: {:?}, running: {}",
                            (i + 1) / 2,
                            vm.state(),
                            vm.is_running()
                        );
                    }
                }

                // Test vsock connection if enabled
                if args.vsock {
                    println!();
                    // Try multiple ports: 2222 (PUI PUI socat), 1024 (arcbox-agent)
                    for port in [2222u32, 1024] {
                        println!("Testing vsock connection to port {}...", port);
                        match vm.connect_vsock(port) {
                            Ok(fd) => {
                                println!("  Vsock port {} connected! fd={}", port, fd);
                                // Close the fd since we're just testing
                                unsafe {
                                    libc::close(fd);
                                }
                                break;
                            }
                            Err(e) => {
                                println!("  Vsock port {} failed: {}", port, e);
                            }
                        }
                    }
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
                eprintln!(
                    "  1. Binary not signed with com.apple.security.virtualization entitlement"
                );
                eprintln!("  2. Kernel format not compatible (needs uncompressed ARM64 Image)");
                eprintln!("  3. Insufficient memory or CPU count");
                std::process::exit(1);
            }
        }
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = args; // Suppress unused warning
        eprintln!("This binary only works on macOS");
        std::process::exit(1);
    }
}
