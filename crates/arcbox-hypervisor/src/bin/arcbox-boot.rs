//! Boot a Linux VM using Virtualization.framework
//!
//! Usage:
//! 1. Build: cargo build --bin arcbox-boot -p arcbox-hypervisor
//! 2. Sign: codesign --entitlements tests/resources/entitlements.plist --force -s - target/debug/arcbox-boot
//! 3. Run: arcbox-boot <kernel_path> [initrd_path] [options]

use clap::Parser;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
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

    /// Interactive mode - attach to serial console
    #[arg(short, long)]
    interactive: bool,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    // Initialize tracing (only if not interactive)
    if !args.interactive {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .init();
    }

    println!("=== ArcBox VM Boot ===");
    println!();

    #[cfg(target_os = "macos")]
    run_macos(args);

    #[cfg(not(target_os = "macos"))]
    {
        let _ = args;
        eprintln!("This binary only works on macOS");
        std::process::exit(1);
    }
}

#[cfg(target_os = "macos")]
fn run_macos(args: Args) {
    use arcbox_hypervisor::{
        config::VmConfig,
        darwin::{is_supported, DarwinHypervisor, DarwinVm},
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
        .clone()
        .unwrap_or_else(|| "console=hvc0 loglevel=8 root=/dev/ram0 rdinit=/init".to_string());
    let memory_bytes = args.memory * 1024 * 1024;

    let config = VmConfig {
        vcpu_count: args.vcpus,
        memory_size: memory_bytes,
        arch: CpuArch::native(),
        kernel_path: Some(args.kernel.to_string_lossy().into_owned()),
        kernel_cmdline: Some(cmdline.clone()),
        initrd_path: args.initrd.as_ref().map(|p| p.to_string_lossy().into_owned()),
        ..Default::default()
    };

    println!("VM Configuration:");
    println!("  Kernel: {}", args.kernel.display());
    if let Some(ref initrd) = args.initrd {
        println!("  Initrd: {}", initrd.display());
    }
    if let Some(ref disk) = args.disk {
        println!("  Disk: {}", disk.display());
    }
    println!(
        "  Network: {}",
        if args.net { "enabled (NAT)" } else { "disabled" }
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
    println!("  Interactive: {}", args.interactive);
    println!();

    // Create VM
    println!("Creating VM...");
    let mut vm: DarwinVm = hypervisor.create_vm(config).expect("Failed to create VM");
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
        let fs_config = VirtioDeviceConfig::filesystem(
            fs_path.to_string_lossy().into_owned(),
            "arcbox",
            false,
        );
        match vm.add_virtio_device(fs_config) {
            Ok(()) => println!("VirtioFS device added successfully"),
            Err(e) => eprintln!("Warning: Failed to add VirtioFS device: {}", e),
        }
    }

    // Set up serial console
    println!("Setting up serial console...");
    match vm.setup_serial_console() {
        Ok(slave_path) => println!("Serial console available at: {}", slave_path),
        Err(e) => eprintln!("Warning: Failed to setup serial console: {}", e),
    }

    println!("Starting VM...");
    match vm.start() {
        Ok(()) => {
            println!("VM started successfully!");
            println!();

            if args.interactive {
                run_interactive_console(&mut vm);
            } else {
                run_demo_mode(&mut vm, args.vsock);
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

#[cfg(target_os = "macos")]
fn run_interactive_console(vm: &mut arcbox_hypervisor::darwin::DarwinVm) {
    use arcbox_hypervisor::traits::VirtualMachine;
    use std::io::{Read, Write};

    println!("Entering interactive console mode...");
    println!("Press Ctrl+A then X to exit.");
    println!();

    // Set up terminal raw mode
    let original_termios = setup_raw_mode();

    // Flag for clean shutdown
    let running = Arc::new(AtomicBool::new(true));
    let running_clone = running.clone();

    // Handle Ctrl+C
    ctrlc::set_handler(move || {
        running_clone.store(false, Ordering::SeqCst);
    })
    .expect("Failed to set Ctrl+C handler");

    let mut ctrl_a_pressed = false;
    let mut stdin = std::io::stdin();
    let mut input_buf = [0u8; 64];

    while running.load(Ordering::SeqCst) && vm.is_running() {
        // Check for console output (non-blocking)
        if let Ok(output) = vm.read_console_output() {
            if !output.is_empty() {
                print!("{}", output);
                let _ = std::io::stdout().flush();
            }
        }

        // Check for stdin input using poll
        let mut pollfd = libc::pollfd {
            fd: 0, // stdin
            events: libc::POLLIN,
            revents: 0,
        };

        let poll_result = unsafe { libc::poll(&mut pollfd, 1, 10) }; // 10ms timeout

        if poll_result > 0 && (pollfd.revents & libc::POLLIN) != 0 {
            match stdin.read(&mut input_buf) {
                Ok(0) => break, // EOF
                Ok(n) => {
                    for &byte in &input_buf[..n] {
                        if ctrl_a_pressed {
                            ctrl_a_pressed = false;
                            if byte == b'x' || byte == b'X' {
                                // Ctrl+A X = exit
                                println!("\r\n[Exiting console...]");
                                running.store(false, Ordering::SeqCst);
                                break;
                            } else if byte == 0x01 {
                                // Ctrl+A Ctrl+A = send Ctrl+A
                                let _ = vm.write_console_input("\x01");
                            } else {
                                // Unknown sequence, send both
                                let _ = vm.write_console_input("\x01");
                                let buf = [byte];
                                let s = String::from_utf8_lossy(&buf);
                                let _ = vm.write_console_input(&s);
                            }
                        } else if byte == 0x01 {
                            // Ctrl+A
                            ctrl_a_pressed = true;
                        } else {
                            let buf = [byte];
                            let s = String::from_utf8_lossy(&buf);
                            let _ = vm.write_console_input(&s);
                        }
                    }
                }
                Err(_) => {}
            }
        }
    }

    // Restore terminal
    restore_terminal(original_termios);

    println!();
    println!("Stopping VM...");
    match vm.stop() {
        Ok(()) => println!("VM stopped successfully"),
        Err(e) => println!("Error stopping VM: {}", e),
    }
}

#[cfg(target_os = "macos")]
fn run_demo_mode(vm: &mut arcbox_hypervisor::darwin::DarwinVm, test_vsock: bool) {
    use arcbox_hypervisor::traits::VirtualMachine;

    println!("VM is running. Press Ctrl+C to stop.");
    println!();

    // Run for a while, reading console output
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
    if test_vsock {
        println!();
        for port in [2222u32, 1024] {
            println!("Testing vsock connection to port {}...", port);
            match vm.connect_vsock(port) {
                Ok(fd) => {
                    println!("  Vsock port {} connected! fd={}", port, fd);
                    unsafe { libc::close(fd) };
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

#[cfg(target_os = "macos")]
fn setup_raw_mode() -> libc::termios {
    use std::mem::MaybeUninit;

    let mut original: MaybeUninit<libc::termios> = MaybeUninit::uninit();

    unsafe {
        libc::tcgetattr(0, original.as_mut_ptr());
        let original = original.assume_init();

        let mut raw = original;
        // Disable canonical mode and echo
        raw.c_lflag &= !(libc::ICANON | libc::ECHO | libc::ISIG);
        // Disable input processing
        raw.c_iflag &= !(libc::IXON | libc::ICRNL);
        // Set minimum characters and timeout
        raw.c_cc[libc::VMIN] = 0;
        raw.c_cc[libc::VTIME] = 0;

        libc::tcsetattr(0, libc::TCSANOW, &raw);

        original
    }
}

#[cfg(target_os = "macos")]
fn restore_terminal(original: libc::termios) {
    unsafe {
        libc::tcsetattr(0, libc::TCSANOW, &original);
    }
}
