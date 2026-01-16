//! VirtioFS directory sharing test example.
//!
//! This example demonstrates VirtioFS directory sharing between host and guest.
//!
//! # Usage
//!
//! ```bash
//! # Build and sign
//! cargo build --example virtiofs -p arcbox-vz
//! codesign --entitlements tests/resources/entitlements.plist --force -s - \
//!     target/debug/examples/virtiofs
//!
//! # Run with a Linux kernel
//! ./target/debug/examples/virtiofs \
//!     tests/resources/Image \
//!     tests/resources/initramfs.cpio.gz \
//!     /tmp/share
//! ```
//!
//! # Expected Behavior
//!
//! The example will:
//! 1. Create a VM with VirtioFS device sharing the specified directory
//! 2. Boot the VM
//! 3. In the guest (with virtiofs support), mount with:
//!    `mount -t virtiofs share /mnt`

use arcbox_vz::{
    EntropyDeviceConfiguration, GenericPlatform, LinuxBootLoader, LinuxRosettaDirectoryShare,
    RosettaAvailability, SerialPortConfiguration, SharedDirectory, SingleDirectoryShare,
    SocketDeviceConfiguration, VirtioFileSystemDeviceConfiguration, VirtualMachineConfiguration,
    VirtualMachineState, is_supported,
};
use std::env;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("arcbox_vz=debug".parse()?),
        )
        .init();

    // Check arguments
    let args: Vec<String> = env::args().collect();
    if args.len() < 4 {
        eprintln!("Usage: {} <kernel> <initrd> <share-path>", args[0]);
        eprintln!();
        eprintln!("Example:");
        eprintln!(
            "  {} tests/resources/Image tests/resources/initramfs.cpio.gz /tmp/share",
            args[0]
        );
        eprintln!();
        eprintln!("To mount in guest (requires virtiofs support):");
        eprintln!("  mount -t virtiofs share /mnt");
        std::process::exit(1);
    }

    let kernel_path = &args[1];
    let initrd_path = &args[2];
    let share_path = &args[3];

    if !is_supported() {
        eprintln!("Virtualization is not supported on this system");
        std::process::exit(1);
    }

    println!("=== arcbox-vz VirtioFS test ===");
    println!();

    // Check Rosetta availability (informational)
    println!("[1/7] Checking Rosetta availability...");
    let rosetta = LinuxRosettaDirectoryShare::availability();
    println!(
        "       Rosetta: {:?}",
        match rosetta {
            RosettaAvailability::Supported => "Supported (installed)",
            RosettaAvailability::NotInstalled => "Not installed (can be installed)",
            RosettaAvailability::NotSupported => "Not supported on this system",
        }
    );

    // Ensure share directory exists
    println!("[2/7] Setting up share directory: {}", share_path);
    if !std::path::Path::new(share_path).exists() {
        std::fs::create_dir_all(share_path)?;
        println!("       Created directory");
    } else {
        println!("       Directory exists");
    }

    // Create a test file in the share directory
    let test_file = format!("{}/hello.txt", share_path);
    std::fs::write(&test_file, "Hello from the host!\n")?;
    println!("       Created test file: hello.txt");

    // Create shared directory
    println!("[3/7] Creating VirtioFS configuration...");
    let shared_dir = SharedDirectory::new(share_path, false)?;
    println!("       SharedDirectory created (read-only: false)");

    let single_share = SingleDirectoryShare::new(shared_dir)?;
    println!("       SingleDirectoryShare created");

    let mut fs_config = VirtioFileSystemDeviceConfiguration::new("share")?;
    println!("       VirtioFileSystemDeviceConfiguration created (tag: 'share')");

    fs_config.set_share(single_share);
    println!("       Share attached to VirtioFS device");

    // Create boot loader
    println!("[4/7] Creating boot loader...");
    let mut boot_loader = LinuxBootLoader::new(kernel_path)?;
    boot_loader
        .set_initial_ramdisk(initrd_path)
        .set_command_line("console=hvc0");

    // Create VM configuration
    println!("[5/7] Building VM configuration...");
    let serial_port = SerialPortConfiguration::virtio_console()?;
    let read_fd = serial_port.read_fd();

    let mut config = VirtualMachineConfiguration::new()?;
    config
        .set_cpu_count(2)
        .set_memory_size(512 * 1024 * 1024) // 512 MB
        .set_platform(GenericPlatform::new()?)
        .set_boot_loader(boot_loader)
        .add_entropy_device(EntropyDeviceConfiguration::new()?)
        .add_serial_port(serial_port)
        .add_socket_device(SocketDeviceConfiguration::new()?)
        .add_directory_share(fs_config);

    println!("       Configuration complete, building VM...");
    let vm = config.build()?;
    println!("       VM built successfully!");

    // Start VM
    println!("[6/7] Starting VM...");
    vm.start().await?;

    if vm.state() != VirtualMachineState::Running {
        eprintln!("VM failed to start, state: {:?}", vm.state());
        std::process::exit(1);
    }
    println!("       VM started successfully!");

    // Read serial output while waiting
    println!("[7/7] Waiting for guest to boot (10 seconds)...");
    println!();
    println!("--- Guest Serial Output ---");

    if let Some(fd) = read_fd {
        // Set non-blocking
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL);
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }

        let start = std::time::Instant::now();

        while start.elapsed() < Duration::from_secs(10) {
            let mut buf = [0u8; 1024];
            let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if n > 0 {
                let s = String::from_utf8_lossy(&buf[..n as usize]);
                print!("{}", s);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        println!();
    } else {
        tokio::time::sleep(Duration::from_secs(10)).await;
    }

    println!("--- End Serial Output ---");
    println!();
    println!("VirtioFS Instructions:");
    println!("  If the guest supports virtiofs, mount with:");
    println!("    mount -t virtiofs share /mnt");
    println!("    cat /mnt/hello.txt");
    println!();

    // Stop VM
    println!("Stopping VM...");
    vm.stop().await?;
    println!("Done!");

    Ok(())
}
