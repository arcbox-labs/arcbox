//! Vsock listen test example.
//!
//! This example tests vsock listen functionality with a running guest VM.
//! It sets up a listener on the host and waits for guest connections.
//!
//! # Usage
//!
//! ```bash
//! # Build and sign
//! cargo build --example vsock_listen -p arcbox-vz
//! codesign --entitlements tests/resources/entitlements.plist --force -s - \
//!     target/debug/examples/vsock_listen
//!
//! # Run with PUI PUI Linux
//! ./target/debug/examples/vsock_listen \
//!     tests/resources/Image \
//!     tests/resources/initramfs.cpio.gz
//! ```
//!
//! # Expected Behavior
//!
//! The example will:
//! 1. Start a VM
//! 2. Set up a listener on port 5000
//! 3. Wait for a few seconds to see if any connections arrive
//! 4. Test connect to port 2222 (to verify vsock works)

use arcbox_vz::{
    is_supported, EntropyDeviceConfiguration, GenericPlatform, LinuxBootLoader,
    SerialPortConfiguration, SocketDeviceConfiguration, VirtualMachineConfiguration,
    VirtualMachineState,
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
    if args.len() < 3 {
        eprintln!("Usage: {} <kernel> <initrd>", args[0]);
        eprintln!();
        eprintln!("Example with PUI PUI Linux:");
        eprintln!(
            "  {} tests/resources/Image tests/resources/initramfs.cpio.gz",
            args[0]
        );
        std::process::exit(1);
    }

    let kernel_path = &args[1];
    let initrd_path = &args[2];

    if !is_supported() {
        eprintln!("Virtualization is not supported on this system");
        std::process::exit(1);
    }

    println!("=== arcbox-vz vsock listen test ===");
    println!();

    // Create boot loader
    println!("[1/6] Creating boot loader...");
    let mut boot_loader = LinuxBootLoader::new(kernel_path)?;
    boot_loader
        .set_initial_ramdisk(initrd_path)
        .set_command_line("console=hvc0");

    // Create VM configuration
    println!("[2/6] Building VM configuration...");
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
        .add_socket_device(SocketDeviceConfiguration::new()?);

    let vm = config.build()?;

    // Start VM
    println!("[3/6] Starting VM...");
    vm.start().await?;

    if vm.state() != VirtualMachineState::Running {
        eprintln!("VM failed to start, state: {:?}", vm.state());
        std::process::exit(1);
    }
    println!("       VM started successfully!");

    // Wait for guest to boot
    println!("[4/6] Waiting for guest to boot (5 seconds)...");

    // Read serial output while waiting
    if let Some(fd) = read_fd {
        // Set non-blocking
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL);
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }

        let start = std::time::Instant::now();

        while start.elapsed() < Duration::from_secs(5) {
            let mut buf = [0u8; 1024];
            let n = unsafe {
                libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
            };
            if n > 0 {
                let s = String::from_utf8_lossy(&buf[..n as usize]);
                print!("{}", s);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        println!();
    } else {
        tokio::time::sleep(Duration::from_secs(5)).await;
    }

    // Get socket device
    let socket_devices = vm.socket_devices();
    if socket_devices.is_empty() {
        eprintln!("ERROR: No socket devices found!");
        vm.stop().await?;
        std::process::exit(1);
    }

    let device = &socket_devices[0];

    // Test listen functionality
    println!("[5/6] Setting up listener on port 5000...");

    match device.listen(5000) {
        Ok(mut listener) => {
            println!("       SUCCESS! Listener created on port {}", listener.port());

            // Wait for incoming connections (timeout after 3 seconds)
            println!("       Waiting for incoming connections (3 seconds)...");
            println!("       (Note: PUI PUI Linux doesn't have a vsock client, so no connections expected)");

            let timeout = tokio::time::timeout(Duration::from_secs(3), listener.accept()).await;

            match timeout {
                Ok(Ok(conn)) => {
                    println!(
                        "       Connection received! fd={}, src_port={}, dst_port={}",
                        conn.as_raw_fd(),
                        conn.source_port(),
                        conn.destination_port()
                    );
                }
                Ok(Err(e)) => {
                    println!("       Accept error: {}", e);
                }
                Err(_) => {
                    println!("       No connections received (timeout - this is expected)");
                }
            }

            // Try non-blocking accept
            if let Some(conn) = listener.try_accept() {
                println!("       try_accept: Connection! fd={}", conn.as_raw_fd());
            } else {
                println!("       try_accept: No pending connections");
            }

            // Drop listener to test cleanup
            println!("       Dropping listener to test cleanup...");
            drop(listener);
            println!("       Listener dropped successfully!");
        }
        Err(e) => {
            eprintln!("       FAILED: {}", e);
        }
    }

    // Also test connect to verify basic vsock works
    println!();
    println!("[6/6] Testing connect to port 2222 (socat)...");
    match device.connect(2222).await {
        Ok(conn) => {
            println!(
                "       Connect SUCCESS! fd={}, src_port={}, dst_port={}",
                conn.as_raw_fd(),
                conn.source_port(),
                conn.destination_port()
            );
        }
        Err(e) => {
            println!("       Connect failed: {}", e);
        }
    }

    // Stop VM
    println!();
    println!("Stopping VM...");
    vm.stop().await?;
    println!("Done!");

    Ok(())
}
