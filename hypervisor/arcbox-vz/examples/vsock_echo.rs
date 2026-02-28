//! Vsock connection test example.
//!
//! This example tests vsock connection to a running guest VM.
//! It uses PUI PUI Linux which has socat listening on port 2222.
//!
//! # Usage
//!
//! ```bash
//! # Build and sign
//! cargo build --example vsock_echo -p arcbox-vz
//! codesign --entitlements tests/resources/entitlements.plist --force -s - \
//!     target/debug/examples/vsock_echo
//!
//! # Run with PUI PUI Linux
//! ./target/debug/examples/vsock_echo \
//!     tests/resources/Image \
//!     tests/resources/initramfs.cpio.gz
//! ```
//!
//! # Expected Output
//!
//! If vsock is working correctly, you should see:
//! - VM starts successfully
//! - Connection to port 2222 succeeds
//! - Echo test passes

use arcbox_vz::{
    EntropyDeviceConfiguration, GenericPlatform, LinuxBootLoader, SerialPortConfiguration,
    SocketDeviceConfiguration, VirtualMachineConfiguration, VirtualMachineState, is_supported,
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

    println!("=== arcbox-vz vsock test ===");
    println!();

    // Create boot loader
    println!("[1/5] Creating boot loader...");
    let mut boot_loader = LinuxBootLoader::new(kernel_path)?;
    boot_loader
        .set_initial_ramdisk(initrd_path)
        .set_command_line("console=hvc0");

    // Create VM configuration
    println!("[2/5] Building VM configuration...");
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
    println!("[3/5] Starting VM...");
    vm.start().await?;

    if vm.state() != VirtualMachineState::Running {
        eprintln!("VM failed to start, state: {:?}", vm.state());
        std::process::exit(1);
    }
    println!("       VM started successfully!");

    // Wait for guest to boot and start socat
    println!("[4/5] Waiting for guest to boot (5 seconds)...");

    // Read serial output while waiting
    if let Some(fd) = read_fd {
        // Set non-blocking
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL);
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }

        let start = std::time::Instant::now();
        let mut output = String::new();

        while start.elapsed() < Duration::from_secs(5) {
            let mut buf = [0u8; 1024];
            let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if n > 0 {
                let s = String::from_utf8_lossy(&buf[..n as usize]);
                output.push_str(&s);
                print!("{}", s);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        println!();

        // Check if socat is running
        if output.contains("socat") || output.contains("listening") {
            println!("       Guest appears to have started socat.");
        }
    } else {
        tokio::time::sleep(Duration::from_secs(5)).await;
    }

    // Test vsock connection
    println!("[5/5] Testing vsock connection to port 2222...");

    let socket_devices = vm.socket_devices();
    if socket_devices.is_empty() {
        eprintln!("       ERROR: No socket devices found!");
        vm.stop().await?;
        std::process::exit(1);
    }

    println!("       Found {} socket device(s)", socket_devices.len());

    let device = &socket_devices[0];

    // Try to connect to port 2222 (PUI PUI Linux socat)
    match device.connect(2222).await {
        Ok(conn) => {
            println!("       SUCCESS! Connected to port 2222");
            println!("         fd = {}", conn.as_raw_fd());
            println!("         source_port = {}", conn.source_port());
            println!("         destination_port = {}", conn.destination_port());

            // Test echo
            println!();
            println!("       Testing echo...");
            let test_message = b"Hello from arcbox-vz!";

            match conn.write(test_message) {
                Ok(n) => println!("         Sent {} bytes", n),
                Err(e) => eprintln!("         Write failed: {}", e),
            }

            // Wait a bit for echo response
            tokio::time::sleep(Duration::from_millis(500)).await;

            let mut buf = [0u8; 256];
            match conn.read(&mut buf) {
                Ok(n) if n > 0 => {
                    let response = String::from_utf8_lossy(&buf[..n]);
                    println!("         Received: {}", response.trim());
                    if response.contains("Hello") {
                        println!("         Echo test PASSED!");
                    }
                }
                Ok(_) => println!("         No data received (might be one-way connection)"),
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        println!("         No data available yet (non-blocking)");
                    } else {
                        eprintln!("         Read error: {}", e);
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("       FAILED: {}", e);
            eprintln!();
            eprintln!("       Possible causes:");
            eprintln!("       - Guest hasn't started socat yet (try waiting longer)");
            eprintln!("       - Guest doesn't have vsock support");
            eprintln!("       - Wrong port number");
        }
    }

    // Also try port 1024 (arcbox-agent default)
    println!();
    println!("       Also trying port 1024 (arcbox-agent)...");
    match device.connect(1024).await {
        Ok(conn) => {
            println!("       Connected to port 1024! fd={}", conn.as_raw_fd());
        }
        Err(e) => {
            println!("       Port 1024 not available: {}", e);
        }
    }

    // Stop VM
    println!();
    println!("Stopping VM...");
    vm.stop().await?;
    println!("Done!");

    Ok(())
}
