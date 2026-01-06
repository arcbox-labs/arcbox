//! Simple VM example.
//!
//! This example demonstrates how to create and run a simple Linux VM
//! using arcbox-vz.
//!
//! # Usage
//!
//! ```bash
//! # Build and sign (required for virtualization entitlement)
//! cargo build --example simple_vm
//! codesign --entitlements tests/resources/entitlements.plist --force -s - \
//!     target/debug/examples/simple_vm
//!
//! # Run
//! ./target/debug/examples/simple_vm <kernel> [initrd]
//! ```

use arcbox_vz::{
    is_supported, EntropyDeviceConfiguration, GenericPlatform, LinuxBootLoader,
    SocketDeviceConfiguration, VirtualMachineConfiguration, VZError,
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
    if args.len() < 2 {
        eprintln!("Usage: {} <kernel> [initrd]", args[0]);
        std::process::exit(1);
    }

    let kernel_path = &args[1];
    let initrd_path = args.get(2);

    // Check if virtualization is supported
    if !is_supported() {
        eprintln!("Virtualization is not supported on this system");
        std::process::exit(1);
    }

    println!("Creating VM configuration...");

    // Create boot loader
    let mut boot_loader = LinuxBootLoader::new(kernel_path)?;
    boot_loader.set_command_line("console=hvc0");

    if let Some(initrd) = initrd_path {
        boot_loader.set_initial_ramdisk(initrd);
    }

    // Create VM configuration
    let mut config = VirtualMachineConfiguration::new()?;
    config
        .set_cpu_count(2)
        .set_memory_size(512 * 1024 * 1024) // 512 MB
        .set_platform(GenericPlatform::new()?)
        .set_boot_loader(boot_loader)
        .add_entropy_device(EntropyDeviceConfiguration::new()?)
        .add_socket_device(SocketDeviceConfiguration::new()?);

    println!("Building VM...");
    let vm = config.build()?;

    println!("Starting VM...");
    vm.start().await?;

    println!("VM is running!");
    println!("State: {:?}", vm.state());

    // Let it run for a bit
    println!("Running for 5 seconds...");
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Stop the VM
    println!("Stopping VM...");
    vm.stop().await?;

    println!("VM stopped.");
    println!("Final state: {:?}", vm.state());

    Ok(())
}
