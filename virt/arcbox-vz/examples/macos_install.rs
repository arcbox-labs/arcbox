//! Gate B for macOS guests: install macOS from a local IPSW and boot to Running.
//!
//! Builds a macOS VM configuration with a fresh system disk, runs `VZMacOSInstaller`
//! against a local restore image, then starts the VM and waits for it to reach the
//! Running state.
//!
//! Requires Apple Silicon, a binary signed with the
//! `com.apple.security.virtualization` entitlement, and an APFS target directory.
//! Installation takes roughly 10-20 minutes.
//!
//! ```sh
//! cargo run -p arcbox-vz --example macos_install -- /path/to/UniversalMac.ipsw [target-dir]
//! ```

use std::error::Error;
use std::path::PathBuf;

use arcbox_vz::{
    MacAuxiliaryStorage, MacGraphicsDeviceConfiguration, MacMachineIdentifier, MacOSBootLoader,
    MacOSInstaller, MacOSRestoreImage, MacPlatform, StorageDeviceConfiguration,
    VirtualMachineConfiguration, VirtualMachineState, min_cpu_count, min_memory_size,
};

/// Size of the sparse macOS system disk image.
const DISK_SIZE_BYTES: u64 = 64 * 1024 * 1024 * 1024;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    if !arcbox_vz::is_supported() {
        eprintln!("Virtualization is not supported on this host (Apple Silicon required).");
        return Ok(());
    }

    let mut args = std::env::args().skip(1);
    let ipsw = args
        .next()
        .ok_or("usage: macos_install <ipsw-path> [target-dir]")?;
    let target = args.next().map_or_else(
        || std::env::temp_dir().join("arcbox-macos-install"),
        PathBuf::from,
    );
    std::fs::create_dir_all(&target)?;
    let disk_path = target.join("disk.img");
    let aux_path = target.join("aux.img");

    println!("Loading restore image {ipsw} ...");
    let restore = MacOSRestoreImage::load_from_url(&ipsw).await?;
    let reqs = restore.requirements()?;
    if !reqs.hardware_model.is_supported() {
        return Err("restore image hardware model is not supported on this host".into());
    }
    let cpus = usize::try_from(reqs.minimum_cpu_count.max(min_cpu_count())).unwrap_or(1);
    // macOS installation/personalization is memory-hungry; use at least 8 GiB.
    let memory = reqs
        .minimum_memory_size
        .max(8 * 1024 * 1024 * 1024)
        .max(min_memory_size());

    // Create the system disk image (sparse) and fresh auxiliary storage.
    println!(
        "Allocating {} GiB system disk at {} ...",
        DISK_SIZE_BYTES / (1024 * 1024 * 1024),
        disk_path.display()
    );
    let disk = std::fs::File::create(&disk_path)?;
    disk.set_len(DISK_SIZE_BYTES)?;
    drop(disk);
    let _ = std::fs::remove_file(&aux_path);
    let aux = MacAuxiliaryStorage::create(&aux_path, &reqs.hardware_model, true)?;
    let machine_id = MacMachineIdentifier::new()?;
    let platform = MacPlatform::new(&reqs.hardware_model, &machine_id, &aux)?;

    let mut config = VirtualMachineConfiguration::new()?;
    config
        .set_cpu_count(cpus)
        .set_memory_size(memory)
        .set_platform(platform)
        .set_boot_loader(MacOSBootLoader::new()?)
        .add_storage_device(StorageDeviceConfiguration::disk_image(&disk_path, false)?)
        .add_graphics_device(MacGraphicsDeviceConfiguration::new(1920, 1080, 80)?);
    config.validate()?;
    let vm = config.build()?;

    println!("Installing macOS (this can take 10-20 minutes) ...");
    let installer = MacOSInstaller::new(&vm, &ipsw)?;
    let mut last = String::new();
    installer
        .install(&vm, |fraction| {
            let line = format!("{:.0}%", fraction * 100.0);
            if line != last {
                println!("  install progress: {line}");
                last = line;
            }
        })
        .await?;
    println!("Install complete.");

    // VZMacOSInstaller leaves the VM running (booted into the installed OS); only
    // issue a start if it came back stopped.
    if vm.state() == VirtualMachineState::Stopped {
        println!("Booting installed macOS ...");
        vm.start().await?;
    }

    let mut waited = 0;
    while vm.state() != VirtualMachineState::Running && waited < 60 {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        waited += 1;
    }

    if vm.state() == VirtualMachineState::Running {
        println!(
            "Gate B PASS: macOS installed and VM reached Running ({cpus} cpus, {} MiB).",
            memory / (1024 * 1024)
        );
        let _ = vm.stop().await;
        Ok(())
    } else {
        Err(format!("VM did not reach Running (state = {:?})", vm.state()).into())
    }
}
