//! Fast diagnostic: build a macOS VM config (platform + boot loader + disk +
//! graphics) from the latest restore image METADATA (no multi-GB IPSW download)
//! and try to START a bare VM. Isolates "is this config/storage attachment valid
//! enough for the VM to start" from the full install flow.
//!
//! ```sh
//! cargo run -p arcbox-vz --example macos_probe -- [target-dir]
//! ```

use std::error::Error;
use std::path::PathBuf;

use arcbox_vz::{
    MacAuxiliaryStorage, MacGraphicsDeviceConfiguration, MacMachineIdentifier, MacOSBootLoader,
    MacOSRestoreImage, MacPlatform, StorageDeviceConfiguration, VirtualMachineConfiguration,
    VirtualMachineState, min_cpu_count, min_memory_size,
};

const DISK_SIZE_BYTES: u64 = 64 * 1024 * 1024 * 1024;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    if !arcbox_vz::is_supported() {
        eprintln!("Virtualization is not supported on this host.");
        return Ok(());
    }
    let dir = std::env::args().nth(1).map_or_else(
        || std::env::temp_dir().join("arcbox-macos-probe"),
        PathBuf::from,
    );
    std::fs::create_dir_all(&dir)?;
    let disk_path = dir.join("disk.img");
    let aux_path = dir.join("aux.img");

    println!("Fetching latest restore image metadata ...");
    let restore = MacOSRestoreImage::latest_supported().await?;
    let reqs = restore.requirements()?;
    let cpus = usize::try_from(reqs.minimum_cpu_count.max(min_cpu_count())).unwrap_or(1);
    let memory = reqs.minimum_memory_size.max(min_memory_size());

    let disk = std::fs::File::create(&disk_path)?;
    disk.set_len(DISK_SIZE_BYTES)?;
    disk.sync_all()?;
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

    print!("validate ... ");
    match config.validate() {
        Ok(()) => println!("OK"),
        Err(e) => {
            println!("ERR: {e}");
            return Err(e.into());
        }
    }

    let vm = config.build()?;
    println!("starting bare VM (empty disk; will not boot an OS) ...");
    match vm.start().await {
        Ok(()) => {
            for _ in 0..10 {
                if vm.state() == VirtualMachineState::Running {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            }
            println!(
                "START OK — state={:?} (config + storage attachment are valid)",
                vm.state()
            );
            let _ = vm.stop().await;
        }
        Err(e) => println!("START ERR: {e}"),
    }
    Ok(())
}
