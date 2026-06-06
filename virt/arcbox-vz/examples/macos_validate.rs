//! Gate A for macOS guests: build and validate a macOS VM configuration.
//!
//! Obtains a hardware model from a restore image (the latest Apple publishes, or a
//! local IPSW passed as the first argument), assembles a macOS
//! `VirtualMachineConfiguration` (boot loader + platform + auxiliary storage), and
//! validates it against Virtualization.framework.
//!
//! Requires Apple Silicon and a binary signed with the
//! `com.apple.security.virtualization` entitlement.
//!
//! ```sh
//! # Latest supported (fetches metadata only, no multi-GB download):
//! cargo run -p arcbox-vz --example macos_validate
//! # From a local restore image / IPSW:
//! cargo run -p arcbox-vz --example macos_validate -- /path/to/UniversalMac.ipsw
//! ```

use std::error::Error;

use arcbox_vz::{
    MacAuxiliaryStorage, MacMachineIdentifier, MacOSBootLoader, MacOSRestoreImage, MacPlatform,
    VirtualMachineConfiguration, min_cpu_count, min_memory_size,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    if !arcbox_vz::is_supported() {
        eprintln!("Virtualization is not supported on this host (Apple Silicon required).");
        return Ok(());
    }

    let restore = match std::env::args().nth(1) {
        Some(path) => {
            println!("Loading restore image from {path} ...");
            MacOSRestoreImage::load_from_url(&path).await?
        }
        None => {
            println!("Fetching latest supported restore image metadata ...");
            MacOSRestoreImage::latest_supported().await?
        }
    };

    let reqs = restore.requirements()?;
    println!(
        "Restore image: hardware model supported = {}, min cpus = {}, min memory = {} MiB",
        reqs.hardware_model.is_supported(),
        reqs.minimum_cpu_count,
        reqs.minimum_memory_size / (1024 * 1024),
    );

    // Auxiliary storage (NVRAM) lives in a scratch directory for this check.
    let dir = std::env::temp_dir().join("arcbox-macos-validate");
    std::fs::create_dir_all(&dir)?;
    let aux_path = dir.join("aux.img");
    let _ = std::fs::remove_file(&aux_path);
    let aux = MacAuxiliaryStorage::create(&aux_path, &reqs.hardware_model, true)?;
    let machine_id = MacMachineIdentifier::new()?;
    let platform = MacPlatform::new(&reqs.hardware_model, &machine_id, &aux)?;

    let cpus = usize::try_from(reqs.minimum_cpu_count.max(min_cpu_count())).unwrap_or(1);
    let memory = reqs.minimum_memory_size.max(min_memory_size());

    let mut config = VirtualMachineConfiguration::new()?;
    config
        .set_cpu_count(cpus)
        .set_memory_size(memory)
        .set_platform(platform)
        .set_boot_loader(MacOSBootLoader::new()?);

    config.validate()?;
    println!(
        "Gate A PASS: macOS VM configuration validated ({cpus} cpus, {} MiB).",
        memory / (1024 * 1024)
    );

    let _ = std::fs::remove_file(&aux_path);
    Ok(())
}
