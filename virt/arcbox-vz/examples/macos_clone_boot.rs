//! Verify clone + boot: copy-on-write clone an installed base disk + aux storage and
//! boot the clone. Confirms `clonefile(2)` is fast and space-shared, that a cloned
//! installed disk is a valid bootable attachment, and whether a fresh machine
//! identifier paired with the copied auxiliary storage still starts.
//!
//! ```sh
//! cargo run -p arcbox-vz --example macos_clone_boot -- <base-dir>
//! ```
//! `base-dir` must hold an installed `disk.img` and `aux.img`.

use std::error::Error;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::time::Instant;

use arcbox_vz::{
    MacAuxiliaryStorage, MacGraphicsDeviceConfiguration, MacMachineIdentifier, MacOSBootLoader,
    MacOSRestoreImage, MacPlatform, StorageDeviceConfiguration, VirtualMachineConfiguration,
    VirtualMachineState, min_cpu_count, min_memory_size,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    if !arcbox_vz::is_supported() {
        eprintln!("Virtualization is not supported on this host.");
        return Ok(());
    }
    let base: PathBuf = std::env::args()
        .nth(1)
        .ok_or("usage: macos_clone_boot <base-dir>")?
        .into();
    let base_disk = base.join("disk.img");
    let base_aux = base.join("aux.img");
    let clone_dir = base.join("clone-test");
    std::fs::create_dir_all(&clone_dir)?;
    let clone_disk = clone_dir.join("disk.img");
    let clone_aux = clone_dir.join("aux.img");

    // Copy-on-write clone the installed system disk via clonefile(2).
    let _ = std::fs::remove_file(&clone_disk);
    let src = CString::new(base_disk.as_os_str().as_bytes())?;
    let dst = CString::new(clone_disk.as_os_str().as_bytes())?;
    let started = Instant::now();
    // SAFETY: clonefile takes two valid NUL-terminated C paths and a flags word.
    let rc = unsafe { libc::clonefile(src.as_ptr(), dst.as_ptr(), 0) };
    if rc != 0 {
        return Err(format!("clonefile failed: {}", std::io::Error::last_os_error()).into());
    }
    let logical = std::fs::metadata(&clone_disk)?.len();
    println!(
        "clonefile disk: {} GiB logical in {:?}",
        logical / (1024 * 1024 * 1024),
        started.elapsed()
    );
    std::fs::copy(&base_aux, &clone_aux)?;

    // Re-derive the hardware model from the latest metadata; use a FRESH identifier.
    let restore = MacOSRestoreImage::latest_supported().await?;
    let reqs = restore.requirements()?;
    let machine_id = MacMachineIdentifier::new()?;
    let aux = MacAuxiliaryStorage::open(&clone_aux)?;
    let platform = MacPlatform::new(&reqs.hardware_model, &machine_id, &aux)?;
    let cpus = usize::try_from(reqs.minimum_cpu_count.max(min_cpu_count())).unwrap_or(1);
    let memory = reqs.minimum_memory_size.max(min_memory_size());

    let mut config = VirtualMachineConfiguration::new()?;
    config
        .set_cpu_count(cpus)
        .set_memory_size(memory)
        .set_platform(platform)
        .set_boot_loader(MacOSBootLoader::new()?)
        .add_storage_device(StorageDeviceConfiguration::disk_image(&clone_disk, false)?)
        .add_graphics_device(MacGraphicsDeviceConfiguration::new(1920, 1080, 80)?);
    config.validate()?;
    let vm = config.build()?;

    println!("booting clone (fresh machine-id, copied aux) ...");
    vm.start().await?;
    let mut waited = 0;
    while vm.state() != VirtualMachineState::Running && waited < 40 {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        waited += 1;
    }
    println!("CLONE BOOT: state={:?}", vm.state());
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    println!("after 5s running: state={:?}", vm.state());
    let _ = vm.stop().await;
    Ok(())
}
