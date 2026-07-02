//! Installing macOS from an IPSW into a base image template.
//!
//! Drives the arcbox-vz installer (the same flow proven by Gate B) and persists a
//! complete base image — `disk.img`, `aux.img`, `hwmodel.bin`, `machine-id.bin`,
//! `meta.json` — that [`MacImageManager::clone_base`] can copy-on-write clone.
//!
//! Retained but unshipped: the product acquires base images exclusively via
//! [`MacImageManager::pull_remote`](super::pull); this module is compiled only
//! under the `macos-ipsw-install` feature so the installer flow stays
//! compiler-verified without being product surface.

use std::path::{Path, PathBuf};

use arcbox_vz::{
    MacAuxiliaryStorage, MacGraphicsDeviceConfiguration, MacMachineIdentifier, MacOSBootLoader,
    MacOSInstaller, MacOSRestoreImage, MacPlatform, StorageDeviceConfiguration,
    VirtualMachineConfiguration, min_cpu_count, min_memory_size,
};
use chrono::Utc;

use super::download::download_ipsw;
use super::image::{MacImage, MacImageManager, MacImageMeta};
use crate::error::{CoreError, Result};

/// Where a [`MacImageManager::pull`] obtains its IPSW.
#[derive(Debug, Clone)]
pub enum PullSource {
    /// Restore from a local IPSW file.
    LocalIpsw(PathBuf),
    /// Download the latest Apple-published restore image.
    Latest,
}

/// The phase a [`MacImageManager::pull`] is in, for progress reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PullPhase {
    /// Downloading the IPSW from Apple.
    Download,
    /// Restoring macOS onto the base image (the long phase).
    Install,
}

/// macOS installation is memory-hungry; floor the install VM at 8 GiB.
const INSTALL_MIN_MEMORY: u64 = 8 * GIB;
const GIB: u64 = 1024 * 1024 * 1024;

impl MacImageManager {
    /// Installs macOS from a local IPSW into a new base image named `name`.
    ///
    /// Writes `disk.img` + `aux.img` + `hwmodel.bin` + `machine-id.bin` + `meta.json`
    /// under the image directory and returns the resulting [`MacImage`]. This is a
    /// long-running operation (tens of minutes); `on_progress` is invoked with the
    /// installation fraction (`0.0..=1.0`) as it proceeds. Apple Silicon only.
    ///
    /// # Errors
    /// Returns an error if the image already exists, the restore image's hardware
    /// model is unsupported on this host, or any install/persist step fails.
    #[allow(
        clippy::future_not_send,
        reason = "drives Virtualization.framework through ObjC pointers and the VM's dispatch queue, which are inherently !Send and held across await; the caller drives it on a single thread"
    )]
    pub async fn install_from_ipsw(
        &self,
        ipsw: &Path,
        name: &str,
        disk_gb: u64,
        on_progress: impl FnMut(f64),
    ) -> Result<MacImage> {
        let dir = self.image_dir(name);
        if dir.join("meta.json").exists() {
            return Err(CoreError::already_exists(format!("macOS image '{name}'")));
        }

        let restore = MacOSRestoreImage::load_from_url(ipsw).await?;
        let reqs = restore.requirements()?;
        if !reqs.hardware_model.is_supported() {
            return Err(CoreError::macos(
                "restore image hardware model is not supported on this host",
            ));
        }

        std::fs::create_dir_all(&dir)?;
        let disk_path = dir.join("disk.img");
        let aux_path = dir.join("aux.img");

        // Persist the identity so clones can reproduce a bootable configuration.
        std::fs::write(
            dir.join("hwmodel.bin"),
            reqs.hardware_model.data_representation(),
        )?;
        let machine_id = MacMachineIdentifier::new()?;
        std::fs::write(dir.join("machine-id.bin"), machine_id.data_representation())?;

        // Allocate the (sparse) system disk and fresh auxiliary storage.
        let disk = std::fs::File::create(&disk_path)?;
        disk.set_len(disk_gb * GIB)?;
        drop(disk);
        let _ = std::fs::remove_file(&aux_path);
        let aux = MacAuxiliaryStorage::create(&aux_path, &reqs.hardware_model, true)?;

        let platform = MacPlatform::new(&reqs.hardware_model, &machine_id, &aux)?;
        let cpus = usize::try_from(reqs.minimum_cpu_count.max(min_cpu_count())).unwrap_or(1);
        let memory = reqs
            .minimum_memory_size
            .max(INSTALL_MIN_MEMORY)
            .max(min_memory_size());

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

        let installer = MacOSInstaller::new(&vm, ipsw)?;
        installer.install(&vm, on_progress).await?;

        // The installer leaves the VM running; power it off so the base is captured
        // at rest. Best-effort — ignore an error if it is already stopped.
        let _ = vm.stop().await;

        let meta = MacImageMeta {
            name: name.to_string(),
            source: Some(ipsw.display().to_string()),
            stream: None,
            version: None,
            os_version: None,
            os_build: None,
            runner_version: None,
            minimum_cpu_count: reqs.minimum_cpu_count,
            minimum_memory_mib: memory / (1024 * 1024),
            disk_gb,
            created_at: Utc::now(),
        };
        self.write_meta(&meta)?;
        self.get(name)
    }

    /// Pulls a base image: obtain an IPSW (downloading the latest when needed), then
    /// restore it into a base image named `name`.
    ///
    /// `on_progress` is invoked with the current phase and its fraction
    /// (`0.0..=1.0`). Apple Silicon only.
    ///
    /// # Errors
    /// Returns an error if the download fails, the latest restore image has no URL,
    /// or any restore/persist step fails.
    #[allow(
        clippy::future_not_send,
        reason = "drives Virtualization.framework through !Send ObjC pointers held across await; the caller drives it on a single thread"
    )]
    pub async fn pull(
        &self,
        source: PullSource,
        name: &str,
        disk_gb: u64,
        mut on_progress: impl FnMut(PullPhase, f64),
    ) -> Result<MacImage> {
        let ipsw = match source {
            PullSource::LocalIpsw(path) => path,
            PullSource::Latest => {
                let restore = MacOSRestoreImage::latest_supported().await?;
                let url = restore
                    .url()
                    .ok_or_else(|| CoreError::macos("latest restore image has no download URL"))?;
                drop(restore);
                download_ipsw(&url, &self.cache_dir(), None, |frac| {
                    on_progress(PullPhase::Download, frac);
                })
                .await?
            }
        };
        self.install_from_ipsw(&ipsw, name, disk_gb, |frac| {
            on_progress(PullPhase::Install, frac);
        })
        .await
    }
}
