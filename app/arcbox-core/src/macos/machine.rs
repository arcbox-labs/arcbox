//! macOS guest machine lifecycle.
//!
//! A macOS machine is a copy-on-write clone of a base image (see
//! [`MacImageManager`]) plus a small persisted record. [`MacMachineManager`] creates
//! (clones), starts (boots a [`MacVm`]), stops, and removes them, holding live VMs
//! in memory.
//!
//! The Apple macOS license permits at most two concurrently-running macOS guests per
//! host; `start` enforces that count for macOS machines only (Linux VMs are not
//! subject to it). Virtualization.framework itself rejects a third macOS guest, so
//! that is the hard backstop.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::image::MacImageManager;
use super::vm::MacVm;
use crate::error::{CoreError, Result};
use crate::machine::MachineState;

/// Apple licenses at most two concurrently-running macOS guests per host.
const MAX_RUNNING_MACOS_GUESTS: usize = 2;

const MACHINE_RECORD_FILE: &str = "machine.json";
const DISK_FILE: &str = "disk.img";
const AUX_FILE: &str = "aux.img";
const HARDWARE_MODEL_FILE: &str = "hwmodel.bin";

/// Persisted record describing a macOS machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MacMachineRecord {
    name: String,
    image: String,
    cpus: u32,
    memory_mib: u64,
    created_at: DateTime<Utc>,
}

/// Configuration for creating a macOS machine from a base image.
#[derive(Debug, Clone)]
pub struct MacMachineConfig {
    /// Machine name (unique).
    pub name: String,
    /// Base image to clone.
    pub image: String,
    /// Number of CPUs.
    pub cpus: u32,
    /// Memory in MiB.
    pub memory_mib: u64,
}

/// Public view of a macOS machine.
#[derive(Debug, Clone)]
pub struct MacMachineInfo {
    /// Machine name.
    pub name: String,
    /// Base image it was cloned from.
    pub image: String,
    /// Number of CPUs.
    pub cpus: u32,
    /// Memory in MiB.
    pub memory_mib: u64,
    /// Current state (Running if a live VM is held, else Stopped).
    pub state: MachineState,
    /// Creation time.
    pub created_at: DateTime<Utc>,
}

/// Manages macOS guest machines: clone-from-base, boot, stop, remove.
pub struct MacMachineManager {
    images: MacImageManager,
    machines_dir: PathBuf,
    records: RwLock<HashMap<String, MacMachineRecord>>,
    running: RwLock<HashMap<String, MacVm>>,
}

impl MacMachineManager {
    /// Creates a manager rooted at `data_dir`.
    #[must_use]
    pub fn new(data_dir: &Path) -> Self {
        let machines_dir = data_dir.join("macos").join("machines");
        let records = Self::load_records(&machines_dir);
        Self {
            images: MacImageManager::new(data_dir),
            machines_dir,
            records: RwLock::new(records),
            running: RwLock::new(HashMap::new()),
        }
    }

    /// Returns the base-image manager.
    #[must_use]
    pub fn images(&self) -> &MacImageManager {
        &self.images
    }

    fn machine_dir(&self, name: &str) -> PathBuf {
        self.machines_dir.join(name)
    }

    fn load_records(machines_dir: &Path) -> HashMap<String, MacMachineRecord> {
        let mut records = HashMap::new();
        let Ok(entries) = std::fs::read_dir(machines_dir) else {
            return records;
        };
        for entry in entries.flatten() {
            let path = entry.path().join(MACHINE_RECORD_FILE);
            if !path.is_file() {
                continue;
            }
            match std::fs::read_to_string(&path)
                .ok()
                .and_then(|raw| serde_json::from_str::<MacMachineRecord>(&raw).ok())
            {
                Some(record) => {
                    records.insert(record.name.clone(), record);
                }
                None => tracing::warn!(
                    "skipping unreadable macOS machine record {}",
                    path.display()
                ),
            }
        }
        records
    }

    fn write_record(&self, record: &MacMachineRecord) -> Result<()> {
        let dir = self.machine_dir(&record.name);
        std::fs::create_dir_all(&dir)?;
        let json = serde_json::to_string_pretty(record)
            .map_err(|e| CoreError::macos(format!("serialize machine record: {e}")))?;
        std::fs::write(dir.join(MACHINE_RECORD_FILE), json)?;
        Ok(())
    }

    /// Creates a macOS machine by copy-on-write cloning `config.image`.
    ///
    /// # Errors
    /// Returns an error if a machine with the name exists, the base image is missing,
    /// or the clone/persist fails.
    pub fn create(&self, config: MacMachineConfig) -> Result<()> {
        let mut records = self.records.write().map_err(|_| CoreError::LockPoisoned)?;
        if records.contains_key(&config.name) {
            return Err(CoreError::already_exists(format!(
                "macOS machine '{}'",
                config.name
            )));
        }

        let dir = self.machine_dir(&config.name);
        let disks = self.images.clone_base(&config.image, &dir)?;
        // Keep the hardware model with the machine so it boots without the base image.
        std::fs::write(dir.join(HARDWARE_MODEL_FILE), &disks.hardware_model)?;

        let record = MacMachineRecord {
            name: config.name.clone(),
            image: config.image,
            cpus: config.cpus,
            memory_mib: config.memory_mib,
            created_at: Utc::now(),
        };
        self.write_record(&record)?;
        records.insert(config.name, record);
        Ok(())
    }

    /// Boots a macOS machine and waits until it is running.
    ///
    /// Enforces the per-host macOS-guest cap (counting only running macOS machines).
    ///
    /// # Errors
    /// Returns an error if the machine is unknown, already running, the cap is
    /// reached, or the VM fails to start.
    #[allow(
        clippy::future_not_send,
        reason = "boots a Virtualization.framework VM (!Send ObjC handles across await); driven on a single thread"
    )]
    pub async fn start(&self, name: &str) -> Result<()> {
        let record = {
            let records = self.records.read().map_err(|_| CoreError::LockPoisoned)?;
            records
                .get(name)
                .cloned()
                .ok_or_else(|| CoreError::not_found(format!("macOS machine '{name}'")))?
        };
        {
            let running = self.running.read().map_err(|_| CoreError::LockPoisoned)?;
            if running.contains_key(name) {
                return Err(CoreError::invalid_state(format!(
                    "macOS machine '{name}' is already running"
                )));
            }
            if running.len() >= MAX_RUNNING_MACOS_GUESTS {
                return Err(CoreError::macos(format!(
                    "at most {MAX_RUNNING_MACOS_GUESTS} macOS guests may run concurrently per host (Apple license)"
                )));
            }
        }

        let dir = self.machine_dir(name);
        let hardware_model = std::fs::read(dir.join(HARDWARE_MODEL_FILE))?;
        // The framework rejects a third macOS guest, so it backstops the cap above.
        let vm = MacVm::boot(
            &dir.join(DISK_FILE),
            &dir.join(AUX_FILE),
            &hardware_model,
            record.cpus,
            record.memory_mib,
        )
        .await?;

        let mut running = self.running.write().map_err(|_| CoreError::LockPoisoned)?;
        running.insert(name.to_string(), vm);
        Ok(())
    }

    /// Stops a running macOS machine.
    ///
    /// # Errors
    /// Returns an error if the machine is not running or cannot be stopped.
    #[allow(
        clippy::future_not_send,
        reason = "stops a Virtualization.framework VM (!Send ObjC handles across await); driven on a single thread"
    )]
    pub async fn stop(&self, name: &str) -> Result<()> {
        let vm = {
            let mut running = self.running.write().map_err(|_| CoreError::LockPoisoned)?;
            running.remove(name).ok_or_else(|| {
                CoreError::invalid_state(format!("macOS machine '{name}' is not running"))
            })?
        };
        vm.stop().await
    }

    /// Removes a macOS machine and its disks.
    ///
    /// # Errors
    /// Returns an error if the machine is running and `force` is false, or if
    /// stopping/removal fails.
    #[allow(
        clippy::future_not_send,
        reason = "may stop a Virtualization.framework VM (!Send ObjC handles across await); driven on a single thread"
    )]
    pub async fn remove(&self, name: &str, force: bool) -> Result<()> {
        let is_running = self
            .running
            .read()
            .map_err(|_| CoreError::LockPoisoned)?
            .contains_key(name);
        if is_running {
            if !force {
                return Err(CoreError::invalid_state(format!(
                    "macOS machine '{name}' is running (use force to remove)"
                )));
            }
            self.stop(name).await?;
        }

        let dir = self.machine_dir(name);
        if dir.exists() {
            std::fs::remove_dir_all(&dir)?;
        }
        self.records
            .write()
            .map_err(|_| CoreError::LockPoisoned)?
            .remove(name);
        Ok(())
    }

    /// Returns whether a machine is currently running.
    #[must_use]
    pub fn is_running(&self, name: &str) -> bool {
        self.running.read().is_ok_and(|r| r.contains_key(name))
    }

    /// Lists all macOS machines.
    #[must_use]
    pub fn list(&self) -> Vec<MacMachineInfo> {
        let Ok(records) = self.records.read() else {
            return Vec::new();
        };
        records
            .values()
            .map(|r| MacMachineInfo {
                name: r.name.clone(),
                image: r.image.clone(),
                cpus: r.cpus,
                memory_mib: r.memory_mib,
                state: if self.is_running(&r.name) {
                    MachineState::Running
                } else {
                    MachineState::Stopped
                },
                created_at: r.created_at,
            })
            .collect()
    }

    /// Returns one macOS machine by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<MacMachineInfo> {
        self.list().into_iter().find(|m| m.name == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_round_trips() {
        let record = MacMachineRecord {
            name: "ci-runner".into(),
            image: "sequoia".into(),
            cpus: 4,
            memory_mib: 8192,
            created_at: Utc::now(),
        };
        let json = serde_json::to_string(&record).unwrap();
        let back: MacMachineRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, back);
    }
}
