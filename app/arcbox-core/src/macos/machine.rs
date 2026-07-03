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
use super::lease;
use super::vm::MacVm;
use crate::error::{CoreError, Result};
use crate::machine::MachineState;

/// Apple licenses at most two concurrently-running macOS guests per host.
const MAX_RUNNING_MACOS_GUESTS: usize = 2;

const MACHINE_RECORD_FILE: &str = "machine.json";
const DISK_FILE: &str = "disk.img";
const AUX_FILE: &str = "aux.img";
const HARDWARE_MODEL_FILE: &str = "hwmodel.bin";
const MACHINE_ID_FILE: &str = "machine-id.bin";

/// Persisted record describing a macOS machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MacMachineRecord {
    name: String,
    image: String,
    cpus: u32,
    memory_mib: u64,
    created_at: DateTime<Utc>,
    /// MAC address pinned to the guest's NAT interface. Stable across
    /// reboots so the guest's DHCP lease identifies it (see [`lease`]).
    /// `None` only for records written before the field existed; `start`
    /// backfills it.
    #[serde(default)]
    mac_address: Option<String>,
}

/// Generates a random locally-administered unicast MAC address.
fn generate_mac() -> String {
    let mut b: [u8; 6] = uuid::Uuid::new_v4().into_bytes()[..6]
        .try_into()
        .expect("slice of length 6");
    // Locally administered (bit 1), unicast (bit 0 clear).
    b[0] = (b[0] | 0x02) & 0xFE;
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5]
    )
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
    /// MAC address of the guest's NAT interface. `None` only for machines
    /// created before MAC pinning that have not been started since.
    pub mac_address: Option<String>,
    /// IPv4 address from the guest's DHCP lease. `None` unless the machine
    /// is running and has acquired a lease.
    pub ip_address: Option<String>,
}

/// A machine's runtime slot. A slot is reserved (`Starting`) before the VM boots so
/// the per-host guest cap is enforced atomically across the multi-second boot, then
/// replaced by the live VM (`Running`).
enum RunningSlot {
    /// Reserved while booting: occupies a guest slot but has no live VM yet.
    Starting,
    /// A booted, running VM.
    Running(MacVm),
}

/// Manages macOS guest machines: clone-from-base, boot, stop, remove.
pub struct MacMachineManager {
    images: MacImageManager,
    machines_dir: PathBuf,
    records: RwLock<HashMap<String, MacMachineRecord>>,
    running: RwLock<HashMap<String, RunningSlot>>,
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
        // Pre-check under a short read lock, then clone (slow file I/O) without holding
        // any lock, then re-check on insert to settle a lost create/create race.
        if self
            .records
            .read()
            .map_err(|_| CoreError::LockPoisoned)?
            .contains_key(&config.name)
        {
            return Err(CoreError::already_exists(format!(
                "macOS machine '{}'",
                config.name
            )));
        }

        let dir = self.machine_dir(&config.name);
        let disks = self.images.clone_base(&config.image, &dir)?;
        // Keep the hardware model and machine identifier with the machine so it boots
        // without the base image and with a stable identity across reboots.
        std::fs::write(dir.join(HARDWARE_MODEL_FILE), &disks.hardware_model)?;
        std::fs::write(dir.join(MACHINE_ID_FILE), &disks.machine_id)?;

        let record = MacMachineRecord {
            name: config.name.clone(),
            image: config.image,
            cpus: config.cpus,
            memory_mib: config.memory_mib,
            created_at: Utc::now(),
            mac_address: Some(generate_mac()),
        };
        self.write_record(&record)?;

        let mut records = self.records.write().map_err(|_| CoreError::LockPoisoned)?;
        if records.contains_key(&config.name) {
            drop(records);
            let _ = std::fs::remove_dir_all(&dir);
            return Err(CoreError::already_exists(format!(
                "macOS machine '{}'",
                config.name
            )));
        }
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

        // Records written before MAC pinning have none persisted: mint one now
        // so the boot below can pin it and the machine keeps it from then on.
        let mac_address = match record.mac_address.clone() {
            Some(mac) => mac,
            None => {
                let mac = generate_mac();
                let record = MacMachineRecord {
                    mac_address: Some(mac.clone()),
                    ..record.clone()
                };
                self.write_record(&record)?;
                self.records
                    .write()
                    .map_err(|_| CoreError::LockPoisoned)?
                    .insert(name.to_owned(), record);
                mac
            }
        };

        // Atomically check the cap and reserve a slot before the multi-second boot, so
        // concurrent starts cannot both pass the check and exceed the cap.
        {
            let mut running = self.running.write().map_err(|_| CoreError::LockPoisoned)?;
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
            running.insert(name.to_string(), RunningSlot::Starting);
        }

        let dir = self.machine_dir(name);
        // The framework rejects a third macOS guest, so it backstops the cap above.
        let booted = async {
            let hardware_model = std::fs::read(dir.join(HARDWARE_MODEL_FILE))?;
            let machine_id = std::fs::read(dir.join(MACHINE_ID_FILE))?;
            MacVm::boot(
                &dir.join(DISK_FILE),
                &dir.join(AUX_FILE),
                &hardware_model,
                &machine_id,
                &mac_address,
                record.cpus,
                record.memory_mib,
            )
            .await
        }
        .await;

        let mut running = self.running.write().map_err(|_| CoreError::LockPoisoned)?;
        match booted {
            Ok(vm) => {
                running.insert(name.to_string(), RunningSlot::Running(vm));
                Ok(())
            }
            Err(e) => {
                // Release the reservation so a retry (and the cap) are not wedged.
                running.remove(name);
                Err(e)
            }
        }
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
            match running.remove(name) {
                Some(RunningSlot::Running(vm)) => vm,
                Some(slot @ RunningSlot::Starting) => {
                    // Mid-boot: keep the reservation; start() will finalize it.
                    running.insert(name.to_string(), slot);
                    return Err(CoreError::invalid_state(format!(
                        "macOS machine '{name}' is still starting"
                    )));
                }
                None => {
                    return Err(CoreError::invalid_state(format!(
                        "macOS machine '{name}' is not running"
                    )));
                }
            }
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

    /// Returns whether a machine currently occupies a runtime slot (starting or
    /// running).
    #[must_use]
    pub fn is_running(&self, name: &str) -> bool {
        self.running.read().is_ok_and(|r| r.contains_key(name))
    }

    /// Maps a machine's runtime slot to its reported state.
    fn state_of(&self, name: &str) -> MachineState {
        let Ok(running) = self.running.read() else {
            return MachineState::Stopped;
        };
        match running.get(name) {
            Some(RunningSlot::Running(_)) => MachineState::Running,
            Some(RunningSlot::Starting) => MachineState::Starting,
            None => MachineState::Stopped,
        }
    }

    /// Builds the public view of a record, resolving its current runtime state
    /// and — for a running guest — the IP of its DHCP lease.
    fn info(&self, record: &MacMachineRecord) -> MacMachineInfo {
        let state = self.state_of(&record.name);
        let ip_address = match (&record.mac_address, state) {
            (Some(mac), MachineState::Running) => lease::resolve_ip(mac),
            _ => None,
        };
        MacMachineInfo {
            name: record.name.clone(),
            image: record.image.clone(),
            cpus: record.cpus,
            memory_mib: record.memory_mib,
            state,
            created_at: record.created_at,
            mac_address: record.mac_address.clone(),
            ip_address,
        }
    }

    /// Lists all macOS machines.
    #[must_use]
    pub fn list(&self) -> Vec<MacMachineInfo> {
        let Ok(records) = self.records.read() else {
            return Vec::new();
        };
        records.values().map(|r| self.info(r)).collect()
    }

    /// Returns one macOS machine by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<MacMachineInfo> {
        let records = self.records.read().ok()?;
        records.get(name).map(|r| self.info(r))
    }

    /// Stops every running macOS guest, returning the per-machine errors that occur.
    ///
    /// Used on daemon shutdown so framework VMs are stopped cleanly rather than dropped
    /// while still running. Reserved (still-starting) slots have no live VM and are
    /// simply discarded.
    #[allow(
        clippy::future_not_send,
        reason = "stops Virtualization.framework VMs (!Send ObjC handles across await); driven on a single thread"
    )]
    pub async fn stop_all(&self) -> Vec<(String, CoreError)> {
        let vms: Vec<(String, MacVm)> = {
            let Ok(mut running) = self.running.write() else {
                return vec![(String::from("<all>"), CoreError::LockPoisoned)];
            };
            running
                .drain()
                .filter_map(|(name, slot)| match slot {
                    RunningSlot::Running(vm) => Some((name, vm)),
                    RunningSlot::Starting => None,
                })
                .collect()
        };
        let mut errors = Vec::new();
        for (name, vm) in vms {
            if let Err(e) = vm.stop().await {
                errors.push((name, e));
            }
        }
        errors
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
            mac_address: Some("06:aa:bb:cc:dd:0e".into()),
        };
        let json = serde_json::to_string(&record).unwrap();
        let back: MacMachineRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, back);
    }

    #[test]
    fn record_without_mac_still_loads() {
        // Records persisted before MAC pinning have no mac_address field.
        let json = r#"{"name":"old","image":"sequoia","cpus":2,"memory_mib":4096,
                       "created_at":"2026-07-01T00:00:00Z"}"#;
        let record: MacMachineRecord = serde_json::from_str(json).unwrap();
        assert_eq!(record.mac_address, None);
    }

    #[test]
    fn generated_mac_is_locally_administered_unicast() {
        for _ in 0..64 {
            let mac = generate_mac();
            assert_eq!(mac.len(), 17);
            let first = u8::from_str_radix(&mac[..2], 16).unwrap();
            assert_eq!(first & 0x02, 0x02, "locally administered bit: {mac}");
            assert_eq!(first & 0x01, 0x00, "unicast bit: {mac}");
        }
    }
}
