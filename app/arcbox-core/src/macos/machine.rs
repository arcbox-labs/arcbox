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
use super::{StagingGuard, lease, validate_name};
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

/// A machine's runtime slot.
///
/// The slot map is the single serialization point for machine lifecycles: every
/// transition (start, stop, remove) reserves the machine's slot before touching
/// its disks or record, so the per-host guest cap and mutual exclusion are both
/// enforced here. While a slot is held no other lifecycle operation can act on
/// the machine. Only [`MacMachineManager::stop_all`] (daemon shutdown) sweeps
/// held slots away; in-flight operations re-check their slot before finalizing
/// so a post-sweep state is never clobbered.
enum RunningSlot {
    /// Reserved while booting: occupies a guest slot but has no live VM yet.
    Starting,
    /// A booted, running VM.
    Running(MacVm),
    /// Reserved while an in-flight stop runs. The VZ guest may still be live,
    /// so the slot keeps occupying the guest cap and blocks a concurrent start
    /// from booting a second VM on the same disks.
    Stopping,
    /// Reserved while the machine's disks and record are being deleted.
    Removing,
}

impl RunningSlot {
    /// How this slot reads in a "cannot do that now" error.
    const fn describe(&self) -> &'static str {
        match self {
            Self::Starting => "still starting",
            Self::Running(_) => "running",
            Self::Stopping => "stopping",
            Self::Removing => "being removed",
        }
    }
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

    /// Directory holding a named machine's artifacts.
    ///
    /// # Errors
    /// Returns an error if `name` is not a single safe path component.
    fn machine_dir(&self, name: &str) -> Result<PathBuf> {
        validate_name(name)?;
        Ok(self.machines_dir.join(name))
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
        Self::write_record_in(&self.machine_dir(&record.name)?, record)
    }

    /// Serializes a machine record into an explicit directory (used by `create`
    /// to assemble a machine in a staging directory before renaming it live).
    fn write_record_in(dir: &Path, record: &MacMachineRecord) -> Result<()> {
        std::fs::create_dir_all(dir)?;
        let json = serde_json::to_string_pretty(record)
            .map_err(|e| CoreError::macos(format!("serialize machine record: {e}")))?;
        std::fs::write(dir.join(MACHINE_RECORD_FILE), json)?;
        Ok(())
    }

    /// Creates a macOS machine by copy-on-write cloning `config.image`.
    ///
    /// The instance is assembled in a unique staging directory and renamed into
    /// place atomically under the records lock, so concurrent creates of the same
    /// name cannot corrupt each other. `config.cpus`/`config.memory_mib` must meet
    /// the image's published minimums.
    ///
    /// # Errors
    /// Returns an error if the name is invalid, a machine with the name exists, the
    /// base image is missing, the requested resources are below the image minimums,
    /// or the clone/persist fails.
    pub fn create(&self, config: MacMachineConfig) -> Result<()> {
        let final_dir = self.machine_dir(&config.name)?;

        // Fast pre-check; the authoritative check happens under the write lock below.
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

        // Enforce the image's published resource minimums before the slow clone.
        let image = self.images.get(&config.image)?;
        if u64::from(config.cpus) < image.meta.minimum_cpu_count {
            return Err(CoreError::macos(format!(
                "image '{}' requires at least {} CPUs",
                config.image, image.meta.minimum_cpu_count
            )));
        }
        if config.memory_mib < image.meta.minimum_memory_mib {
            return Err(CoreError::macos(format!(
                "image '{}' requires at least {} MiB of memory",
                config.image, image.meta.minimum_memory_mib
            )));
        }

        // Assemble in a unique staging directory. Two concurrent creates of the
        // same name each stage independently, so the loser only ever removes its
        // own staging directory — never the winner's cloned disks. The guard
        // removes staging on any early return.
        let staging =
            self.machines_dir
                .join(format!(".create-{}-{}", config.name, uuid::Uuid::new_v4()));
        let mut guard = StagingGuard::new(staging.clone());
        let disks = image.clone_into(&staging)?;
        // Keep the hardware model and machine identifier with the machine so it boots
        // without the base image and with a stable identity across reboots.
        std::fs::write(staging.join(HARDWARE_MODEL_FILE), &disks.hardware_model)?;
        std::fs::write(staging.join(MACHINE_ID_FILE), &disks.machine_id)?;
        let record = MacMachineRecord {
            name: config.name.clone(),
            image: config.image,
            cpus: config.cpus,
            memory_mib: config.memory_mib,
            created_at: Utc::now(),
            mac_address: Some(generate_mac()),
        };
        Self::write_record_in(&staging, &record)?;

        // Land under the write lock: re-check, clear any stale orphan, rename, insert.
        let mut records = self.records.write().map_err(|_| CoreError::LockPoisoned)?;
        if records.contains_key(&config.name) {
            return Err(CoreError::already_exists(format!(
                "macOS machine '{}'",
                config.name
            )));
        }
        if final_dir.exists() {
            // An orphan from an earlier create that crashed before inserting.
            std::fs::remove_dir_all(&final_dir)?;
        }
        std::fs::rename(&staging, &final_dir)?;
        guard.disarm();
        records.insert(config.name, record);
        Ok(())
    }

    /// Boots a macOS machine and waits until it is running.
    ///
    /// Enforces the per-host macOS-guest cap (counting only running macOS machines).
    ///
    /// # Errors
    /// Returns an error if the machine is unknown, its slot is held (running,
    /// or an in-flight start/stop/remove), the cap is reached, or the VM fails
    /// to start.
    #[allow(
        clippy::future_not_send,
        reason = "boots a Virtualization.framework VM (!Send ObjC handles across await); driven on a single thread"
    )]
    pub async fn start(&self, name: &str) -> Result<()> {
        // Fast not-found before touching the slot map; the authoritative
        // re-check happens under the reservation below.
        if !self
            .records
            .read()
            .map_err(|_| CoreError::LockPoisoned)?
            .contains_key(name)
        {
            return Err(CoreError::not_found(format!("macOS machine '{name}'")));
        }

        // Atomically check the cap and reserve the slot before the multi-second
        // boot, so concurrent starts cannot exceed the cap and no concurrent
        // stop/remove can act on the machine while it boots.
        {
            let mut running = self.running.write().map_err(|_| CoreError::LockPoisoned)?;
            if let Some(slot) = running.get(name) {
                return Err(CoreError::invalid_state(format!(
                    "macOS machine '{name}' is {}",
                    slot.describe()
                )));
            }
            if running.len() >= MAX_RUNNING_MACOS_GUESTS {
                return Err(CoreError::macos(format!(
                    "at most {MAX_RUNNING_MACOS_GUESTS} macOS guests may run concurrently per host (Apple license)"
                )));
            }
            running.insert(name.to_string(), RunningSlot::Starting);
        }

        let booted = self.boot_reserved(name).await;

        let mut running = self.running.write().map_err(|_| CoreError::LockPoisoned)?;
        match booted {
            Ok(vm) => match running.get_mut(name) {
                Some(slot @ RunningSlot::Starting) => {
                    *slot = RunningSlot::Running(vm);
                    Ok(())
                }
                // Only stop_all (daemon shutdown) sweeps a held reservation:
                // the fresh VM dies with the process, and whatever occupies
                // the slot now belongs to a newer operation.
                _ => Err(CoreError::invalid_state(format!(
                    "macOS machine '{name}': daemon is shutting down"
                ))),
            },
            Err(e) => {
                // Release the reservation so a retry (and the cap) are not
                // wedged — unless stop_all already swept it.
                if matches!(running.get(name), Some(RunningSlot::Starting)) {
                    running.remove(name);
                }
                Err(e)
            }
        }
    }

    /// Re-validates the record and boots the VM for a machine whose `Starting`
    /// slot the caller holds. The reservation is what makes the re-read
    /// authoritative: a concurrent remove cannot delete the record or the
    /// machine directory while the slot is held.
    #[allow(
        clippy::future_not_send,
        reason = "boots a Virtualization.framework VM (!Send ObjC handles across await); driven on a single thread"
    )]
    async fn boot_reserved(&self, name: &str) -> Result<MacVm> {
        let record = {
            let records = self.records.read().map_err(|_| CoreError::LockPoisoned)?;
            records
                .get(name)
                .cloned()
                .ok_or_else(|| CoreError::not_found(format!("macOS machine '{name}'")))?
        };

        // Records written before MAC pinning have none persisted: mint one now
        // so the boot below can pin it and the machine keeps it from then on.
        // Runs under the reservation, so it cannot resurrect a directory a
        // concurrent remove is deleting.
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

        let dir = self.machine_dir(name)?;
        // The framework rejects a third macOS guest, so it backstops the cap
        // enforced by the caller's reservation.
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

    /// Stops a running macOS machine.
    ///
    /// If the stop fails, the machine stays tracked as running (the VZ guest may
    /// still be live), so the guest cap and [`list`](Self::list) remain accurate.
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
                Some(RunningSlot::Running(vm)) => {
                    // Leave a placeholder: the machine keeps occupying its
                    // guest slot while the stop is in flight, so the cap stays
                    // accurate and a concurrent start cannot boot a second VM
                    // on the same disks while the VZ guest may still be live.
                    running.insert(name.to_string(), RunningSlot::Stopping);
                    vm
                }
                Some(other) => {
                    // An in-flight operation owns the slot; keep its state.
                    let state = other.describe();
                    running.insert(name.to_string(), other);
                    return Err(CoreError::invalid_state(format!(
                        "macOS machine '{name}' is {state}"
                    )));
                }
                None => {
                    return Err(CoreError::invalid_state(format!(
                        "macOS machine '{name}' is not running"
                    )));
                }
            }
        };

        let stopped = vm.stop().await;

        let mut running = self.running.write().map_err(|_| CoreError::LockPoisoned)?;
        match stopped {
            Ok(()) => {
                // Clear our placeholder — unless stop_all already swept it.
                if matches!(running.get(name), Some(RunningSlot::Stopping)) {
                    running.remove(name);
                }
                Ok(())
            }
            Err(e) => {
                // Stop failed: the VZ guest may still hold a framework slot.
                // Restore the live slot so the guest cap and list() reflect it
                // — unless stop_all already swept the placeholder (the daemon
                // is exiting and the guest dies with the process).
                if matches!(running.get(name), Some(RunningSlot::Stopping)) {
                    running.insert(name.to_string(), RunningSlot::Running(vm));
                }
                Err(e)
            }
        }
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
        // Reserve the machine's slot before touching disk, so a concurrent
        // start cannot boot from files that are mid-deletion.
        let occupied = {
            let mut running = self.running.write().map_err(|_| CoreError::LockPoisoned)?;
            match running.get(name) {
                Some(slot) if !force => {
                    let hint = if matches!(slot, RunningSlot::Running(_)) {
                        " (use force to remove)"
                    } else {
                        ""
                    };
                    return Err(CoreError::invalid_state(format!(
                        "macOS machine '{name}' is {}{hint}",
                        slot.describe()
                    )));
                }
                Some(_) => true,
                None => {
                    running.insert(name.to_string(), RunningSlot::Removing);
                    false
                }
            }
        };
        if occupied {
            // Force: stop the guest first (fails cleanly if the machine is
            // still starting, stopping, or being removed), then claim the
            // freed slot.
            self.stop(name).await?;
            let mut running = self.running.write().map_err(|_| CoreError::LockPoisoned)?;
            if let Some(slot) = running.get(name) {
                // A concurrent start won the slot between the stop and here.
                return Err(CoreError::invalid_state(format!(
                    "macOS machine '{name}' is {}",
                    slot.describe()
                )));
            }
            running.insert(name.to_string(), RunningSlot::Removing);
        }

        let removed = self.delete_machine(name);

        // Release the reservation on success and failure alike — unless
        // stop_all already swept it.
        let mut running = self.running.write().map_err(|_| CoreError::LockPoisoned)?;
        if matches!(running.get(name), Some(RunningSlot::Removing)) {
            running.remove(name);
        }
        removed
    }

    /// Deletes a machine's directory and record. The caller must hold the
    /// machine's `Removing` slot.
    fn delete_machine(&self, name: &str) -> Result<()> {
        let dir = self.machine_dir(name)?;
        if dir.exists() {
            std::fs::remove_dir_all(&dir)?;
        }
        self.records
            .write()
            .map_err(|_| CoreError::LockPoisoned)?
            .remove(name);
        Ok(())
    }

    /// Returns whether a machine currently occupies a runtime slot (starting,
    /// running, stopping, or being removed).
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
            Some(RunningSlot::Stopping) => MachineState::Stopping,
            // Between disk deletion and record pruning, list() can still see
            // the record; the machine is no longer running.
            Some(RunningSlot::Removing) | None => MachineState::Stopped,
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
    /// while still running. Placeholder slots (starting/stopping/removing) have no live
    /// VM here and are simply discarded; their in-flight owners re-check the slot
    /// before finalizing, so the sweep cannot be clobbered.
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
                    _ => None,
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
    use super::super::MacImageMeta;
    use super::*;
    use tempfile::tempdir;

    /// Writes a minimal but clonable base image into the manager's registry.
    fn write_base_image(mgr: &MacMachineManager, name: &str, min_cpu: u64, min_mem: u64) {
        mgr.images()
            .write_meta(&MacImageMeta {
                name: name.into(),
                source: None,
                stream: None,
                version: None,
                os_version: None,
                os_build: None,
                runner_version: None,
                minimum_cpu_count: min_cpu,
                minimum_memory_mib: min_mem,
                disk_gb: 1,
                created_at: Utc::now(),
            })
            .unwrap();
        let dir = mgr.images().image_dir(name).unwrap();
        std::fs::write(dir.join("disk.img"), b"disk").unwrap();
        std::fs::write(dir.join("aux.img"), b"aux").unwrap();
        std::fs::write(dir.join("hwmodel.bin"), b"hw").unwrap();
        std::fs::write(dir.join("machine-id.bin"), b"id").unwrap();
    }

    fn config(name: &str, cpus: u32, memory_mib: u64) -> MacMachineConfig {
        MacMachineConfig {
            name: name.into(),
            image: "base".into(),
            cpus,
            memory_mib,
        }
    }

    /// Drives a `!Send` lifecycle future on a transient current-thread runtime
    /// (the same pattern the gRPC handlers use).
    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    }

    /// Reserves `name`'s runtime slot as if an operation were in flight.
    fn hold_slot(mgr: &MacMachineManager, name: &str, slot: RunningSlot) {
        mgr.running.write().unwrap().insert(name.to_string(), slot);
    }

    #[test]
    fn create_rejects_resources_below_image_minimums() {
        let dir = tempdir().unwrap();
        let mgr = MacMachineManager::new(dir.path());
        write_base_image(&mgr, "base", 2, 4096);

        assert!(mgr.create(config("ci", 1, 8192)).is_err()); // too few CPUs
        assert!(mgr.create(config("ci", 4, 1024)).is_err()); // too little memory
        assert!(mgr.get("ci").is_none()); // nothing recorded
    }

    #[test]
    fn create_conflict_keeps_the_existing_machine_disks() {
        let dir = tempdir().unwrap();
        let mgr = MacMachineManager::new(dir.path());
        write_base_image(&mgr, "base", 2, 4096);

        mgr.create(config("ci", 4, 8192)).unwrap();
        let disk = mgr.machine_dir("ci").unwrap().join(DISK_FILE);
        assert!(disk.exists());

        // A second create for the same name must fail without destroying the first.
        assert!(mgr.create(config("ci", 4, 8192)).is_err());
        assert!(disk.exists());
    }

    #[test]
    fn create_rejects_invalid_names() {
        let dir = tempdir().unwrap();
        let mgr = MacMachineManager::new(dir.path());
        write_base_image(&mgr, "base", 2, 4096);
        assert!(mgr.create(config("../escape", 4, 8192)).is_err());
    }

    #[test]
    fn lifecycle_refuses_a_machine_whose_slot_is_held() {
        let dir = tempdir().unwrap();
        let mgr = MacMachineManager::new(dir.path());
        write_base_image(&mgr, "base", 2, 4096);
        mgr.create(config("ci", 4, 8192)).unwrap();

        // A held slot blocks start, stop, and non-force remove, and the
        // holder's state survives the refused call.
        hold_slot(&mgr, "ci", RunningSlot::Removing);
        let err = block_on(mgr.start("ci")).unwrap_err().to_string();
        assert!(err.contains("being removed"), "{err}");
        let err = block_on(mgr.stop("ci")).unwrap_err().to_string();
        assert!(err.contains("being removed"), "{err}");
        let err = block_on(mgr.remove("ci", false)).unwrap_err().to_string();
        assert!(err.contains("being removed"), "{err}");
        assert!(mgr.is_running("ci"));

        // Force-remove of a still-starting machine fails through stop()
        // without deleting anything.
        hold_slot(&mgr, "ci", RunningSlot::Starting);
        let err = block_on(mgr.remove("ci", true)).unwrap_err().to_string();
        assert!(err.contains("still starting"), "{err}");
        assert!(mgr.machine_dir("ci").unwrap().join(DISK_FILE).exists());
        assert!(mgr.is_running("ci"));

        // A stop racing an in-flight stop is refused, not doubled.
        hold_slot(&mgr, "ci", RunningSlot::Stopping);
        let err = block_on(mgr.stop("ci")).unwrap_err().to_string();
        assert!(err.contains("stopping"), "{err}");
        assert!(mgr.is_running("ci"));
    }

    #[test]
    fn remove_releases_its_reservation() {
        let dir = tempdir().unwrap();
        let mgr = MacMachineManager::new(dir.path());
        write_base_image(&mgr, "base", 2, 4096);
        mgr.create(config("ci", 4, 8192)).unwrap();

        block_on(mgr.remove("ci", false)).unwrap();
        assert!(mgr.get("ci").is_none());
        assert!(!mgr.machine_dir("ci").unwrap().exists());
        // The Removing placeholder must not leak into the slot map.
        assert!(!mgr.is_running("ci"));

        // Removing an unknown machine stays idempotent and leaks no slot.
        block_on(mgr.remove("ghost", false)).unwrap();
        assert!(!mgr.is_running("ghost"));
    }

    #[test]
    fn failed_start_releases_the_reservation() {
        let dir = tempdir().unwrap();
        let mgr = MacMachineManager::new(dir.path());
        write_base_image(&mgr, "base", 2, 4096);
        mgr.create(config("ci", 4, 8192)).unwrap();

        // The fixture's hardware model is garbage, so the boot fails after
        // the slot is reserved; the reservation must be released so a retry
        // is not refused as "still starting".
        let err = block_on(mgr.start("ci")).unwrap_err().to_string();
        assert!(!err.contains("still starting"), "{err}");
        assert!(!mgr.is_running("ci"));
        let retry = block_on(mgr.start("ci")).unwrap_err().to_string();
        assert!(!retry.contains("still starting"), "{retry}");
    }

    #[test]
    fn placeholder_slots_count_against_the_guest_cap() {
        let dir = tempdir().unwrap();
        let mgr = MacMachineManager::new(dir.path());
        write_base_image(&mgr, "base", 2, 4096);
        mgr.create(config("ci", 4, 8192)).unwrap();

        hold_slot(&mgr, "other-a", RunningSlot::Starting);
        hold_slot(&mgr, "other-b", RunningSlot::Stopping);
        let err = block_on(mgr.start("ci")).unwrap_err().to_string();
        assert!(err.contains("at most 2"), "{err}");
    }

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
