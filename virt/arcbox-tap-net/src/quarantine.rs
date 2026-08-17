use std::collections::{HashMap, HashSet};
use std::io::Write as _;
use std::net::Ipv4Addr;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

use arcbox_vm_driver::VmId;
use serde::{Deserialize, Serialize};
use tracing::debug;
use uuid::Uuid;

#[cfg(target_os = "linux")]
use super::tap;
use super::{NetworkAllocation, TapNetwork, mac_from_vm_id, tap_name_from_ip};
use crate::error::{Result, TapNetError};

impl TapNetwork {
    /// Deactivate a sandbox TAP while retaining its IP until host forwarding
    /// cleanup is confirmed.
    pub fn quarantine_checked(&self, sandbox_id: &str, alloc: &NetworkAllocation) -> Result<()> {
        let Some(dir) = self.quarantine_dir.as_deref() else {
            return self.release_checked(alloc);
        };
        let mut allocation = alloc.clone();
        if allocation.cleanup_token.is_empty() {
            allocation.cleanup_token = Uuid::new_v4().to_string();
        }
        let mut quarantined = self.quarantined.lock().unwrap();
        if let Some(existing) = quarantined.get(sandbox_id) {
            if !same_allocation(existing, alloc) {
                return Err(TapNetError::Unavailable(format!(
                    "sandbox {sandbox_id} has a different quarantined network allocation"
                )));
            }
        } else {
            write_quarantine(dir, sandbox_id, &allocation)?;
            quarantined.insert(sandbox_id.to_owned(), allocation);
            self.allocated
                .lock()
                .unwrap()
                .insert(u32::from(alloc.ip_address));
        }

        // Translation state does not die with the device; remove it first
        // (tolerant of absence, so legacy TAPs are a no-op).
        #[cfg(target_os = "linux")]
        self.deactivate_translation(alloc)?;
        #[cfg(target_os = "linux")]
        tap::destroy_checked(&alloc.tap_name)?;
        debug!(
            sandbox_id,
            tap = %alloc.tap_name,
            ip = %alloc.ip_address,
            "sandbox network quarantined"
        );
        Ok(())
    }

    /// Recycle a quarantined IP after guest DNAT and host listeners are gone.
    pub fn validate_quarantine(&self, sandbox_id: &str, token: &str) -> Result<NetworkAllocation> {
        let quarantined = self.quarantined.lock().unwrap();
        let allocation = quarantined
            .get(sandbox_id)
            .ok_or_else(|| TapNetError::WrongState {
                id: sandbox_id.to_owned(),
                expected: "cleanup awaiting host finalization".into(),
                actual: "no pending cleanup".into(),
            })?;
        if allocation.cleanup_token != token {
            return Err(TapNetError::WrongState {
                id: sandbox_id.to_owned(),
                expected: format!("cleanup token {}", allocation.cleanup_token),
                actual: token.to_owned(),
            });
        }
        Ok(allocation.clone())
    }

    /// Recycle one exact quarantined generation.
    pub fn finalize_quarantine(&self, sandbox_id: &str, token: &str) -> Result<()> {
        let mut quarantined = self.quarantined.lock().unwrap();
        let Some(alloc) = quarantined.get(sandbox_id) else {
            return Err(TapNetError::WrongState {
                id: sandbox_id.to_owned(),
                expected: "cleanup awaiting host finalization".into(),
                actual: "no pending cleanup".into(),
            });
        };
        if alloc.cleanup_token != token {
            return Err(TapNetError::WrongState {
                id: sandbox_id.to_owned(),
                expected: format!("cleanup token {}", alloc.cleanup_token),
                actual: token.to_owned(),
            });
        }

        #[cfg(target_os = "linux")]
        tap::destroy_checked(&alloc.tap_name)?;
        if let Some(dir) = self.quarantine_dir.as_deref() {
            remove_quarantine(dir, sandbox_id)?;
        }
        let ip = u32::from(alloc.ip_address);
        quarantined.remove(sandbox_id);
        self.allocated.lock().unwrap().remove(&ip);
        if quarantined.is_empty() && self.startup_host_cleaned.load(Ordering::Acquire) {
            self.startup_barrier.store(false, Ordering::Release);
            self.startup_changed.send_replace(());
        }
        debug!(sandbox_id, ip = %Ipv4Addr::from(ip), "sandbox network finalized");
        Ok(())
    }

    /// IDs awaiting host-side forwarding cleanup.
    pub fn pending_quarantines(&self) -> Vec<(String, String)> {
        self.quarantined
            .lock()
            .unwrap()
            .iter()
            .map(|(id, allocation)| (id.clone(), allocation.cleanup_token.clone()))
            .collect()
    }

    /// Record that the owner has finished reconciling its own durable state
    /// (replaying leftover VMs into quarantine). Startup-cleanup validation
    /// refuses every token until then, so a host cannot finalize a sweep
    /// whose quarantines are still being discovered.
    pub fn mark_reconciled(&self) {
        self.startup_reconciled.store(true, Ordering::Release);
    }

    /// The token gating this process generation's startup sweep, while the
    /// host-side half of that sweep is still pending; `None` once the host
    /// finalized it or when this manager keeps no ledger.
    pub fn startup_cleanup_token(&self) -> Option<String> {
        (self.startup_barrier.load(Ordering::Acquire)
            && !self.startup_host_cleaned.load(Ordering::Acquire))
        .then(|| self.startup_token.clone())
    }

    /// Check that `token` names the pending startup cleanup of this process
    /// generation and that reconciliation has finished.
    ///
    /// The two refusals are different answers and must not be folded
    /// together. Before [`Self::mark_reconciled`] the owner is still
    /// replaying what a previous process left, so no token — not even the
    /// current one — can finalize a sweep whose contents are still being
    /// discovered: retry-later, and the same token will do. Everything else
    /// is a token that does not name this generation, which no retry fixes.
    pub fn validate_startup_cleanup(&self, token: &str) -> Result<()> {
        if !self.startup_reconciled.load(Ordering::Acquire) {
            return Err(TapNetError::Unavailable(
                "sandbox startup cleanup is awaiting the owner's durable-state replay".into(),
            ));
        }
        if !self.startup_barrier.load(Ordering::Acquire)
            || self.startup_host_cleaned.load(Ordering::Acquire)
            || token != self.startup_token
        {
            return Err(TapNetError::WrongState {
                id: "startup".into(),
                expected: "current sandbox startup cleanup generation".into(),
                actual: token.to_owned(),
            });
        }
        Ok(())
    }

    /// Mark the startup sweep's host-side cleanup done and open the
    /// allocation gate — refused while any per-VM quarantine is still
    /// pending, since those addresses would otherwise be handed out again.
    pub fn finalize_startup_cleanup(&self, token: &str) -> Result<()> {
        self.validate_startup_cleanup(token)?;
        if !self.quarantined.lock().unwrap().is_empty() {
            return Err(TapNetError::Unavailable(
                "sandbox cleanup generations remain pending".into(),
            ));
        }
        self.startup_host_cleaned.store(true, Ordering::Release);
        self.startup_barrier.store(false, Ordering::Release);
        self.startup_changed.send_replace(());
        Ok(())
    }

    /// Wait until the startup gate is open: no startup cleanup and no
    /// replayed quarantine of this generation is pending.
    pub async fn wait_startup_cleanup_complete(&self) {
        let mut changed = self.startup_changed.subscribe();
        while self.startup_barrier.load(Ordering::Acquire) {
            changed
                .changed()
                .await
                .expect("startup notification sender lives with the network manager");
        }
    }

    /// Refuse with [`TapNetError::Unavailable`] while the startup gate is
    /// closed; the non-blocking counterpart of
    /// [`Self::wait_startup_cleanup_complete`].
    pub fn ensure_startup_cleanup_complete(&self) -> Result<()> {
        if self.startup_barrier.load(Ordering::Acquire) {
            return Err(TapNetError::Unavailable(
                "sandbox startup cleanup is awaiting host finalization".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
struct NetworkQuarantine {
    id: String,
    allocation: NetworkAllocation,
}

pub fn load_quarantines(
    dir: &Path,
    base: Ipv4Addr,
    prefix_len: u8,
    gateway: Ipv4Addr,
) -> Result<HashMap<String, NetworkAllocation>> {
    let existed = dir.try_exists()?;
    std::fs::create_dir_all(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    if !existed {
        let parent = dir.parent().ok_or_else(|| {
            TapNetError::Network(format!(
                "sandbox network quarantine directory has no parent: {}",
                dir.display()
            ))
        })?;
        // The sandbox data root is created durably before TapNetwork.
        // Syncing that existing parent makes this new directory entry durable.
        std::fs::File::open(parent)?.sync_all()?;
    }
    let mut quarantined = HashMap::new();
    let mut tokens = HashSet::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let path = entry.path();
        match path.extension().and_then(|value| value.to_str()) {
            // A staging file (`.{id}-{uuid}.tmp`) a crash left mid-write. The
            // skip is keyed on that shape, not on a leading dot: a `VmId` may
            // start with one, and its marker `.{id}.json` must load.
            Some("tmp") => continue,
            Some("json") => {}
            _ => {
                return Err(TapNetError::Network(format!(
                    "unexpected sandbox network quarantine file {}",
                    path.display()
                )));
            }
        }
        let marker: NetworkQuarantine = serde_json::from_slice(&std::fs::read(&path)?)?;
        validate_id(&marker.id)?;
        if Uuid::parse_str(&marker.allocation.cleanup_token).is_err() {
            return Err(TapNetError::Network(format!(
                "sandbox network quarantine {} has an invalid cleanup token",
                marker.id
            )));
        }
        validate_allocation(&marker.id, &marker.allocation, base, prefix_len, gateway)?;
        if !tokens.insert(marker.allocation.cleanup_token.clone()) {
            return Err(TapNetError::Network(format!(
                "duplicate sandbox network quarantine token for {}",
                marker.id
            )));
        }
        if path.file_stem().and_then(|value| value.to_str()) != Some(marker.id.as_str()) {
            return Err(TapNetError::Network(format!(
                "sandbox network quarantine filename does not match {}",
                marker.id
            )));
        }
        if quarantined
            .insert(marker.id.clone(), marker.allocation)
            .is_some()
        {
            return Err(TapNetError::Network(format!(
                "duplicate sandbox network quarantine {}",
                marker.id
            )));
        }
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(quarantined)
}

/// Whether `allocation` is one this network could have written for `id`:
/// an allocatable address of this pool, with the prefix, gateway, TAP name
/// and MAC that `reserve` derives. Applied to every record read back from
/// durable state — the ledger's markers at load, and a journaled lease at
/// [`TapNetwork::adopt`] — since neither is this process's own memory.
pub fn validate_allocation(
    id: &str,
    allocation: &NetworkAllocation,
    base: Ipv4Addr,
    prefix_len: u8,
    gateway: Ipv4Addr,
) -> Result<()> {
    let host_bits = 32 - u32::from(prefix_len);
    let mask = !((1u32 << host_bits) - 1);
    let network = u32::from(base) & mask;
    let ip = u32::from(allocation.ip_address);
    let broadcast = network | !mask;
    if ip & mask != network || ip <= network + 1 || ip == u32::from(gateway) || ip == broadcast {
        return Err(TapNetError::Network(format!(
            "sandbox network record {id} has non-allocatable IP {}",
            allocation.ip_address
        )));
    }
    if allocation.prefix_len != prefix_len
        || allocation.gateway != gateway
        || allocation.tap_name != tap_name_from_ip(allocation.ip_address)
        || allocation.mac_address != mac_from_vm_id(id).to_string()
    {
        return Err(TapNetError::Network(format!(
            "sandbox network record {id} metadata does not match the current network"
        )));
    }
    Ok(())
}

fn same_allocation(existing: &NetworkAllocation, requested: &NetworkAllocation) -> bool {
    if existing == requested {
        return true;
    }
    if requested.cleanup_token.is_empty() {
        let mut requested = requested.clone();
        requested.cleanup_token.clone_from(&existing.cleanup_token);
        return existing == &requested;
    }
    false
}

pub fn write_quarantine(dir: &Path, sandbox_id: &str, alloc: &NetworkAllocation) -> Result<()> {
    validate_id(sandbox_id)?;
    let marker = NetworkQuarantine {
        id: sandbox_id.to_owned(),
        allocation: alloc.clone(),
    };
    let bytes = serde_json::to_vec_pretty(&marker)?;
    let temp = dir.join(format!(".{sandbox_id}-{}.tmp", Uuid::new_v4()));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    std::fs::rename(&temp, quarantine_path(dir, sandbox_id))?;
    std::fs::File::open(dir)?.sync_all()?;
    Ok(())
}

fn remove_quarantine(dir: &Path, sandbox_id: &str) -> Result<()> {
    match std::fs::remove_file(quarantine_path(dir, sandbox_id)) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    std::fs::File::open(dir)?.sync_all()?;
    Ok(())
}

fn quarantine_path(dir: &Path, sandbox_id: &str) -> PathBuf {
    dir.join(format!("{sandbox_id}.json"))
}

/// The network's id contract is the driver port's: a VM id is a `VmId`
/// (`[A-Za-z0-9._-]`, non-empty, at most [`VmId::MAX_LEN`] bytes, not `.`
/// or `..`), which also makes it a safe ledger path component
/// (`{id}.json`; a leading dot is fine — the loader skips staging files by
/// their `.tmp` extension, not by dotfile). Checked where an id enters the
/// network (`reserve`), on
/// every ledger write, and on every ledger load, so a reserved address can
/// always be quarantined, every entry the ledger holds is one the port can
/// name, and a file from outside the contract fails at load with its id in
/// the message rather than lingering as a quarantine `NetworkReconcile`
/// could never list or finalize.
pub fn validate_id(id: &str) -> Result<()> {
    VmId::new(id)
        .map(drop)
        .map_err(|error| TapNetError::Network(error.to_string()))
}
