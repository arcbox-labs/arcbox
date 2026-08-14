use std::ffi::OsStr;
use std::fs::{self, File};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::warn;
use uuid::Uuid;

use arcbox_atomic_file::AtomicWriteError;

use super::types::IdleAction;
use super::{SandboxId, SandboxSpec, validate_id};
use crate::error::{Result, VmmError};

const RECORD_VERSION: u32 = 1;
const RECORDS_DIR: &str = "sandbox-records";

/// Durable control-plane phase for one sandbox generation.
///
/// Workload execution remains transient: a running workload keeps the durable
/// phase at `Ready`, avoiding record writes on the execution hot path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum SandboxPhase {
    Creating,
    Starting,
    Ready,
    Stopping,
    Stopped,
    Failed,
    Removing,
    /// Pause in progress: checkpoint taken or being taken, runtime
    /// resources not yet fully released.
    Pausing,
    /// Checkpointed with resources released; `pause_snapshot_id` names the
    /// catalog entry a Resume restores from (CORE-21).
    Paused,
    /// Resume in progress: runtime resources are being re-created.
    Resuming,
}

/// The stable result returned once a provisioning request has been accepted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct SandboxProvisionOutcome {
    pub(super) ip_address: String,
}

/// Versioned durable state for one sandbox generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct SandboxRecord {
    version: u32,
    pub(super) id: SandboxId,
    pub(super) generation: Uuid,
    pub(super) request_key: String,
    pub(super) effective_spec: SandboxSpec,
    pub(super) phase: SandboxPhase,
    pub(super) provision_outcome: Option<SandboxProvisionOutcome>,
    pub(super) created_at: DateTime<Utc>,
    pub(super) error: Option<String>,
    /// Catalog id of the internal pause checkpoint. Set while the record is
    /// `Paused`/`Resuming` so a Resume after an agent restart still finds
    /// its snapshot; cleared when the sandbox is `Ready` again.
    #[serde(default)]
    pub(super) pause_snapshot_id: Option<String>,
    /// When the sandbox reached `Paused` (None otherwise).
    #[serde(default)]
    pub(super) paused_at: Option<DateTime<Utc>>,
    /// When the hard maximum lifetime fires (None = no limit). Seeded from
    /// `effective_spec.ttl_seconds`; replaced by `SetLifecycle` (CORE-60).
    /// Survives `redact_runtime_inputs` — unlike the seed seconds, the
    /// deadline is durable lifecycle state, not a runtime input.
    #[serde(default)]
    pub(super) ttl_deadline: Option<DateTime<Utc>>,
}

/// Result of reserving a durable provisioning intent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ProvisionIntent {
    Created(SandboxRecord),
    Resume(SandboxRecord),
    Replay(SandboxRecord),
    Blocked(SandboxRecord),
}

/// Generation-checked lifecycle update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum SandboxTransition {
    Starting(SandboxProvisionOutcome),
    ReadyWithOutcome(SandboxProvisionOutcome),
    Ready,
    Stopping,
    Stopped,
    Failed(String),
    Removing,
    Pausing,
    Paused { snapshot_id: String },
    Resuming,
}

impl SandboxTransition {
    fn phase(&self) -> SandboxPhase {
        match self {
            Self::Starting(_) => SandboxPhase::Starting,
            Self::ReadyWithOutcome(_) | Self::Ready => SandboxPhase::Ready,
            Self::Stopping => SandboxPhase::Stopping,
            Self::Stopped => SandboxPhase::Stopped,
            Self::Failed(_) => SandboxPhase::Failed,
            Self::Removing => SandboxPhase::Removing,
            Self::Pausing => SandboxPhase::Pausing,
            Self::Paused { .. } => SandboxPhase::Paused,
            Self::Resuming => SandboxPhase::Resuming,
        }
    }
}

impl SandboxRecord {
    fn new(id: &str, request_key: &str, effective_spec: SandboxSpec) -> Self {
        let created_at = Utc::now();
        let ttl_deadline = (effective_spec.ttl_seconds > 0)
            .then(|| created_at + chrono::Duration::seconds(i64::from(effective_spec.ttl_seconds)));

        Self {
            version: RECORD_VERSION,
            id: id.to_owned(),
            generation: Uuid::new_v4(),
            request_key: request_key.to_owned(),
            effective_spec,
            phase: SandboxPhase::Creating,
            provision_outcome: None,
            created_at,
            error: None,
            pause_snapshot_id: None,
            paused_at: None,
            ttl_deadline,
        }
    }

    fn apply(&mut self, transition: SandboxTransition) -> Result<()> {
        let next = transition.phase();
        let atomic_ready = matches!(&transition, SandboxTransition::ReadyWithOutcome(_))
            && self.phase == SandboxPhase::Creating;
        if !atomic_ready && !self.phase.can_transition_to(next) {
            return Err(VmmError::WrongState {
                id: self.id.clone(),
                expected: format!("a valid transition from {}", self.phase.as_str()),
                actual: next.as_str().to_owned(),
            });
        }

        match transition {
            SandboxTransition::Starting(outcome) => {
                if let Some(existing) = &self.provision_outcome
                    && existing != &outcome
                {
                    return Err(VmmError::WrongState {
                        id: self.id.clone(),
                        expected: format!("provision outcome {existing:?}"),
                        actual: format!("provision outcome {outcome:?}"),
                    });
                }
                self.phase = SandboxPhase::Starting;
                self.provision_outcome = Some(outcome);
                self.error = None;
            }
            SandboxTransition::ReadyWithOutcome(outcome) => {
                if let Some(existing) = &self.provision_outcome
                    && existing != &outcome
                {
                    return Err(VmmError::WrongState {
                        id: self.id.clone(),
                        expected: format!("provision outcome {existing:?}"),
                        actual: format!("provision outcome {outcome:?}"),
                    });
                }
                self.phase = SandboxPhase::Ready;
                self.provision_outcome = Some(outcome);
                self.error = None;
                self.redact_runtime_inputs();
            }
            SandboxTransition::Ready => {
                self.phase = SandboxPhase::Ready;
                self.error = None;
                self.pause_snapshot_id = None;
                self.paused_at = None;
                self.redact_runtime_inputs();
            }
            SandboxTransition::Stopping => {
                self.phase = SandboxPhase::Stopping;
                self.error = None;
                self.redact_runtime_inputs();
            }
            SandboxTransition::Stopped => {
                self.phase = SandboxPhase::Stopped;
                self.error = None;
            }
            SandboxTransition::Failed(error) => {
                self.phase = SandboxPhase::Failed;
                self.error = Some(error);
                self.redact_runtime_inputs();
            }
            SandboxTransition::Removing => {
                self.phase = SandboxPhase::Removing;
                self.redact_runtime_inputs();
            }
            SandboxTransition::Pausing => {
                self.phase = SandboxPhase::Pausing;
                self.error = None;
            }
            SandboxTransition::Paused { snapshot_id } => {
                self.phase = SandboxPhase::Paused;
                self.pause_snapshot_id = Some(snapshot_id);
                // Stamped once per pause, not once per transition: a failed
                // resume parks the record back at `Paused`, and overwriting
                // here would report the sandbox as freshly paused — and push
                // the time forward again on every retry. `Ready` clears the
                // stamp, so a genuine re-pause still gets a fresh one.
                self.paused_at.get_or_insert_with(Utc::now);
                self.error = None;
            }
            SandboxTransition::Resuming => {
                self.phase = SandboxPhase::Resuming;
                self.error = None;
            }
        }
        Ok(())
    }

    fn redact_runtime_inputs(&mut self) {
        self.effective_spec.kernel.clear();
        self.effective_spec.rootfs.clear();
        self.effective_spec.boot_args.clear();
        self.effective_spec.cmd.clear();
        self.effective_spec.env.clear();
        self.effective_spec.working_dir.clear();
        self.effective_spec.user.clear();
        self.effective_spec.mounts.clear();
        self.effective_spec.ttl_seconds = 0;
        self.effective_spec.ssh_public_key = None;
    }
}

impl SandboxPhase {
    fn can_transition_to(self, next: Self) -> bool {
        self == next
            || matches!(
                (self, next),
                (
                    Self::Creating,
                    Self::Starting | Self::Failed | Self::Removing
                ) | (
                    Self::Starting,
                    Self::Ready | Self::Stopping | Self::Failed | Self::Removing
                ) | (
                    Self::Ready,
                    Self::Stopping | Self::Pausing | Self::Failed | Self::Removing
                ) | (
                    Self::Stopping,
                    Self::Stopped | Self::Failed | Self::Removing
                ) | (Self::Stopped | Self::Failed, Self::Removing)
                    // A failed pause reverts to Ready and a completed one
                    // parks at Paused; a resume mirrors that exactly (a
                    // failed one unwinds back to Paused).
                    | (
                        Self::Pausing | Self::Resuming,
                        Self::Paused | Self::Ready | Self::Failed | Self::Removing
                    )
                    | (Self::Paused, Self::Resuming | Self::Failed | Self::Removing)
            )
    }

    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Creating => "creating",
            Self::Starting => "starting",
            Self::Ready => "ready",
            Self::Stopping => "stopping",
            Self::Stopped => "stopped",
            Self::Failed => "failed",
            Self::Removing => "removing",
            Self::Pausing => "pausing",
            Self::Paused => "paused",
            Self::Resuming => "resuming",
        }
    }
}

/// A filesystem mutation whose rename/unlink happened, but whose directory
/// fsync may have failed. Callers must treat `value` as the visible state and
/// may surface `durability_error` as an unconfirmed result.
pub(super) struct DurableCommit<T> {
    pub(super) value: T,
    pub(super) durability_error: Option<String>,
}

impl<T> DurableCommit<T> {
    pub(super) fn confirmed(self, operation: &str) -> Result<T> {
        match self.durability_error {
            Some(error) => Err(VmmError::Unavailable(format!(
                "{operation} is visible but its durability is unconfirmed: {error}"
            ))),
            None => Ok(self.value),
        }
    }
}

/// File-backed sandbox record store serialized by a process-local mutex.
pub(super) struct SandboxRecordStore {
    root: PathBuf,
    lock: Mutex<()>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExistingProvision {
    Pending,
    Replay,
    Blocked,
}

impl SandboxRecordStore {
    /// Opens the durable store beside, rather than inside, runtime sandboxes.
    pub(super) fn new(data_dir: &Path) -> Result<Self> {
        let root = data_dir.join(RECORDS_DIR);
        fs::create_dir_all(&root)?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        File::open(data_dir)?.sync_all()?;
        File::open(&root)?.sync_all()?;
        Ok(Self {
            root,
            lock: Mutex::new(()),
        })
    }

    /// Loads the current record for `id`.
    #[cfg(test)]
    pub(super) fn load(&self, id: &str) -> Result<Option<SandboxRecord>> {
        let _guard = self.lock()?;
        self.load_unlocked(id)
    }

    /// Loads every durable record, rejecting any malformed record file.
    pub(super) fn load_all(&self) -> Result<Vec<SandboxRecord>> {
        let _guard = self.lock()?;
        let mut paths = fs::read_dir(&self.root)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<std::io::Result<Vec<_>>>()?;
        paths.sort();

        paths
            .into_iter()
            .filter(|path| path.extension() == Some(OsStr::new("json")))
            .map(|path| {
                if !fs::symlink_metadata(&path)?.file_type().is_file() {
                    return Err(VmmError::Config(format!(
                        "sandbox record is not a regular file: {}",
                        path.display()
                    )));
                }
                let id = path.file_stem().and_then(OsStr::to_str).ok_or_else(|| {
                    VmmError::Config(format!(
                        "sandbox record has an invalid file name: {}",
                        path.display()
                    ))
                })?;
                self.load_unlocked(id)?.ok_or_else(|| {
                    VmmError::Other(format!(
                        "sandbox record disappeared while loading: {}",
                        path.display()
                    ))
                })
            })
            .collect()
    }

    /// Returns a durable provisioning result before resolving mutable inputs.
    ///
    /// `None` means either no record exists or the matching create is still
    /// pending; both cases continue through the normal provisioning path.
    pub(super) fn replay_provision(
        &self,
        id: &str,
        request_key: &str,
    ) -> Result<Option<SandboxProvisionOutcome>> {
        validate_provision_input(id, request_key)?;
        let _guard = self.lock()?;
        let Some(record) = self.load_unlocked(id)? else {
            return Ok(None);
        };

        match classify_existing_provision(&record, request_key)? {
            ExistingProvision::Pending => Ok(None),
            ExistingProvision::Replay => {
                self.confirm_root_unlocked("provision replay")?;
                Ok(record.provision_outcome)
            }
            ExistingProvision::Blocked => {
                self.confirm_root_unlocked("provision collision")?;
                Err(VmmError::AlreadyExists(id.to_owned()))
            }
        }
    }

    /// Persists a new provisioning intent or classifies the existing match.
    pub(super) fn provision_intent(
        &self,
        id: &str,
        request_key: &str,
        effective_spec: SandboxSpec,
    ) -> Result<ProvisionIntent> {
        validate_provision_input(id, request_key)?;

        let _guard = self.lock()?;
        if let Some(record) = self.load_unlocked(id)? {
            return Ok(match classify_existing_provision(&record, request_key)? {
                ExistingProvision::Pending => ProvisionIntent::Resume(record),
                ExistingProvision::Replay => {
                    self.confirm_root_unlocked("provision replay")?;
                    ProvisionIntent::Replay(record)
                }
                ExistingProvision::Blocked => {
                    self.confirm_root_unlocked("provision collision")?;
                    ProvisionIntent::Blocked(record)
                }
            });
        }

        let record = SandboxRecord::new(id, request_key, effective_spec);
        if let Some(error) = self.save_unlocked(&record)? {
            warn!(
                sandbox_id = id,
                error, "provision intent is visible but directory fsync failed"
            );
        }
        Ok(ProvisionIntent::Created(record))
    }

    /// Applies a lifecycle transition only to the expected generation.
    pub(super) fn transition(
        &self,
        id: &str,
        generation: Uuid,
        transition: SandboxTransition,
    ) -> Result<DurableCommit<SandboxRecord>> {
        let _guard = self.lock()?;
        let mut record = self
            .load_unlocked(id)?
            .ok_or_else(|| VmmError::NotFound(id.to_owned()))?;
        if record.generation != generation {
            return Err(generation_mismatch(id, record.generation, generation));
        }
        record.apply(transition)?;
        let durability_error = self.save_unlocked(&record)?;
        Ok(DurableCommit {
            value: record,
            durability_error,
        })
    }

    /// Persists the resolved lifecycle knobs without changing the phase.
    ///
    /// Called by `SetLifecycle` (CORE-60) with the post-update values so a
    /// paused sandbox reloaded after an agent restart keeps its (re-armed)
    /// TTL deadline and idle policy.
    pub(super) fn update_lifecycle(
        &self,
        id: &str,
        generation: Uuid,
        ttl_deadline: Option<DateTime<Utc>>,
        idle_timeout_seconds: u32,
        on_idle: IdleAction,
    ) -> Result<DurableCommit<()>> {
        let _guard = self.lock()?;
        let mut record = self
            .load_unlocked(id)?
            .ok_or_else(|| VmmError::NotFound(id.to_owned()))?;
        if record.generation != generation {
            return Err(generation_mismatch(id, record.generation, generation));
        }
        record.ttl_deadline = ttl_deadline;
        record.effective_spec.idle_timeout_seconds = idle_timeout_seconds;
        record.effective_spec.on_idle = on_idle;
        let durability_error = self.save_unlocked(&record)?;
        Ok(DurableCommit {
            value: (),
            durability_error,
        })
    }

    /// Removes a known pre-ACK provision intent after side effects rolled back.
    pub(super) fn abort_provision(&self, id: &str, generation: Uuid) -> Result<DurableCommit<()>> {
        self.delete_record(id, generation, SandboxPhase::Creating)
    }

    /// Releases an ID only after removal and resource cleanup completed.
    pub(super) fn finish_remove(&self, id: &str, generation: Uuid) -> Result<DurableCommit<()>> {
        self.delete_record(id, generation, SandboxPhase::Removing)
    }

    /// Cancels a pre-ACK intent, or confirms that an already-removed ID is free.
    pub(super) fn cancel_pending_or_missing(&self, id: &str) -> Result<DurableCommit<()>> {
        let _guard = self.lock()?;
        let Some(record) = self.load_unlocked(id)? else {
            return Ok(self.confirm_absence_unlocked());
        };
        if record.phase != SandboxPhase::Creating || record.provision_outcome.is_some() {
            return Err(VmmError::AlreadyExists(id.to_owned()));
        }
        self.delete_unlocked(id)
    }

    fn lock(&self) -> Result<MutexGuard<'_, ()>> {
        self.lock
            .lock()
            .map_err(|_| VmmError::Other("sandbox record store mutex poisoned".into()))
    }

    fn load_unlocked(&self, id: &str) -> Result<Option<SandboxRecord>> {
        validate_id("sandbox id", id)?;
        let path = self.record_path(id);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if !metadata.file_type().is_file() {
            return Err(VmmError::Config(format!(
                "sandbox record is not a regular file: {}",
                path.display()
            )));
        }
        if metadata.permissions().mode() & 0o077 != 0 {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        }
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        #[derive(Deserialize)]
        struct RecordHeader {
            version: u32,
        }
        let header: RecordHeader = serde_json::from_slice(&bytes)?;
        if header.version != RECORD_VERSION {
            return Err(VmmError::Config(format!(
                "unsupported sandbox record version {} for {id}",
                header.version
            )));
        }
        let record: SandboxRecord = serde_json::from_slice(&bytes)?;
        validate_record(id, &record)?;
        Ok(Some(record))
    }

    fn save_unlocked(&self, record: &SandboxRecord) -> Result<Option<String>> {
        validate_record(&record.id, record)?;
        let bytes = serde_json::to_vec_pretty(record)?;
        // A record that reached the filesystem but whose rename is not
        // yet confirmed durable is still the record: keep it and report the
        // doubt upward, rather than failing a write that did land.
        match arcbox_atomic_file::write(&self.record_path(&record.id), &bytes) {
            Ok(()) => Ok(None),
            Err(error @ AtomicWriteError::NotCommitted { .. }) => Err(error.into()),
            Err(error @ AtomicWriteError::DurabilityUncertain { .. }) => {
                Ok(Some(error.to_string()))
            }
        }
    }

    fn record_path(&self, id: &str) -> PathBuf {
        self.root.join(format!("{id}.json"))
    }

    fn delete_record(
        &self,
        id: &str,
        generation: Uuid,
        expected_phase: SandboxPhase,
    ) -> Result<DurableCommit<()>> {
        let _guard = self.lock()?;
        let Some(record) = self.load_unlocked(id)? else {
            return Ok(self.confirm_absence_unlocked());
        };
        if record.generation != generation {
            return Err(generation_mismatch(id, record.generation, generation));
        }
        if record.phase != expected_phase {
            return Err(VmmError::WrongState {
                id: id.to_owned(),
                expected: expected_phase.as_str().into(),
                actual: record.phase.as_str().into(),
            });
        }
        self.delete_unlocked(id)
    }

    fn delete_unlocked(&self, id: &str) -> Result<DurableCommit<()>> {
        fs::remove_file(self.record_path(id))?;
        let durability_error = self
            .sync_root_unlocked()
            .err()
            .map(|error| error.to_string());
        Ok(DurableCommit {
            value: (),
            durability_error,
        })
    }

    fn sync_root_unlocked(&self) -> std::io::Result<()> {
        File::open(&self.root).and_then(|directory| directory.sync_all())
    }

    fn confirm_root_unlocked(&self, operation: &str) -> Result<()> {
        self.sync_root_unlocked().map_err(|error| {
            VmmError::Unavailable(format!(
                "{operation} durability could not be confirmed: {error}"
            ))
        })
    }

    fn confirm_absence_unlocked(&self) -> DurableCommit<()> {
        DurableCommit {
            value: (),
            durability_error: self
                .sync_root_unlocked()
                .err()
                .map(|error| error.to_string()),
        }
    }
}

fn validate_provision_input(id: &str, request_key: &str) -> Result<()> {
    validate_id("sandbox id", id)?;
    if request_key.is_empty() {
        return Err(VmmError::Config(
            "sandbox provision request key must not be empty".into(),
        ));
    }
    Ok(())
}

fn classify_existing_provision(
    record: &SandboxRecord,
    request_key: &str,
) -> Result<ExistingProvision> {
    if record.request_key != request_key {
        return Err(VmmError::AlreadyExists(record.id.clone()));
    }
    Ok(match record.phase {
        SandboxPhase::Creating => ExistingProvision::Pending,
        SandboxPhase::Starting | SandboxPhase::Ready => ExistingProvision::Replay,
        // A paused sandbox's provision outcome names a released IP, so a
        // same-key create retry must not replay it as live.
        SandboxPhase::Stopping
        | SandboxPhase::Stopped
        | SandboxPhase::Failed
        | SandboxPhase::Removing
        | SandboxPhase::Pausing
        | SandboxPhase::Paused
        | SandboxPhase::Resuming => ExistingProvision::Blocked,
    })
}

fn validate_record(id: &str, record: &SandboxRecord) -> Result<()> {
    validate_id("sandbox id", id)?;
    if record.version != RECORD_VERSION {
        return Err(VmmError::Config(format!(
            "unsupported sandbox record version {} for {id}",
            record.version
        )));
    }
    if record.id != id {
        return Err(VmmError::Config(format!(
            "sandbox record id mismatch: expected {id}, got {}",
            record.id
        )));
    }
    if record.effective_spec.id.as_deref() != Some(id) {
        return Err(VmmError::Config(format!(
            "sandbox record spec id mismatch for {id}"
        )));
    }
    if record.request_key.is_empty() {
        return Err(VmmError::Config(format!(
            "sandbox record provision request key is empty for {id}"
        )));
    }
    if record.phase == SandboxPhase::Creating && record.provision_outcome.is_some() {
        return Err(VmmError::Config(format!(
            "creating sandbox record unexpectedly has a provision outcome for {id}"
        )));
    }
    if matches!(
        record.phase,
        SandboxPhase::Starting
            | SandboxPhase::Ready
            | SandboxPhase::Stopping
            | SandboxPhase::Stopped
            | SandboxPhase::Pausing
            | SandboxPhase::Paused
            | SandboxPhase::Resuming
    ) && record.provision_outcome.is_none()
    {
        return Err(VmmError::Config(format!(
            "sandbox record has no provision outcome in phase {} for {id}",
            record.phase.as_str()
        )));
    }
    if matches!(record.phase, SandboxPhase::Paused | SandboxPhase::Resuming)
        && record.pause_snapshot_id.is_none()
    {
        return Err(VmmError::Config(format!(
            "sandbox record has no pause snapshot in phase {} for {id}",
            record.phase.as_str()
        )));
    }
    Ok(())
}

fn generation_mismatch(id: &str, expected: Uuid, actual: Uuid) -> VmmError {
    VmmError::WrongState {
        id: id.to_owned(),
        expected: format!("generation {expected}"),
        actual: format!("generation {actual}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(id: &str) -> SandboxSpec {
        SandboxSpec {
            id: Some(id.to_owned()),
            ttl_seconds: 60,
            ..SandboxSpec::default()
        }
    }

    fn created(intent: ProvisionIntent) -> SandboxRecord {
        match intent {
            ProvisionIntent::Created(record) => record,
            other => panic!("expected created intent, got {other:?}"),
        }
    }

    #[test]
    fn records_survive_reopen_and_ignore_truncated_temporary_files() {
        let data_dir = tempfile::tempdir().unwrap();
        let store = SandboxRecordStore::new(data_dir.path()).unwrap();
        let record = created(store.provision_intent("box", "key", spec("box")).unwrap());

        fs::write(store.root.join(".box.interrupted.tmp"), b"{").unwrap();
        let reopened = SandboxRecordStore::new(data_dir.path()).unwrap();

        assert_eq!(reopened.load("box").unwrap(), Some(record));
        assert_eq!(reopened.load("other").unwrap(), None);
        assert_eq!(reopened.load_all().unwrap().len(), 1);
        assert_eq!(
            fs::metadata(reopened.record_path("box"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&reopened.root).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[test]
    fn ready_restore_outcome_replays_after_store_reopen() {
        let data_dir = tempfile::tempdir().unwrap();
        let store = SandboxRecordStore::new(data_dir.path()).unwrap();
        let record = created(
            store
                .provision_intent("restored", "restore-key", spec("restored"))
                .unwrap(),
        );
        let outcome = SandboxProvisionOutcome {
            ip_address: "192.0.2.8".into(),
        };
        store
            .transition(
                "restored",
                record.generation,
                SandboxTransition::ReadyWithOutcome(outcome.clone()),
            )
            .unwrap();

        let reopened = SandboxRecordStore::new(data_dir.path()).unwrap();
        assert_eq!(
            reopened
                .replay_provision("restored", "restore-key")
                .unwrap(),
            Some(outcome)
        );
        assert!(matches!(
            reopened.replay_provision("restored", "different-restore-key"),
            Err(VmmError::AlreadyExists(id)) if id == "restored"
        ));
    }

    #[test]
    fn load_all_rejects_corrupt_and_unsupported_records() {
        let data_dir = tempfile::tempdir().unwrap();
        let store = SandboxRecordStore::new(data_dir.path()).unwrap();
        let mut record = created(store.provision_intent("box", "key", spec("box")).unwrap());
        let path = store.record_path("box");

        fs::write(&path, b"{").unwrap();
        assert!(matches!(store.load_all(), Err(VmmError::Json(_))));

        record.version = RECORD_VERSION + 1;
        fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
        assert!(matches!(
            store.load_all(),
            Err(VmmError::Config(message))
                if message.contains("unsupported sandbox record version")
        ));
    }

    #[test]
    fn matching_intent_resumes_then_replays_but_a_different_key_collides() {
        let data_dir = tempfile::tempdir().unwrap();
        let store = SandboxRecordStore::new(data_dir.path()).unwrap();
        assert_eq!(store.replay_provision("missing", "key").unwrap(), None);
        let mut original = spec("box");
        original.rootfs = "/first/rootfs.ext4".into();
        let record = created(store.provision_intent("box", "key", original).unwrap());
        assert_eq!(store.replay_provision("box", "key").unwrap(), None);

        let mut refreshed = spec("box");
        refreshed.rootfs = "/new/rootfs.ext4".into();
        assert!(matches!(
            store.provision_intent("box", "key", refreshed).unwrap(),
            ProvisionIntent::Resume(found)
                if found.generation == record.generation
                    && found.effective_spec.rootfs == "/first/rootfs.ext4"
        ));
        assert!(matches!(
            store.provision_intent("box", "other", spec("box")),
            Err(VmmError::AlreadyExists(id)) if id == "box"
        ));
        assert!(matches!(
            store.replay_provision("box", "other"),
            Err(VmmError::AlreadyExists(id)) if id == "box"
        ));

        let mut with_secret = spec("box");
        with_secret.env.insert("TOKEN".into(), "secret".into());
        let store2 = SandboxRecordStore::new(data_dir.path()).unwrap();
        store2
            .provision_intent("secret-box", "secret-key", {
                with_secret.id = Some("secret-box".into());
                with_secret
            })
            .unwrap();
        let secret_record = store2.load("secret-box").unwrap().unwrap();
        store2
            .transition(
                "secret-box",
                secret_record.generation,
                SandboxTransition::Failed("boot failed".into()),
            )
            .unwrap();
        assert!(
            store2
                .load("secret-box")
                .unwrap()
                .unwrap()
                .effective_spec
                .env
                .is_empty()
        );

        store
            .transition(
                "box",
                record.generation,
                SandboxTransition::Starting(SandboxProvisionOutcome {
                    ip_address: "192.0.2.2".into(),
                }),
            )
            .unwrap();
        assert_eq!(
            store.replay_provision("box", "key").unwrap(),
            Some(SandboxProvisionOutcome {
                ip_address: "192.0.2.2".into()
            })
        );
        assert!(matches!(
            store.provision_intent("box", "key", spec("box")).unwrap(),
            ProvisionIntent::Replay(found)
                if found.provision_outcome == Some(SandboxProvisionOutcome {
                    ip_address: "192.0.2.2".into()
                })
        ));
        store
            .transition(
                "box",
                record.generation,
                SandboxTransition::Failed("boot failed".into()),
            )
            .unwrap();
        assert!(matches!(
            store.replay_provision("box", "key"),
            Err(VmmError::AlreadyExists(id)) if id == "box"
        ));
        assert!(matches!(
            store.provision_intent("box", "key", spec("box")).unwrap(),
            ProvisionIntent::Blocked(found) if found.phase == SandboxPhase::Failed
        ));
    }

    #[test]
    fn transitions_enforce_generation_and_lifecycle_edges() {
        let data_dir = tempfile::tempdir().unwrap();
        let store = SandboxRecordStore::new(data_dir.path()).unwrap();
        let record = created(store.provision_intent("box", "key", spec("box")).unwrap());

        assert!(
            store
                .transition("box", Uuid::new_v4(), SandboxTransition::Ready)
                .is_err()
        );
        assert!(
            store
                .transition("box", record.generation, SandboxTransition::Ready)
                .is_err()
        );
        assert_eq!(
            store.load("box").unwrap().unwrap().phase,
            SandboxPhase::Creating
        );

        store
            .transition(
                "box",
                record.generation,
                SandboxTransition::Starting(SandboxProvisionOutcome {
                    ip_address: String::new(),
                }),
            )
            .unwrap();
        store
            .transition("box", record.generation, SandboxTransition::Ready)
            .unwrap();
        assert!(store.replay_provision("box", "key").unwrap().is_some());
        store
            .transition("box", record.generation, SandboxTransition::Stopping)
            .unwrap();
        assert!(matches!(
            store.replay_provision("box", "key"),
            Err(VmmError::AlreadyExists(id)) if id == "box"
        ));
        store
            .transition("box", record.generation, SandboxTransition::Stopped)
            .unwrap();
        assert!(matches!(
            store.replay_provision("box", "key"),
            Err(VmmError::AlreadyExists(id)) if id == "box"
        ));
        store
            .transition("box", record.generation, SandboxTransition::Stopped)
            .unwrap()
            .confirmed("idempotent stopped retry")
            .unwrap();
        store
            .transition("box", record.generation, SandboxTransition::Removing)
            .unwrap();
        assert!(matches!(
            store.replay_provision("box", "key"),
            Err(VmmError::AlreadyExists(id)) if id == "box"
        ));
        store.finish_remove("box", record.generation).unwrap();
        assert_eq!(store.load("box").unwrap(), None);
        assert_eq!(store.replay_provision("box", "key").unwrap(), None);
        let recreated = created(
            store
                .provision_intent("box", "new-key", spec("box"))
                .unwrap(),
        );
        assert_ne!(recreated.generation, record.generation);

        let failed = created(
            store
                .provision_intent("failed", "key", spec("failed"))
                .unwrap(),
        );
        store
            .transition(
                "failed",
                failed.generation,
                SandboxTransition::Failed("interrupted".into()),
            )
            .unwrap();
        assert!(matches!(
            store.replay_provision("failed", "key"),
            Err(VmmError::AlreadyExists(id)) if id == "failed"
        ));
    }

    #[test]
    fn pause_resume_transitions_carry_the_snapshot_and_paused_at() {
        let data_dir = tempfile::tempdir().unwrap();
        let store = SandboxRecordStore::new(data_dir.path()).unwrap();
        let record = created(store.provision_intent("box", "key", spec("box")).unwrap());
        let generation = record.generation;
        store
            .transition(
                "box",
                generation,
                SandboxTransition::Starting(SandboxProvisionOutcome {
                    ip_address: "192.0.2.2".into(),
                }),
            )
            .unwrap();
        store
            .transition("box", generation, SandboxTransition::Ready)
            .unwrap();

        // Pausing may not jump straight to Paused-from-Ready.
        assert!(
            store
                .transition(
                    "box",
                    generation,
                    SandboxTransition::Paused {
                        snapshot_id: "snap".into()
                    }
                )
                .is_err()
        );
        store
            .transition("box", generation, SandboxTransition::Pausing)
            .unwrap();
        let paused = store
            .transition(
                "box",
                generation,
                SandboxTransition::Paused {
                    snapshot_id: "snap".into(),
                },
            )
            .unwrap()
            .value;
        assert_eq!(paused.phase, SandboxPhase::Paused);
        assert_eq!(paused.pause_snapshot_id.as_deref(), Some("snap"));
        assert!(paused.paused_at.is_some());

        // A paused id must not replay its (released) provision outcome.
        assert!(matches!(
            store.replay_provision("box", "key"),
            Err(VmmError::AlreadyExists(_))
        ));

        // Resume keeps the snapshot until Ready clears it.
        let resuming = store
            .transition("box", generation, SandboxTransition::Resuming)
            .unwrap()
            .value;
        assert_eq!(resuming.pause_snapshot_id.as_deref(), Some("snap"));
        // A failed resume unwinds back to Paused, keeping the ORIGINAL
        // paused_at — the sandbox has been paused since the pause call, and
        // a retry loop must not keep pushing the stamp forward.
        let reverted = store
            .transition(
                "box",
                generation,
                SandboxTransition::Paused {
                    snapshot_id: "snap".into(),
                },
            )
            .unwrap()
            .value;
        assert_eq!(reverted.paused_at, paused.paused_at);
        // …and a successful one lands Ready with the pause state cleared.
        store
            .transition("box", generation, SandboxTransition::Resuming)
            .unwrap();
        let ready = store
            .transition("box", generation, SandboxTransition::Ready)
            .unwrap()
            .value;
        assert_eq!(ready.phase, SandboxPhase::Ready);
        assert_eq!(ready.pause_snapshot_id, None);
        assert_eq!(ready.paused_at, None);

        // A genuine re-pause after Ready gets a fresh stamp.
        store
            .transition("box", generation, SandboxTransition::Pausing)
            .unwrap();
        let repaused = store
            .transition(
                "box",
                generation,
                SandboxTransition::Paused {
                    snapshot_id: "snap2".into(),
                },
            )
            .unwrap()
            .value;
        assert!(repaused.paused_at.is_some());
        assert!(repaused.paused_at >= paused.paused_at);
    }

    #[test]
    fn failed_pause_reverts_to_ready_and_paused_cannot_stop() {
        let data_dir = tempfile::tempdir().unwrap();
        let store = SandboxRecordStore::new(data_dir.path()).unwrap();
        let record = created(store.provision_intent("box", "key", spec("box")).unwrap());
        let generation = record.generation;
        store
            .transition(
                "box",
                generation,
                SandboxTransition::Starting(SandboxProvisionOutcome {
                    ip_address: String::new(),
                }),
            )
            .unwrap();
        store
            .transition("box", generation, SandboxTransition::Ready)
            .unwrap();
        store
            .transition("box", generation, SandboxTransition::Pausing)
            .unwrap();
        store
            .transition("box", generation, SandboxTransition::Ready)
            .unwrap();

        store
            .transition("box", generation, SandboxTransition::Pausing)
            .unwrap();
        store
            .transition(
                "box",
                generation,
                SandboxTransition::Paused {
                    snapshot_id: "snap".into(),
                },
            )
            .unwrap();
        // Paused has no VM to drain: only Resume, Failed, or Removing apply.
        assert!(
            store
                .transition("box", generation, SandboxTransition::Stopping)
                .is_err()
        );
        store
            .transition("box", generation, SandboxTransition::Removing)
            .unwrap();
        store.finish_remove("box", generation).unwrap();
    }

    #[test]
    fn pre_ack_abort_releases_only_the_expected_generation() {
        let data_dir = tempfile::tempdir().unwrap();
        let store = SandboxRecordStore::new(data_dir.path()).unwrap();
        let record = created(store.provision_intent("box", "key", spec("box")).unwrap());

        assert!(store.abort_provision("box", Uuid::new_v4()).is_err());
        store
            .abort_provision("box", record.generation)
            .unwrap()
            .confirmed("test abort")
            .unwrap();
        assert!(store.load("box").unwrap().is_none());
        store
            .cancel_pending_or_missing("box")
            .unwrap()
            .confirmed("idempotent remove")
            .unwrap();
    }
}
