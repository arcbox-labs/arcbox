//! The file-backed record store: how a [`super::phase::SandboxRecord`]
//! reaches the disk, and what "durable" means for each write.
//!
//! Every mutation is generation-checked, serialized by a process-local
//! mutex, and reports its own durability separately from its visibility
//! ([`DurableCommit`]) — a rename that landed is still the record even when
//! the directory fsync behind it could not be confirmed.

use std::ffi::OsStr;
use std::fs::{self, File};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use chrono::{DateTime, Utc};
use serde::Deserialize;
use tracing::warn;
use uuid::Uuid;

use arcbox_atomic_file::AtomicWriteError;

use super::phase::{
    ExistingProvision, ProvisionIntent, RECORD_VERSION, SandboxPhase, SandboxProvisionOutcome,
    SandboxRecord, SandboxTransition, classify_existing_provision, validate_record,
};
use crate::error::{ComputerError, Result};
use crate::sandbox::types::IdleAction;
use crate::sandbox::{ComputerSpec, validate_id};

const RECORDS_DIR: &str = "sandbox-records";

/// A filesystem mutation whose rename/unlink happened, but whose directory
/// fsync may have failed. Callers must treat `value` as the visible state and
/// may surface `durability_error` as an unconfirmed result.
pub struct DurableCommit<T> {
    pub(in crate::sandbox) value: T,
    pub durability_error: Option<String>,
}

impl<T> DurableCommit<T> {
    pub fn confirmed(self, operation: &str) -> Result<T> {
        match self.durability_error {
            Some(error) => Err(ComputerError::Unavailable(format!(
                "{operation} is visible but its durability is unconfirmed: {error}"
            ))),
            None => Ok(self.value),
        }
    }
}

/// File-backed sandbox record store serialized by a process-local mutex.
pub struct SandboxRecordStore {
    root: PathBuf,
    lock: Mutex<()>,
}

impl SandboxRecordStore {
    /// Opens the durable store beside, rather than inside, runtime sandboxes.
    pub fn new(data_dir: &Path) -> Result<Self> {
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
    pub(in crate::sandbox) fn load(&self, id: &str) -> Result<Option<SandboxRecord>> {
        let _guard = self.lock()?;
        self.load_unlocked(id)
    }

    /// Loads every durable record, rejecting any malformed record file.
    pub(in crate::sandbox) fn load_all(&self) -> Result<Vec<SandboxRecord>> {
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
                    return Err(ComputerError::Config(format!(
                        "sandbox record is not a regular file: {}",
                        path.display()
                    )));
                }
                let id = path.file_stem().and_then(OsStr::to_str).ok_or_else(|| {
                    ComputerError::Config(format!(
                        "sandbox record has an invalid file name: {}",
                        path.display()
                    ))
                })?;
                self.load_unlocked(id)?.ok_or_else(|| {
                    ComputerError::Other(format!(
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
    pub(in crate::sandbox) fn replay_provision(
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
                Err(ComputerError::AlreadyExists(id.to_owned()))
            }
        }
    }

    /// Persists a new provisioning intent or classifies the existing match.
    pub(crate) fn provision_intent(
        &self,
        id: &str,
        request_key: &str,
        effective_spec: ComputerSpec,
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
    pub fn transition(
        &self,
        id: &str,
        generation: Uuid,
        transition: SandboxTransition,
    ) -> Result<DurableCommit<SandboxRecord>> {
        let _guard = self.lock()?;
        let mut record = self
            .load_unlocked(id)?
            .ok_or_else(|| ComputerError::NotFound(id.to_owned()))?;
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
    pub fn update_lifecycle(
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
            .ok_or_else(|| ComputerError::NotFound(id.to_owned()))?;
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
    pub fn abort_provision(&self, id: &str, generation: Uuid) -> Result<DurableCommit<()>> {
        self.delete_record(id, generation, SandboxPhase::Creating)
    }

    /// Releases an ID only after removal and resource cleanup completed.
    pub fn finish_remove(&self, id: &str, generation: Uuid) -> Result<DurableCommit<()>> {
        self.delete_record(id, generation, SandboxPhase::Removing)
    }

    /// Cancels a pre-ACK intent, or confirms that an already-removed ID is free.
    pub(in crate::sandbox) fn cancel_pending_or_missing(
        &self,
        id: &str,
    ) -> Result<DurableCommit<()>> {
        let _guard = self.lock()?;
        let Some(record) = self.load_unlocked(id)? else {
            return Ok(self.confirm_absence_unlocked());
        };
        if record.phase != SandboxPhase::Creating || record.provision_outcome.is_some() {
            return Err(ComputerError::AlreadyExists(id.to_owned()));
        }
        self.delete_unlocked(id)
    }

    fn lock(&self) -> Result<MutexGuard<'_, ()>> {
        self.lock
            .lock()
            .map_err(|_| ComputerError::Other("sandbox record store mutex poisoned".into()))
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
            return Err(ComputerError::Config(format!(
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
            return Err(ComputerError::Config(format!(
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
            return Err(ComputerError::WrongState {
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
            ComputerError::Unavailable(format!(
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
        return Err(ComputerError::Config(
            "sandbox provision request key must not be empty".into(),
        ));
    }
    Ok(())
}

fn generation_mismatch(id: &str, expected: Uuid, actual: Uuid) -> ComputerError {
    ComputerError::WrongState {
        id: id.to_owned(),
        expected: format!("generation {expected}"),
        actual: format!("generation {actual}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(id: &str) -> ComputerSpec {
        ComputerSpec {
            id: Some(id.to_owned()),
            ttl_seconds: 60,
            ..ComputerSpec::default()
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
            Err(ComputerError::AlreadyExists(id)) if id == "restored"
        ));
    }

    #[test]
    fn load_all_rejects_corrupt_and_unsupported_records() {
        let data_dir = tempfile::tempdir().unwrap();
        let store = SandboxRecordStore::new(data_dir.path()).unwrap();
        let mut record = created(store.provision_intent("box", "key", spec("box")).unwrap());
        let path = store.record_path("box");

        fs::write(&path, b"{").unwrap();
        assert!(matches!(store.load_all(), Err(ComputerError::Json(_))));

        record.version = RECORD_VERSION + 1;
        fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
        assert!(matches!(
            store.load_all(),
            Err(ComputerError::Config(message))
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
            Err(ComputerError::AlreadyExists(id)) if id == "box"
        ));
        assert!(matches!(
            store.replay_provision("box", "other"),
            Err(ComputerError::AlreadyExists(id)) if id == "box"
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
            Err(ComputerError::AlreadyExists(id)) if id == "box"
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
            Err(ComputerError::AlreadyExists(id)) if id == "box"
        ));
        store
            .transition("box", record.generation, SandboxTransition::Stopped)
            .unwrap();
        assert!(matches!(
            store.replay_provision("box", "key"),
            Err(ComputerError::AlreadyExists(id)) if id == "box"
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
            Err(ComputerError::AlreadyExists(id)) if id == "box"
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
            Err(ComputerError::AlreadyExists(id)) if id == "failed"
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
            Err(ComputerError::AlreadyExists(_))
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
