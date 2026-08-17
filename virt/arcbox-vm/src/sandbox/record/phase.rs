//! The durable phase vocabulary: what a record can say about a sandbox
//! generation, and which moves between those phases are legal.
//!
//! No filesystem and no store state — the record's own `Utc::now()` stamps
//! are the only outside input. [`super::store`] is what persists it.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{Result, VmmError};
use crate::sandbox::{SandboxId, SandboxSpec, validate_id};

pub(super) const RECORD_VERSION: u32 = 1;

/// Durable control-plane phase for one sandbox generation.
///
/// Workload execution remains transient: a running workload keeps the durable
/// phase at `Ready`, avoiding record writes on the execution hot path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(in crate::sandbox) enum SandboxPhase {
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
pub(in crate::sandbox) struct SandboxProvisionOutcome {
    pub(in crate::sandbox) ip_address: String,
}

/// Versioned durable state for one sandbox generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(in crate::sandbox) struct SandboxRecord {
    pub(super) version: u32,
    pub(in crate::sandbox) id: SandboxId,
    pub(in crate::sandbox) generation: Uuid,
    pub(in crate::sandbox) request_key: String,
    pub(in crate::sandbox) effective_spec: SandboxSpec,
    pub(in crate::sandbox) phase: SandboxPhase,
    pub(in crate::sandbox) provision_outcome: Option<SandboxProvisionOutcome>,
    pub(in crate::sandbox) created_at: DateTime<Utc>,
    pub(in crate::sandbox) error: Option<String>,
    /// Catalog id of the internal pause checkpoint. Set while the record is
    /// `Paused`/`Resuming` so a Resume after an agent restart still finds
    /// its snapshot; cleared when the sandbox is `Ready` again.
    #[serde(default)]
    pub(in crate::sandbox) pause_snapshot_id: Option<String>,
    /// When the sandbox reached `Paused` (None otherwise).
    #[serde(default)]
    pub(in crate::sandbox) paused_at: Option<DateTime<Utc>>,
    /// When the hard maximum lifetime fires (None = no limit). Seeded from
    /// `effective_spec.ttl_seconds`; replaced by `SetLifecycle` (CORE-60).
    /// Survives `redact_runtime_inputs` — unlike the seed seconds, the
    /// deadline is durable lifecycle state, not a runtime input.
    #[serde(default)]
    pub(in crate::sandbox) ttl_deadline: Option<DateTime<Utc>>,
}

/// Result of reserving a durable provisioning intent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::sandbox) enum ProvisionIntent {
    Created(SandboxRecord),
    Resume(SandboxRecord),
    Replay(SandboxRecord),
    Blocked(SandboxRecord),
}

/// Generation-checked lifecycle update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::sandbox) enum SandboxTransition {
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
    pub(super) fn new(id: &str, request_key: &str, effective_spec: SandboxSpec) -> Self {
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

    pub(super) fn apply(&mut self, transition: SandboxTransition) -> Result<()> {
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

    pub(in crate::sandbox) fn as_str(self) -> &'static str {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ExistingProvision {
    Pending,
    Replay,
    Blocked,
}

pub(super) fn classify_existing_provision(
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

pub(super) fn validate_record(id: &str, record: &SandboxRecord) -> Result<()> {
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
