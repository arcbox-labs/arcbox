//! Hand-written public shapes and their wire mappings.
//!
//! Generated types never appear in a public signature — these DTOs are
//! mapped from the wire messages at the transport boundary, the same
//! rule the TypeScript and Python SDKs follow.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arcbox_connect::sandbox_v1 as pb;
use buffa_types::google::protobuf::Timestamp;

/// Lifecycle state of a sandbox. See `sandbox.proto` for the state
/// machine. `Unknown` covers wire values this SDK predates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SandboxState {
    Unknown,
    Starting,
    Ready,
    Running,
    Stopping,
    Stopped,
    Failed,
    Pausing,
    Paused,
}

/// What the daemon does when the idle timeout expires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdlePolicy {
    Kill,
    Pause,
}

/// Full sandbox state, always fetched fresh — never a cached mirror.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SandboxInfo {
    pub id: String,
    pub state: SandboxState,
    pub labels: BTreeMap<String, String>,
    /// Template reference the sandbox was created from (`""` = built-in
    /// minimal).
    pub template: String,
    /// Effective vCPU count, when reported.
    pub vcpus: Option<u32>,
    /// Effective memory in MiB, when reported.
    pub memory_mib: Option<u64>,
    pub ip_address: Option<String>,
    pub created_at: Option<SystemTime>,
    pub ready_at: Option<SystemTime>,
    pub paused_at: Option<SystemTime>,
    pub failed_at: Option<SystemTime>,
    /// Failure reason; set exactly when the state is [`SandboxState::Failed`].
    pub error: Option<String>,
    /// When the hard maximum lifetime fires (unset = no limit).
    pub ttl_deadline: Option<SystemTime>,
    /// Idle window (unset = no idle detection).
    pub idle_timeout: Option<Duration>,
    /// Action applied when the idle timeout expires (unset = daemon default).
    pub on_idle: Option<IdlePolicy>,
    /// On-disk footprint of retained state; paused sandboxes keep paying
    /// this.
    pub storage_bytes: u64,
}

/// One row of a sandbox listing.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SandboxSummary {
    pub id: String,
    pub state: SandboxState,
    pub labels: BTreeMap<String, String>,
    pub ip_address: Option<String>,
    pub created_at: Option<SystemTime>,
    pub ready_at: Option<SystemTime>,
    pub paused_at: Option<SystemTime>,
    pub failed_at: Option<SystemTime>,
    pub storage_bytes: u64,
}

/// Nested-virtualization support on this host.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct NestedVirtCapability {
    /// True when sandboxes can run (M3+ hardware, VZ backend).
    pub supported: bool,
    /// The daemon's authoritative reason, when unsupported.
    pub reason: Option<String>,
}

/// What the daemon can do — the `ArcBox::capabilities` handshake.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Capabilities {
    /// Daemon version string (informational).
    pub daemon_version: String,
    /// Sandbox API protocol level.
    pub protocol: u32,
    /// Append-only named feature flags (e.g. `"pause_resume"`).
    pub features: Vec<String>,
    /// Whether this host can run sandboxes at all.
    pub nested_virt: NestedVirtCapability,
}

/// One checkpointed sandbox image in the snapshot catalog.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Snapshot {
    pub id: String,
    /// The sandbox this snapshot was checkpointed from.
    pub sandbox_id: String,
    /// Human-readable name recorded at checkpoint time.
    pub name: String,
    /// Labels recorded at checkpoint time, filterable in listings.
    pub labels: BTreeMap<String, String>,
    pub created_at: Option<SystemTime>,
}

/// Kind of a sandbox lifecycle event. `Unknown` covers wire values
/// this SDK predates. `Idle` fires when an execution exits and the
/// sandbox returns to ready.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SandboxEventKind {
    Created,
    Ready,
    Running,
    Idle,
    Stopping,
    Stopped,
    Failed,
    Removed,
    Pausing,
    Paused,
    Resumed,
    Unknown,
}

/// One sandbox lifecycle event, as delivered by `Sandbox::events`.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SandboxEvent {
    pub sandbox_id: String,
    pub kind: SandboxEventKind,
    /// When it happened (daemon clock).
    pub time: Option<SystemTime>,
    /// Per-kind context: `exit_code`/`signal` on `Idle`, `error` on
    /// `Failed`, `reason` on `Pausing`/`Resumed`.
    pub attributes: BTreeMap<String, String>,
}

/// One knob of a lifecycle update: leave it, clear it to the daemon
/// default, or set a value. [`Update::Unchanged`] is the `Default`, so
/// struct-update syntax touches only the knobs it names.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Update<T> {
    /// Leave the knob as it is.
    #[default]
    Unchanged,
    /// Restore the daemon default (no TTL / no idle detection / the
    /// default idle action).
    Clear,
    /// Replace the knob with this value.
    Set(T),
}

/// A lifecycle-deadline update for `Sandbox::set_lifecycle`. Each knob
/// is tri-state — see [`Update`].
#[derive(Debug, Clone, Copy, Default)]
pub struct LifecycleUpdate {
    /// Replace the hard maximum lifetime: expire this long from NOW —
    /// setting it repeatedly keeps a busy sandbox alive.
    pub ttl: Update<Duration>,
    /// Replace the idle window, re-arming a live timer.
    pub idle_timeout: Update<Duration>,
    /// Replace what the daemon does when the idle timeout expires.
    pub on_idle: Update<IdlePolicy>,
}

pub fn state_from_wire(state: buffa::EnumValue<pb::SandboxState>) -> SandboxState {
    match state.as_known() {
        Some(pb::SandboxState::SANDBOX_STATE_STARTING) => SandboxState::Starting,
        Some(pb::SandboxState::SANDBOX_STATE_READY) => SandboxState::Ready,
        Some(pb::SandboxState::SANDBOX_STATE_RUNNING) => SandboxState::Running,
        Some(pb::SandboxState::SANDBOX_STATE_STOPPING) => SandboxState::Stopping,
        Some(pb::SandboxState::SANDBOX_STATE_STOPPED) => SandboxState::Stopped,
        Some(pb::SandboxState::SANDBOX_STATE_FAILED) => SandboxState::Failed,
        Some(pb::SandboxState::SANDBOX_STATE_PAUSING) => SandboxState::Pausing,
        Some(pb::SandboxState::SANDBOX_STATE_PAUSED) => SandboxState::Paused,
        Some(pb::SandboxState::SANDBOX_STATE_UNSPECIFIED) | None => SandboxState::Unknown,
    }
}

pub fn state_to_wire(state: SandboxState) -> pb::SandboxState {
    match state {
        SandboxState::Starting => pb::SandboxState::SANDBOX_STATE_STARTING,
        SandboxState::Ready => pb::SandboxState::SANDBOX_STATE_READY,
        SandboxState::Running => pb::SandboxState::SANDBOX_STATE_RUNNING,
        SandboxState::Stopping => pb::SandboxState::SANDBOX_STATE_STOPPING,
        SandboxState::Stopped => pb::SandboxState::SANDBOX_STATE_STOPPED,
        SandboxState::Failed => pb::SandboxState::SANDBOX_STATE_FAILED,
        SandboxState::Pausing => pb::SandboxState::SANDBOX_STATE_PAUSING,
        SandboxState::Paused => pb::SandboxState::SANDBOX_STATE_PAUSED,
        SandboxState::Unknown => pb::SandboxState::SANDBOX_STATE_UNSPECIFIED,
    }
}

pub fn idle_action_to_wire(policy: Option<IdlePolicy>) -> pb::IdleAction {
    match policy {
        Some(IdlePolicy::Kill) => pb::IdleAction::IDLE_ACTION_KILL,
        Some(IdlePolicy::Pause) => pb::IdleAction::IDLE_ACTION_PAUSE,
        None => pb::IdleAction::IDLE_ACTION_UNSPECIFIED,
    }
}

/// Whole wire seconds, rounded UP — 0 is the wire's "daemon default"
/// sentinel, so a small positive duration must never truncate to it.
pub fn seconds_to_wire(duration: Option<Duration>) -> u32 {
    match duration {
        None => 0,
        Some(duration) => {
            let whole = duration.as_secs();
            let rounded = if duration.subsec_nanos() > 0 {
                whole.saturating_add(1)
            } else {
                whole
            };
            u32::try_from(rounded).unwrap_or(u32::MAX)
        }
    }
}

pub fn time_from_wire(timestamp: Option<&Timestamp>) -> Option<SystemTime> {
    let timestamp = timestamp?;
    let seconds = u64::try_from(timestamp.seconds).ok()?;
    UNIX_EPOCH.checked_add(Duration::new(seconds, timestamp.nanos.try_into().ok()?))
}

pub fn info_from_wire(info: pb::SandboxInfo) -> SandboxInfo {
    let limits = info.limits.as_option();
    let vcpus = limits
        .map(|limits| limits.vcpus)
        .filter(|&vcpus| vcpus != 0);
    let memory_mib = limits
        .map(|limits| limits.memory_mib)
        .filter(|&mib| mib != 0);
    let idle_timeout = (info.idle_timeout_seconds != 0)
        .then(|| Duration::from_secs(u64::from(info.idle_timeout_seconds)));
    let on_idle = match info.on_idle.as_known() {
        Some(pb::IdleAction::IDLE_ACTION_KILL) => Some(IdlePolicy::Kill),
        Some(pb::IdleAction::IDLE_ACTION_PAUSE) => Some(IdlePolicy::Pause),
        _ => None,
    };
    SandboxInfo {
        id: info.id,
        state: state_from_wire(info.state),
        labels: info.labels.into_iter().collect(),
        template: info.template,
        vcpus,
        memory_mib,
        ip_address: info
            .network
            .as_option()
            .map(|network| network.ip_address.clone())
            .filter(|ip| !ip.is_empty()),
        created_at: time_from_wire(info.created_at.as_option()),
        ready_at: time_from_wire(info.ready_at.as_option()),
        paused_at: time_from_wire(info.paused_at.as_option()),
        failed_at: time_from_wire(info.failed_at.as_option()),
        error: (!info.error.is_empty()).then_some(info.error),
        ttl_deadline: time_from_wire(info.ttl_deadline.as_option()),
        idle_timeout,
        on_idle,
        storage_bytes: info.storage_bytes,
    }
}

pub fn summary_from_wire(summary: pb::SandboxSummary) -> SandboxSummary {
    SandboxSummary {
        id: summary.id,
        state: state_from_wire(summary.state),
        labels: summary.labels.into_iter().collect(),
        ip_address: (!summary.ip_address.is_empty()).then_some(summary.ip_address),
        created_at: time_from_wire(summary.created_at.as_option()),
        ready_at: time_from_wire(summary.ready_at.as_option()),
        paused_at: time_from_wire(summary.paused_at.as_option()),
        failed_at: time_from_wire(summary.failed_at.as_option()),
        storage_bytes: summary.storage_bytes,
    }
}

pub fn capabilities_from_wire(response: pb::GetCapabilitiesResponse) -> Capabilities {
    let nested = response.nested_virt.as_option();
    Capabilities {
        daemon_version: response.daemon_version,
        protocol: response.protocol,
        features: response.features,
        nested_virt: NestedVirtCapability {
            supported: nested.is_some_and(|nested| nested.supported),
            reason: nested
                .map(|nested| nested.reason.clone())
                .filter(|reason| !reason.is_empty()),
        },
    }
}

/// Map one ListSnapshots row to the public DTO.
pub fn snapshot_from_wire(summary: pb::SnapshotSummary) -> Snapshot {
    Snapshot {
        id: summary.id,
        sandbox_id: summary.sandbox_id,
        name: summary.name,
        labels: summary.labels.into_iter().collect(),
        created_at: time_from_wire(summary.created_at.as_option()),
    }
}

/// Map one Events frame to the public DTO.
pub fn sandbox_event_from_wire(event: pb::SandboxEvent) -> SandboxEvent {
    use pb::SandboxEventKind as Kind;
    let kind = match event.kind.as_known() {
        Some(Kind::SANDBOX_EVENT_KIND_CREATED) => SandboxEventKind::Created,
        Some(Kind::SANDBOX_EVENT_KIND_READY) => SandboxEventKind::Ready,
        Some(Kind::SANDBOX_EVENT_KIND_RUNNING) => SandboxEventKind::Running,
        Some(Kind::SANDBOX_EVENT_KIND_IDLE) => SandboxEventKind::Idle,
        Some(Kind::SANDBOX_EVENT_KIND_STOPPING) => SandboxEventKind::Stopping,
        Some(Kind::SANDBOX_EVENT_KIND_STOPPED) => SandboxEventKind::Stopped,
        Some(Kind::SANDBOX_EVENT_KIND_FAILED) => SandboxEventKind::Failed,
        Some(Kind::SANDBOX_EVENT_KIND_REMOVED) => SandboxEventKind::Removed,
        Some(Kind::SANDBOX_EVENT_KIND_PAUSING) => SandboxEventKind::Pausing,
        Some(Kind::SANDBOX_EVENT_KIND_PAUSED) => SandboxEventKind::Paused,
        Some(Kind::SANDBOX_EVENT_KIND_RESUMED) => SandboxEventKind::Resumed,
        _ => SandboxEventKind::Unknown,
    };
    SandboxEvent {
        sandbox_id: event.sandbox_id,
        kind,
        time: time_from_wire(event.time.as_option()),
        attributes: event.attributes.into_iter().collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_seconds_round_up_never_down_to_the_sentinel() {
        assert_eq!(seconds_to_wire(None), 0);
        assert_eq!(seconds_to_wire(Some(Duration::from_millis(1))), 1);
        assert_eq!(seconds_to_wire(Some(Duration::from_secs(60))), 60);
        assert_eq!(seconds_to_wire(Some(Duration::from_millis(60_500))), 61);
    }
}
