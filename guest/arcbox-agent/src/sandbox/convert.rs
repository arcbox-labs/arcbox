//! Conversions between `arcbox-vm` native types and `sandbox.v1` protos,
//! plus the shared id-ordered pagination helper.

use arcbox_connect::sandbox_v1;
use arcbox_vm::{
    CheckpointInfo, CheckpointSummary, ExecutionChannel, ExecutionSnapshot, ExitStatus, IdleAction,
    SandboxEvent as VmSandboxEvent, SandboxInfo, SandboxState, SandboxSummary, StdinState,
};
use buffa_types::google::protobuf::Timestamp;
use chrono::{DateTime, Utc};

/// Server default when a list request leaves `page_size` at 0.
const DEFAULT_PAGE_SIZE: u32 = 100;
/// Hard cap on a single page.
const MAX_PAGE_SIZE: u32 = 1000;

pub(super) fn timestamp(dt: DateTime<Utc>) -> Timestamp {
    Timestamp {
        seconds: dt.timestamp(),
        // Sub-second nanos are < 2e9 even on leap seconds; i32 holds them.
        nanos: i32::try_from(dt.timestamp_subsec_nanos()).unwrap_or(0),
        ..Default::default()
    }
}

pub(super) fn timestamp_from_rfc3339(s: &str) -> Option<Timestamp> {
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|dt| timestamp(dt.with_timezone(&Utc)))
}

pub(super) fn timestamp_from_unix_nanos(ns: i64) -> Timestamp {
    Timestamp {
        seconds: ns.div_euclid(1_000_000_000),
        // rem_euclid of 1e9 is always in [0, 1e9), which fits i32.
        nanos: i32::try_from(ns.rem_euclid(1_000_000_000)).expect("nanos below 1e9"),
        ..Default::default()
    }
}

pub(super) fn exit_status_to_proto(status: ExitStatus) -> sandbox_v1::ExitStatus {
    let status = match status {
        ExitStatus::Code(code) => sandbox_v1::exit_status::Status::Code(code),
        ExitStatus::Signaled(signal) => sandbox_v1::exit_status::Status::Signal(signal),
    };
    sandbox_v1::ExitStatus {
        status: Some(status),
        ..Default::default()
    }
}

pub(super) fn stdin_to_proto(state: StdinState) -> sandbox_v1::StdinStatus {
    sandbox_v1::StdinStatus {
        bytes_written: state.bytes_written,
        closed: state.closed,
        ..Default::default()
    }
}

pub(super) fn execution_to_proto(snap: &ExecutionSnapshot) -> sandbox_v1::Execution {
    let state = if snap.is_running() {
        sandbox_v1::ExecutionState::Running
    } else {
        sandbox_v1::ExecutionState::Exited
    };
    sandbox_v1::Execution {
        id: snap.id.clone(),
        sandbox_id: snap.sandbox_id.clone(),
        state: state.into(),
        tty: snap.tty,
        started_at: timestamp(snap.started_at).into(),
        exited_at: snap.exited_at.map(timestamp).into(),
        exit_status: snap.exit_status.map(exit_status_to_proto).into(),
        error: snap.error.clone().unwrap_or_default(),
        stdout_len: snap.stdout_len,
        stderr_len: snap.stderr_len,
        stdin: stdin_to_proto(snap.stdin).into(),
        ..Default::default()
    }
}

/// Map a vm-level output channel to the wire channel. TTY executions carry
/// the merged PTY stream on the vm-level stdout channel.
pub(super) fn channel_to_proto(channel: ExecutionChannel, tty: bool) -> sandbox_v1::StdioChannel {
    match (channel, tty) {
        (ExecutionChannel::Stdout, true) => sandbox_v1::StdioChannel::Pty,
        (ExecutionChannel::Stdout, false) => sandbox_v1::StdioChannel::Stdout,
        (ExecutionChannel::Stderr, _) => sandbox_v1::StdioChannel::Stderr,
    }
}

pub(super) fn state_to_proto(state: SandboxState) -> sandbox_v1::SandboxState {
    match state {
        SandboxState::Starting => sandbox_v1::SandboxState::Starting,
        SandboxState::Ready => sandbox_v1::SandboxState::Ready,
        SandboxState::Running => sandbox_v1::SandboxState::Running,
        SandboxState::Stopping => sandbox_v1::SandboxState::Stopping,
        SandboxState::Stopped => sandbox_v1::SandboxState::Stopped,
        SandboxState::Failed => sandbox_v1::SandboxState::Failed,
        SandboxState::Pausing => sandbox_v1::SandboxState::Pausing,
        SandboxState::Paused => sandbox_v1::SandboxState::Paused,
    }
}

/// Map a wire state filter onto the manager's string filter
/// (`UNSPECIFIED` = no filter).
pub(super) fn state_filter(state: sandbox_v1::SandboxState) -> Option<&'static str> {
    match state {
        sandbox_v1::SandboxState::Unspecified => None,
        sandbox_v1::SandboxState::Starting => Some("starting"),
        sandbox_v1::SandboxState::Ready => Some("ready"),
        sandbox_v1::SandboxState::Running => Some("running"),
        sandbox_v1::SandboxState::Stopping => Some("stopping"),
        sandbox_v1::SandboxState::Stopped => Some("stopped"),
        sandbox_v1::SandboxState::Failed => Some("failed"),
        sandbox_v1::SandboxState::Pausing => Some("pausing"),
        sandbox_v1::SandboxState::Paused => Some("paused"),
    }
}

/// Map a manager event action onto the wire event kind.
pub(super) fn event_kind(action: &str) -> sandbox_v1::SandboxEventKind {
    match action {
        "created" => sandbox_v1::SandboxEventKind::Created,
        "ready" => sandbox_v1::SandboxEventKind::Ready,
        "running" => sandbox_v1::SandboxEventKind::Running,
        "idle" => sandbox_v1::SandboxEventKind::Idle,
        "stopping" => sandbox_v1::SandboxEventKind::Stopping,
        "stopped" => sandbox_v1::SandboxEventKind::Stopped,
        "failed" => sandbox_v1::SandboxEventKind::Failed,
        "removed" => sandbox_v1::SandboxEventKind::Removed,
        "pausing" => sandbox_v1::SandboxEventKind::Pausing,
        "paused" => sandbox_v1::SandboxEventKind::Paused,
        "resumed" => sandbox_v1::SandboxEventKind::Resumed,
        _ => sandbox_v1::SandboxEventKind::Unspecified,
    }
}

pub(super) fn vm_event_to_proto(e: VmSandboxEvent) -> sandbox_v1::SandboxEvent {
    sandbox_v1::SandboxEvent {
        sandbox_id: e.sandbox_id,
        kind: event_kind(&e.action).into(),
        time: timestamp_from_unix_nanos(e.timestamp_ns).into(),
        attributes: e.attributes.into_iter().collect(),
        ..Default::default()
    }
}

pub(super) fn info_to_proto(info: SandboxInfo) -> sandbox_v1::SandboxInfo {
    // The host TAP name is deliberately not exposed (CORE-54): it is a host
    // interface a tenant can neither see nor use.
    let network = info.network.map(|n| sandbox_v1::SandboxNetwork {
        ip_address: n.ip_address,
        gateway: n.gateway,
        ..Default::default()
    });
    sandbox_v1::SandboxInfo {
        id: info.id,
        state: state_to_proto(info.state).into(),
        labels: info.labels.into_iter().collect(),
        limits: sandbox_v1::ResourceLimits {
            vcpus: info.vcpus,
            memory_mib: info.memory_mib,
            ..Default::default()
        }
        .into(),
        network: network.into(),
        created_at: timestamp(info.created_at).into(),
        ready_at: info.ready_at.map(timestamp).into(),
        last_exited_at: info.last_exited_at.map(timestamp).into(),
        last_exit_status: info.last_exit_status.map(exit_status_to_proto).into(),
        error: info.error.unwrap_or_default(),
        paused_at: info.paused_at.map(timestamp).into(),
        storage_bytes: info.storage_bytes,
        ttl_deadline: info.ttl_deadline.map(timestamp).into(),
        idle_timeout_seconds: info.idle_timeout_seconds,
        on_idle: idle_action_to_proto(info.on_idle).into(),
        ..Default::default()
    }
}

/// Map the manager's effective idle policy onto the wire enum.
pub(super) fn idle_action_to_proto(action: IdleAction) -> sandbox_v1::IdleAction {
    match action {
        IdleAction::Kill => sandbox_v1::IdleAction::Kill,
        IdleAction::Pause => sandbox_v1::IdleAction::Pause,
    }
}

pub(super) fn summary_to_proto(s: SandboxSummary) -> sandbox_v1::SandboxSummary {
    sandbox_v1::SandboxSummary {
        id: s.id,
        state: state_to_proto(s.state).into(),
        labels: s.labels.into_iter().collect(),
        ip_address: s.ip_address,
        created_at: timestamp(s.created_at).into(),
        paused_at: s.paused_at.map(timestamp).into(),
        storage_bytes: s.storage_bytes,
        ..Default::default()
    }
}

// Snapshots are identified by id on the wire; their on-disk directory is a
// host path and stays inside the guest (CORE-54).

pub(super) fn checkpoint_to_proto(info: CheckpointInfo) -> sandbox_v1::CheckpointResponse {
    sandbox_v1::CheckpointResponse {
        snapshot_id: info.snapshot_id,
        created_at: timestamp_from_rfc3339(&info.created_at).into(),
        ..Default::default()
    }
}

pub(super) fn checkpoint_summary_to_proto(s: CheckpointSummary) -> sandbox_v1::SnapshotSummary {
    sandbox_v1::SnapshotSummary {
        id: s.id,
        sandbox_id: s.sandbox_id,
        name: s.name,
        labels: s.labels.into_iter().collect(),
        created_at: timestamp_from_rfc3339(&s.created_at).into(),
        ..Default::default()
    }
}

/// Deterministic id-ordered pagination over an in-memory listing.
///
/// The continuation token is the last id of the previous page; entries with
/// ids at or below it are skipped, so a concurrent insert or delete shifts
/// nothing already returned.
pub(super) fn paginate<T>(
    mut items: Vec<T>,
    id_of: impl Fn(&T) -> &str,
    page_size: u32,
    page_token: &str,
) -> (Vec<T>, String) {
    items.sort_by(|a, b| id_of(a).cmp(id_of(b)));
    let size = if page_size == 0 {
        DEFAULT_PAGE_SIZE
    } else {
        page_size.min(MAX_PAGE_SIZE)
    } as usize;
    let start = if page_token.is_empty() {
        0
    } else {
        items.partition_point(|it| id_of(it) <= page_token)
    };
    let has_more = items.len() > start.saturating_add(size);
    let page: Vec<T> = items.into_iter().skip(start).take(size).collect();
    let next = if has_more {
        page.last()
            .map(|it| id_of(it).to_owned())
            .unwrap_or_default()
    } else {
        String::new()
    };
    (page, next)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paginate_orders_by_id_and_chains_tokens() {
        let items = vec!["c", "a", "d", "b", "e"];
        let (page1, token1) = paginate(items.clone(), |s| s, 2, "");
        assert_eq!(page1, vec!["a", "b"]);
        assert_eq!(token1, "b");

        let (page2, token2) = paginate(items.clone(), |s| s, 2, &token1);
        assert_eq!(page2, vec!["c", "d"]);
        assert_eq!(token2, "d");

        // Final page: partial, empty token.
        let (page3, token3) = paginate(items, |s| s, 2, &token2);
        assert_eq!(page3, vec!["e"]);
        assert_eq!(token3, "");
    }

    #[test]
    fn paginate_exact_boundary_has_no_next_token() {
        let items = vec!["a", "b"];
        let (page, token) = paginate(items, |s| s, 2, "");
        assert_eq!(page, vec!["a", "b"]);
        assert_eq!(token, "");
    }

    #[test]
    fn paginate_defaults_and_caps_page_size() {
        let items: Vec<String> = (0..250).map(|i| format!("{i:04}")).collect();
        let (page, token) = paginate(items.clone(), |s| s, 0, "");
        assert_eq!(page.len(), 100);
        assert!(!token.is_empty());

        let (page, _) = paginate(items, |s| s, 5000, "");
        assert_eq!(page.len(), 250);
    }

    #[test]
    fn unix_nanos_round_to_timestamp() {
        let ts = timestamp_from_unix_nanos(1_700_000_001_500_000_000);
        assert_eq!(ts.seconds, 1_700_000_001);
        assert_eq!(ts.nanos, 500_000_000);
        // Negative nanos (pre-epoch) still yield canonical non-negative nanos.
        let ts = timestamp_from_unix_nanos(-1_500_000_000);
        assert_eq!(ts.seconds, -2);
        assert_eq!(ts.nanos, 500_000_000);
    }

    #[test]
    fn rfc3339_parses_to_timestamp() {
        let ts = timestamp_from_rfc3339("2026-08-01T00:00:00Z").unwrap();
        assert!(ts.seconds > 1_700_000_000);
        assert!(timestamp_from_rfc3339("not a date").is_none());
    }
}
