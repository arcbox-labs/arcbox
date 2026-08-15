//! Host-side runtime migration manager.

mod dto;

use crate::error::{CoreError, Result};
use arcbox_connect::v1::{
    PrepareMigrationRequest, PrepareMigrationResponse, RunMigrationEvent, RunMigrationRequest,
};
use arcbox_migration::{
    DockerCliRunner, MigrationError, MigrationExecutor, MigrationExecutorOptions, MigrationPlanner,
    MigrationProgress, SourceConfig, SourceKind, resolve_source,
};
use dto::ToWire;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc::{UnboundedReceiver, unbounded_channel};
use tokio::sync::{Mutex, RwLock, broadcast};
use uuid::Uuid;

#[derive(Debug, Clone)]
struct PreparedMigration {
    source: SourceConfig,
    plan: arcbox_migration::MigrationPlan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MigrationRunOptions {
    allow_replacements: bool,
    skip_start: bool,
}

impl From<&RunMigrationRequest> for MigrationRunOptions {
    fn from(request: &RunMigrationRequest) -> Self {
        Self {
            allow_replacements: request.allow_replacements,
            skip_start: request.skip_start,
        }
    }
}

/// Buffered progress events per attached client. A migration emits one per
/// resource; the margin covers a client that stalls briefly without losing the
/// stage it stalled on.
const EVENT_BUFFER: usize = 256;

/// One run's event history, in the two shapes its two readers need.
///
/// A reattaching client needs the *latest* event; a live client needs *every*
/// event. Those cannot be the same channel — this is the `SetupState` lesson
/// (CORE-67, see `app/AGENTS.md`) in a second place: a snapshot channel
/// coalesces whenever the reader has not been scheduled, and the executor emits
/// its last per-resource progress and the terminal event with no await between
/// them, so the progress a UI exists to show is exactly what gets dropped.
///
/// So: `latest` retains, `updates` delivers, and [`MigrationRun::publish`]
/// writes both under one lock while [`MigrationRun::subscribe`] takes both
/// under the matching read lock. Split either pair and a client either misses
/// an update or replays one already folded into its snapshot.
#[derive(Debug, Clone)]
struct MigrationRun {
    options: MigrationRunOptions,
    latest: Arc<std::sync::RwLock<Option<RunMigrationEvent>>>,
    updates: broadcast::Sender<RunMigrationEvent>,
}

impl MigrationRun {
    fn new(options: MigrationRunOptions) -> Self {
        Self {
            options,
            latest: Arc::new(std::sync::RwLock::new(None)),
            updates: broadcast::channel(EVENT_BUFFER).0,
        }
    }

    /// Whether this run has yet to reach a terminal event.
    fn is_active(&self) -> bool {
        self.latest
            .read()
            .expect("migration run state is never held across a panic")
            .as_ref()
            .is_none_or(|event| !event.done)
    }

    /// Publishes one event. Synchronous because the executor's progress
    /// callback is: the lock is held for a clone and a send, never across an
    /// await.
    fn publish(&self, event: RunMigrationEvent) {
        let mut latest = self
            .latest
            .write()
            .expect("migration run state is never held across a panic");
        // Fails only when nobody is attached, which is the common case.
        let _ = self.updates.send(event.clone());
        *latest = Some(event);
    }

    fn subscribe(&self) -> UnboundedReceiver<Result<RunMigrationEvent>> {
        let (snapshot, mut updates) = {
            let latest = self
                .latest
                .read()
                .expect("migration run state is never held across a panic");
            (latest.clone(), self.updates.subscribe())
        };
        let (tx, rx) = unbounded_channel();

        tokio::spawn(async move {
            // The snapshot is this client's starting point: for a finished run
            // it is the terminal event and the stream ends on it; for a live
            // one it is the stage the run has reached, and `updates` carries
            // the rest without gaps.
            if let Some(event) = snapshot {
                let done = event.done;
                if tx.send(Ok(event)).is_err() || done {
                    return;
                }
            }
            loop {
                match updates.recv().await {
                    Ok(event) => {
                        let done = event.done;
                        if tx.send(Ok(event)).is_err() || done {
                            return;
                        }
                    }
                    // A client that stalled past the buffer loses the oldest
                    // events rather than the stream: progress is advisory, and
                    // the terminal event is what it cannot afford to miss.
                    Err(broadcast::error::RecvError::Lagged(dropped)) => {
                        tracing::warn!(dropped, "migration client fell behind its event stream");
                    }
                    Err(broadcast::error::RecvError::Closed) => return,
                }
            }
        });

        rx
    }
}

/// Host-side migration manager.
#[derive(Debug)]
pub struct MigrationManager {
    target_socket: PathBuf,
    prepared: RwLock<HashMap<String, PreparedMigration>>,
    runs: RwLock<HashMap<String, MigrationRun>>,
    run_start: Mutex<()>,
}

impl MigrationManager {
    /// Creates a migration manager for the target Docker socket.
    #[must_use]
    pub fn new(target_socket: PathBuf) -> Self {
        Self {
            target_socket,
            prepared: RwLock::new(HashMap::new()),
            runs: RwLock::new(HashMap::new()),
            run_start: Mutex::new(()),
        }
    }

    /// Prepares a migration plan.
    pub async fn prepare_migration(
        &self,
        request: PrepareMigrationRequest,
    ) -> Result<PrepareMigrationResponse> {
        let source_kind = parse_source_kind(&request.source_kind)?;
        let source = resolve_source(
            source_kind,
            non_empty_path(request.source_socket_path.as_str()),
        )
        .map_err(map_migration_error)?;
        let target_runner =
            DockerCliRunner::new(self.target_socket.clone()).map_err(map_migration_error)?;
        let planner = MigrationPlanner::new(target_runner);
        let plan = planner
            .plan(source.clone())
            .await
            .map_err(map_migration_error)?;

        // Unsupported resources are reported rather than raised here: the
        // executor already refuses to run a plan that has any, and callers
        // inspecting a plan need to see *why* it is blocked.
        //
        // Nothing is stored unless the plan can actually be run: `run_migration`
        // is the only thing that removes entries, so storing a plan no caller
        // will ever run would retain it for the life of the daemon. That covers
        // both a dry run and a plan the executor would refuse anyway.
        let runnable = !request.dry_run && plan.unsupported_resources.is_empty();
        let plan_id = if runnable {
            let plan_id = Uuid::new_v4().to_string();
            self.prepared.write().await.insert(
                plan_id.clone(),
                PreparedMigration {
                    source,
                    plan: plan.clone(),
                },
            );
            plan_id
        } else {
            String::new()
        };

        let mut warnings = Vec::new();
        warnings.extend(plan.blockers.iter().map(|blocker| {
            format!(
                "volume '{}' is attached to running source containers: {}",
                blocker.volume_name,
                blocker.containers.join(", ")
            )
        }));
        warnings.extend(plan.warnings.iter().cloned());

        Ok(PrepareMigrationResponse {
            plan_id,
            source_kind: plan.source.kind.as_str().to_string(),
            source_socket_path: plan.source.socket_path.to_string_lossy().to_string(),
            image_count: u32::try_from(plan.images.len()).unwrap_or(u32::MAX),
            volume_count: u32::try_from(plan.volumes.len()).unwrap_or(u32::MAX),
            network_count: u32::try_from(plan.networks.len()).unwrap_or(u32::MAX),
            container_count: u32::try_from(plan.containers.len()).unwrap_or(u32::MAX),
            // Only indicates actual ArcBox resource replacements; blockers
            // are surfaced via `warnings`.
            replacements_required: !plan.replacements.is_empty(),
            warnings,
            // Only for an explicit dry run: the plan embeds each container's
            // environment verbatim, so it is not worth shipping on a prepare
            // whose caller is about to run the migration anyway.
            plan: request
                .dry_run
                .then(|| plan.to_wire())
                .map_or_else(Default::default, Into::into),
            unsupported_resources: plan.unsupported_resources.clone(),
            ..Default::default()
        })
    }

    /// Runs a prepared migration plan.
    pub async fn run_migration(
        &self,
        request: RunMigrationRequest,
    ) -> Result<UnboundedReceiver<Result<RunMigrationEvent>>> {
        let _start = self.run_start.lock().await;
        let run_options = MigrationRunOptions::from(&request);

        let existing = self.runs.read().await.get(&request.plan_id).cloned();
        if let Some(run) = existing {
            if run.options != run_options {
                return Err(CoreError::invalid_state(format!(
                    "migration {} is already running with different options",
                    request.plan_id
                )));
            }
            return Ok(run.subscribe());
        }

        if self.runs.read().await.values().any(MigrationRun::is_active) {
            return Err(CoreError::invalid_state(
                "another migration is already running",
            ));
        }

        let prepared = self
            .prepared
            .read()
            .await
            .get(&request.plan_id)
            .cloned()
            .ok_or_else(|| CoreError::not_found(format!("migration plan {}", request.plan_id)))?;

        let requires_confirmation =
            !prepared.plan.replacements.is_empty() || !prepared.plan.blockers.is_empty();
        if requires_confirmation && !request.allow_replacements {
            return Err(CoreError::invalid_state(
                "migration requires confirmation for replacement or stopping source containers",
            ));
        }

        let target_runner =
            DockerCliRunner::new(self.target_socket.clone()).map_err(map_migration_error)?;
        let executor = MigrationExecutor::new(target_runner);
        let executor_options = MigrationExecutorOptions {
            confirm_replace: request.allow_replacements,
            confirm_stop_source_containers: request.allow_replacements,
            start_containers: !request.skip_start,
        };
        let plan_id = request.plan_id.clone();
        // Consume the plan and publish its run without a cancellation point
        // between the two state transitions.
        let (prepared, run) = {
            let (mut prepared_plans, mut runs) =
                tokio::join!(self.prepared.write(), self.runs.write());
            let prepared = prepared_plans.remove(&request.plan_id).ok_or_else(|| {
                CoreError::not_found(format!("migration plan {}", request.plan_id))
            })?;
            let run = MigrationRun::new(run_options);
            // ponytail: retain tiny terminal snapshots for the daemon lifetime;
            // add bounded durable history if migration volume makes this material.
            runs.insert(plan_id.clone(), run.clone());
            (prepared, run)
        };
        let source = prepared.source;
        let plan = prepared.plan;
        let receiver = run.subscribe();

        tokio::spawn(async move {
            let mut emit = |progress: MigrationProgress| {
                // Intermediate events: done=false, success is not meaningful
                // yet so we leave it as true (not-failed-yet) to avoid
                // misleading clients that check `success` without gating on
                // `done`.
                let event = progress_to_event(&plan_id, progress, false, true);
                run.publish(event);
            };

            match executor
                .execute(source, &plan, executor_options, &mut emit)
                .await
            {
                Ok(outcome) => {
                    let detail = if outcome.warnings.is_empty() {
                        "migration completed".to_string()
                    } else {
                        format!(
                            "migration completed with {} warning(s)",
                            outcome.warnings.len()
                        )
                    };
                    let mut event = progress_to_event(
                        &plan_id,
                        MigrationProgress {
                            stage: arcbox_migration::MigrationStage::Complete,
                            detail,
                            resource_type: None,
                            resource_name: None,
                            current: None,
                            total: None,
                        },
                        true,
                        true,
                    );
                    event.warnings = outcome.warnings;
                    run.publish(event);
                }
                Err(error) => {
                    run.publish(progress_to_event(
                        &plan_id,
                        MigrationProgress {
                            stage: arcbox_migration::MigrationStage::Complete,
                            detail: error.to_string(),
                            resource_type: None,
                            resource_name: None,
                            current: None,
                            total: None,
                        },
                        true,
                        false,
                    ));
                }
            }
        });

        Ok(receiver)
    }
}

fn parse_source_kind(value: &str) -> Result<SourceKind> {
    match value {
        "docker-desktop" => Ok(SourceKind::DockerDesktop),
        "orbstack" => Ok(SourceKind::OrbStack),
        other => Err(CoreError::config(format!(
            "unsupported migration source '{}'",
            other
        ))),
    }
}

fn non_empty_path(value: &str) -> Option<PathBuf> {
    if value.is_empty() {
        None
    } else {
        Some(PathBuf::from(value))
    }
}

fn progress_to_event(
    plan_id: &str,
    progress: MigrationProgress,
    done: bool,
    success: bool,
) -> RunMigrationEvent {
    RunMigrationEvent {
        plan_id: plan_id.to_string(),
        phase: progress.stage.as_str().to_string(),
        resource: progress.resource_name.unwrap_or_default(),
        message: progress.detail,
        completed: progress.current.unwrap_or(0),
        total: progress.total.unwrap_or(0),
        done,
        success,
        // Only the terminal event carries warnings; the caller fills them in.
        warnings: Vec::new(),
        ..Default::default()
    }
}

fn map_migration_error(error: MigrationError) -> CoreError {
    match error {
        MigrationError::MissingSource { .. }
        | MigrationError::UnsupportedSource(_)
        | MigrationError::UnsupportedResource(_)
        | MigrationError::InvalidPlan(_) => CoreError::config(error.to_string()),
        MigrationError::Blocked(_) => CoreError::invalid_state(error.to_string()),
        MigrationError::Docker(_) => CoreError::Machine(error.to_string()),
        MigrationError::Io(io_error) => io_error.into(),
        MigrationError::SerdeJson(error) => CoreError::Machine(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arcbox_migration::{MigrationPlan, ReplacementSummary, SourceInfo};
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::Path;

    /// Serializes the tests that repoint `PATH` at a `docker` stand-in.
    ///
    /// A tokio mutex so it can be held across the awaits it guards; `PATH` is
    /// process-global, so releasing it earlier would let concurrent tests
    /// observe each other's shim.
    static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// Installs an executable `docker` in `dir` and points `PATH` at it.
    ///
    /// Returns the previous `PATH` so the caller can restore it.
    fn install_docker_shim(dir: &Path, script: &str) -> Option<std::ffi::OsString> {
        let docker_path = dir.join("docker");
        std::fs::write(&docker_path, script).unwrap();
        let mut permissions = std::fs::metadata(&docker_path).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&docker_path, permissions).unwrap();

        let previous = std::env::var_os("PATH");
        // SAFETY: env mutation in tests is serialized by ENV_LOCK.
        unsafe { std::env::set_var("PATH", dir) };
        previous
    }

    fn restore_path(previous: Option<std::ffi::OsString>) {
        // SAFETY: env mutation in tests is serialized by ENV_LOCK.
        unsafe {
            match previous {
                Some(value) => std::env::set_var("PATH", value),
                None => std::env::remove_var("PATH"),
            }
        }
    }

    /// A `docker` that reports a reachable but completely empty daemon.
    ///
    /// Every listing comes back empty, so `inspect_many` short-circuits and
    /// planning only ever needs a real answer for `docker info`.
    const EMPTY_DAEMON_SHIM: &str = r#"#!/bin/sh
case "$*" in
  *"info --format"*)
    echo '{"Name":"orbstack","ServerVersion":"29.0","OperatingSystem":"OrbStack","Architecture":"aarch64"}'
    ;;
esac
exit 0
"#;

    const FAILING_SHIM: &str = "#!/bin/sh\nexit 1\n";

    /// Builds a prepare request against a source socket that exists.
    fn prepare_request(socket: &Path, dry_run: bool) -> PrepareMigrationRequest {
        PrepareMigrationRequest {
            source_kind: "orbstack".to_string(),
            source_socket_path: socket.to_string_lossy().into_owned(),
            allow_replacements: true,
            dry_run,
            ..Default::default()
        }
    }

    fn sample_plan() -> MigrationPlan {
        MigrationPlan {
            source: SourceInfo {
                kind: SourceKind::DockerDesktop,
                socket_path: PathBuf::from("/tmp/docker.sock"),
                daemon_name: "docker-desktop".to_string(),
                server_version: "29.0".to_string(),
                operating_system: "Docker Desktop".to_string(),
                architecture: "aarch64".to_string(),
            },
            helper_image: "arcbox-migration-helper:latest".to_string(),
            images: Vec::new(),
            volumes: Vec::new(),
            networks: Vec::new(),
            containers: Vec::new(),
            unsupported_resources: Vec::new(),
            warnings: Vec::new(),
            replacements: ReplacementSummary {
                containers: vec!["conflict".to_string()],
                ..Default::default()
            },
            blockers: Vec::new(),
        }
    }

    async fn terminal_event(
        events: &mut UnboundedReceiver<Result<RunMigrationEvent>>,
    ) -> RunMigrationEvent {
        while let Some(event) = events.recv().await {
            let event = event.unwrap();
            if event.done {
                return event;
            }
        }
        panic!("migration stream ended without a terminal event");
    }

    fn event(message: &str, done: bool) -> RunMigrationEvent {
        RunMigrationEvent {
            plan_id: "test-plan".to_string(),
            message: message.to_string(),
            done,
            success: true,
            ..Default::default()
        }
    }

    /// An attached client must see every event, not the newest snapshot. The
    /// executor emits its last per-resource progress and the terminal event
    /// with no await between them, so a coalescing channel drops precisely the
    /// progress a migration UI exists to show. Same failure as CORE-67's
    /// `SetupState`, one layer down.
    #[tokio::test]
    async fn an_attached_client_sees_every_event_not_the_latest() {
        let run = MigrationRun::new(MigrationRunOptions {
            allow_replacements: true,
            skip_start: false,
        });
        let mut events = run.subscribe();

        // Published back to back, with no await for the subscriber to be
        // scheduled in between — the shape that coalesces.
        run.publish(event("copying volume 1", false));
        run.publish(event("copying volume 2", false));
        run.publish(event("migration completed", true));

        let mut seen = Vec::new();
        while let Some(received) = events.recv().await {
            seen.push(received.unwrap().message);
        }
        assert_eq!(
            seen,
            vec![
                "copying volume 1",
                "copying volume 2",
                "migration completed"
            ]
        );
    }

    /// A client attaching mid-run starts from where the run has reached and
    /// then follows it live — without replaying what the snapshot already
    /// carried.
    #[tokio::test]
    async fn a_late_client_starts_from_the_snapshot_and_then_follows() {
        let run = MigrationRun::new(MigrationRunOptions {
            allow_replacements: true,
            skip_start: false,
        });
        run.publish(event("copying volume 1", false));

        let mut events = run.subscribe();
        run.publish(event("migration completed", true));

        let mut seen = Vec::new();
        while let Some(received) = events.recv().await {
            seen.push(received.unwrap().message);
        }
        assert_eq!(seen, vec!["copying volume 1", "migration completed"]);
    }

    #[tokio::test]
    async fn run_migration_keeps_plan_when_confirmation_is_missing() {
        let manager = MigrationManager::new(PathBuf::from("/tmp/arcbox-docker.sock"));
        let plan_id = "test-plan".to_string();
        manager.prepared.write().await.insert(
            plan_id.clone(),
            PreparedMigration {
                source: SourceConfig {
                    kind: SourceKind::DockerDesktop,
                    socket_path: PathBuf::from("/tmp/docker.sock"),
                },
                plan: sample_plan(),
            },
        );

        let error = manager
            .run_migration(RunMigrationRequest {
                plan_id: plan_id.clone(),
                allow_replacements: false,
                skip_start: false,
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert!(error.to_string().contains("requires confirmation"));
        assert!(manager.prepared.read().await.contains_key(&plan_id));
    }

    #[tokio::test]
    async fn run_migration_removes_plan_after_starting() {
        let manager = MigrationManager::new(PathBuf::from("/tmp/arcbox-docker.sock"));
        let plan_id = "test-plan".to_string();
        manager.prepared.write().await.insert(
            plan_id.clone(),
            PreparedMigration {
                source: SourceConfig {
                    kind: SourceKind::DockerDesktop,
                    socket_path: PathBuf::from("/tmp/docker.sock"),
                },
                plan: MigrationPlan {
                    replacements: ReplacementSummary::default(),
                    ..sample_plan()
                },
            },
        );

        let _env_lock = ENV_LOCK.lock().await;
        let temp_dir = tempfile::tempdir().unwrap();
        let previous_path = install_docker_shim(temp_dir.path(), FAILING_SHIM);

        let _ = manager
            .run_migration(RunMigrationRequest {
                plan_id: plan_id.clone(),
                allow_replacements: true,
                skip_start: false,
                ..Default::default()
            })
            .await
            .unwrap();

        restore_path(previous_path);

        assert!(!manager.prepared.read().await.contains_key(&plan_id));
    }

    /// Stores a prepared plan that the executor will reject, so a run reaches
    /// a terminal failure without touching a real Docker socket.
    async fn prepare_unsupported(manager: &MigrationManager, plan_id: &str, unsupported: &str) {
        manager.prepared.write().await.insert(
            plan_id.to_string(),
            PreparedMigration {
                source: SourceConfig {
                    kind: SourceKind::DockerDesktop,
                    socket_path: PathBuf::from("/tmp/docker.sock"),
                },
                plan: MigrationPlan {
                    replacements: ReplacementSummary::default(),
                    unsupported_resources: vec![unsupported.to_string()],
                    ..sample_plan()
                },
            },
        );
    }

    fn run_request(plan_id: &str) -> RunMigrationRequest {
        RunMigrationRequest {
            plan_id: plan_id.to_string(),
            allow_replacements: true,
            skip_start: false,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn unsupported_resources_fail_the_run_rather_than_the_prepare() {
        let manager = MigrationManager::new(PathBuf::from("/tmp/arcbox-docker.sock"));
        prepare_unsupported(&manager, "test-plan", "container 'vpn-client' shares").await;

        let _env_lock = ENV_LOCK.lock().await;
        let temp_dir = tempfile::tempdir().unwrap();
        let previous_path = install_docker_shim(temp_dir.path(), FAILING_SHIM);

        let mut events = manager
            .run_migration(run_request("test-plan"))
            .await
            .unwrap();
        let event = terminal_event(&mut events).await;

        restore_path(previous_path);

        assert!(event.done);
        assert!(!event.success);
        assert!(event.message.contains("unsupported resources"));
    }

    /// A client that lost its stream must be able to reattach and learn how the
    /// run ended — including after an unrelated migration has come and gone,
    /// which is what makes this a per-plan record rather than a "last run" slot.
    #[tokio::test]
    async fn terminal_result_survives_a_later_migration() {
        let manager = MigrationManager::new(PathBuf::from("/tmp/arcbox-docker.sock"));
        prepare_unsupported(&manager, "test-plan", "container 'vpn-client' shares").await;

        let _env_lock = ENV_LOCK.lock().await;
        let temp_dir = tempfile::tempdir().unwrap();
        let previous_path = install_docker_shim(temp_dir.path(), FAILING_SHIM);

        let mut events = manager
            .run_migration(run_request("test-plan"))
            .await
            .unwrap();
        let event = terminal_event(&mut events).await;

        prepare_unsupported(&manager, "next-plan", "another unsupported resource").await;
        let mut next_events = manager
            .run_migration(run_request("next-plan"))
            .await
            .unwrap();
        terminal_event(&mut next_events).await;

        let mut reattached = manager
            .run_migration(run_request("test-plan"))
            .await
            .unwrap();
        let replayed = terminal_event(&mut reattached).await;

        restore_path(previous_path);

        assert_eq!(replayed, event);
    }

    #[tokio::test]
    async fn concurrent_plan_is_rejected_without_being_consumed() {
        let manager = MigrationManager::new(PathBuf::from("/tmp/arcbox-docker.sock"));
        manager.runs.write().await.insert(
            "active-plan".to_string(),
            MigrationRun::new(MigrationRunOptions {
                allow_replacements: true,
                skip_start: false,
            }),
        );
        manager.prepared.write().await.insert(
            "next-plan".to_string(),
            PreparedMigration {
                source: SourceConfig {
                    kind: SourceKind::DockerDesktop,
                    socket_path: PathBuf::from("/tmp/docker.sock"),
                },
                plan: MigrationPlan {
                    replacements: ReplacementSummary::default(),
                    ..sample_plan()
                },
            },
        );

        let error = manager
            .run_migration(RunMigrationRequest {
                plan_id: "next-plan".to_string(),
                allow_replacements: true,
                skip_start: false,
                ..Default::default()
            })
            .await
            .unwrap_err();

        assert!(error.to_string().contains("another migration"));
        assert!(manager.prepared.read().await.contains_key("next-plan"));
    }

    #[tokio::test]
    async fn dry_run_returns_the_plan_without_storing_it() {
        let _env_lock = ENV_LOCK.lock().await;
        let temp_dir = tempfile::tempdir().unwrap();
        let previous_path = install_docker_shim(temp_dir.path(), EMPTY_DAEMON_SHIM);
        let socket = temp_dir.path().join("docker.sock");
        std::fs::write(&socket, "").unwrap();

        let manager = MigrationManager::new(temp_dir.path().join("arcbox-docker.sock"));
        let response = manager
            .prepare_migration(prepare_request(&socket, true))
            .await;

        restore_path(previous_path);
        let response = response.unwrap();

        assert!(response.plan_id.is_empty(), "a dry run issues no plan id");
        let plan = response.plan.expect("a dry run ships the plan");
        assert!(
            plan.source.is_set(),
            "the plan's source is always projected"
        );
        assert!(
            manager.prepared.read().await.is_empty(),
            "a dry run must not accumulate plans in the daemon"
        );
    }

    #[tokio::test]
    async fn a_real_prepare_stores_the_plan_and_issues_an_id() {
        let _env_lock = ENV_LOCK.lock().await;
        let temp_dir = tempfile::tempdir().unwrap();
        let previous_path = install_docker_shim(temp_dir.path(), EMPTY_DAEMON_SHIM);
        let socket = temp_dir.path().join("docker.sock");
        std::fs::write(&socket, "").unwrap();

        let manager = MigrationManager::new(temp_dir.path().join("arcbox-docker.sock"));
        let response = manager
            .prepare_migration(prepare_request(&socket, false))
            .await;

        restore_path(previous_path);
        let response = response.unwrap();

        assert!(!response.plan_id.is_empty());
        assert_eq!(manager.prepared.read().await.len(), 1);
        // The plan embeds container environments; it ships only when a caller
        // explicitly asked to inspect it.
        assert!(
            response.plan.is_unset(),
            "a runnable prepare must not ship the plan payload"
        );
    }
}
