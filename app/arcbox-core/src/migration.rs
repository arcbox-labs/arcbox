//! Host-side runtime migration manager.

use crate::error::{CoreError, Result};
use arcbox_migration::{
    DockerCliRunner, MigrationError, MigrationExecutor, MigrationExecutorOptions, MigrationPlanner,
    MigrationProgress, SourceConfig, SourceKind, resolve_source,
};
use arcbox_protocol::v1::{
    PrepareMigrationRequest, PrepareMigrationResponse, RunMigrationEvent, RunMigrationRequest,
};
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::sync::RwLock;
use tokio::sync::mpsc::{UnboundedReceiver, unbounded_channel};
use uuid::Uuid;

#[derive(Debug, Clone)]
struct PreparedMigration {
    source: SourceConfig,
    plan: arcbox_migration::MigrationPlan,
}

/// Host-side migration manager.
#[derive(Debug)]
pub struct MigrationManager {
    target_socket: PathBuf,
    prepared: RwLock<HashMap<String, PreparedMigration>>,
}

impl MigrationManager {
    /// Creates a migration manager for the target Docker socket.
    #[must_use]
    pub fn new(target_socket: PathBuf) -> Self {
        Self {
            target_socket,
            prepared: RwLock::new(HashMap::new()),
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

        if !plan.unsupported_resources.is_empty() {
            return Err(CoreError::config(format!(
                "source contains unsupported resources: {}",
                plan.unsupported_resources.join(", ")
            )));
        }

        let plan_id = Uuid::new_v4().to_string();
        self.prepared.write().await.insert(
            plan_id.clone(),
            PreparedMigration {
                source,
                plan: plan.clone(),
            },
        );

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
            plan_json: serde_json::to_string(&plan).unwrap_or_default(),
            unsupported_resources: plan.unsupported_resources.clone(),
        })
    }

    /// Runs a prepared migration plan.
    pub async fn run_migration(
        &self,
        request: RunMigrationRequest,
    ) -> Result<UnboundedReceiver<Result<RunMigrationEvent>>> {
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
        let options = MigrationExecutorOptions {
            confirm_replace: request.allow_replacements,
            confirm_stop_source_containers: request.allow_replacements,
            start_containers: !request.skip_start,
        };
        let plan_id = request.plan_id.clone();
        let prepared = self
            .prepared
            .write()
            .await
            .remove(&request.plan_id)
            .ok_or_else(|| CoreError::not_found(format!("migration plan {}", request.plan_id)))?;
        let source = prepared.source;
        let plan = prepared.plan;
        let (tx, rx) = unbounded_channel();

        tokio::spawn(async move {
            let mut emit = |progress: MigrationProgress| {
                // Intermediate events: done=false, success is not meaningful
                // yet so we leave it as true (not-failed-yet) to avoid
                // misleading clients that check `success` without gating on
                // `done`.
                let event = progress_to_event(&plan_id, progress, false, true);
                let _ = tx.send(Ok(event));
            };

            match executor.execute(source, &plan, options, &mut emit).await {
                Ok(()) => {
                    let _ = tx.send(Ok(progress_to_event(
                        &plan_id,
                        MigrationProgress {
                            stage: arcbox_migration::MigrationStage::Complete,
                            detail: "migration completed".to_string(),
                            resource_type: None,
                            resource_name: None,
                            current: None,
                            total: None,
                        },
                        true,
                        true,
                    )));
                }
                Err(error) => {
                    let _ = tx.send(Ok(progress_to_event(
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
                    )));
                }
            }
        });

        Ok(rx)
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
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

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

        let temp_dir = tempfile::tempdir().unwrap();
        let docker_path = temp_dir.path().join("docker");
        std::fs::write(&docker_path, "#!/bin/sh\nexit 1\n").unwrap();
        let mut permissions = std::fs::metadata(&docker_path).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&docker_path, permissions).unwrap();

        // Hold ENV_LOCK only during the synchronous env mutation; drop
        // it before any `.await` to satisfy clippy::await_holding_lock.
        {
            let _env_lock = ENV_LOCK.lock().unwrap();
            // SAFETY: tests serialize environment mutation with ENV_LOCK.
            unsafe {
                std::env::set_var("PATH", temp_dir.path());
            }
        }

        let _ = manager
            .run_migration(RunMigrationRequest {
                plan_id: plan_id.clone(),
                allow_replacements: true,
                skip_start: false,
            })
            .await
            .unwrap();

        {
            let _env_lock = ENV_LOCK.lock().unwrap();
            // SAFETY: tests serialize environment mutation with ENV_LOCK.
            unsafe {
                std::env::remove_var("PATH");
            }
        }

        assert!(!manager.prepared.read().await.contains_key(&plan_id));
    }
}
