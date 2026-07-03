//! `FleetImageService` — converges each image setting's `current` onto its
//! `target` by fetching and verifying the target artifact through the
//! runtime that owns it (the Docker socket today; the arcbox-daemon socket
//! once the macOS VM backend lands), streaming progress. Split from
//! `FleetSettingsService` so quick state reads/writes never share a service
//! with RPCs that stream a multi-gigabyte transfer.

use std::pin::Pin;
use std::sync::Arc;

use arcbox_fleet_control_proto::v1::fleet_image_service_server::FleetImageService as FleetImageServiceTrait;
use arcbox_fleet_control_proto::v1::{ImageKind, PrepareRequest, PrepareResponse};
use tokio_stream::Stream;
use tonic::{Request, Response, Status};

use crate::docker::DockerRunner;
use crate::state::AgentState;

pub struct ImageService {
    state: AgentState,
    /// The process-lifetime Docker handle, if configured. Never stale:
    /// `docker_mode` changes are restart-scoped (see
    /// `AgentSupervisor::docker`'s doc).
    docker: Option<DockerRunner>,
    /// Serializes preparations. Two racing Prepares would pull concurrently
    /// and promote in arbitrary order, so the loser gets `ABORTED` instead
    /// of queueing behind a transfer of unknown length.
    busy: Arc<tokio::sync::Mutex<()>>,
}

impl ImageService {
    pub fn new(state: AgentState, docker: Option<DockerRunner>) -> Self {
        Self {
            state,
            docker,
            busy: Arc::new(tokio::sync::Mutex::new(())),
        }
    }
}

fn event(kind: ImageKind, detail: &str, stage: &str, fraction: f64) -> PrepareResponse {
    PrepareResponse {
        kind: kind as i32,
        detail: detail.to_owned(),
        stage: stage.to_owned(),
        fraction,
    }
}

/// Expand the requested kinds: empty prepares every kind this agent
/// supports. An unrecognized kind (a newer client) is rejected rather than
/// silently skipped, so "prepare everything I asked for" never quietly
/// under-delivers. Duplicates collapse to one preparation.
///
/// Returns a plain message rather than `Status` — every failure here maps
/// to the same `INVALID_ARGUMENT` code, so the caller does that one
/// conversion (the same convention as `control::settings::validate`).
fn resolve_kinds(raw: &[i32]) -> Result<Vec<ImageKind>, String> {
    if raw.is_empty() {
        return Ok(vec![ImageKind::LinuxRunnerImage]);
    }
    let mut kinds = raw
        .iter()
        .map(|&v| match ImageKind::try_from(v) {
            Ok(ImageKind::LinuxRunnerImage) => Ok(ImageKind::LinuxRunnerImage),
            Ok(ImageKind::Unspecified) | Err(_) => Err(format!("unsupported image kind {v}")),
        })
        .collect::<Result<Vec<_>, _>>()?;
    kinds.sort_unstable();
    kinds.dedup();
    Ok(kinds)
}

#[tonic::async_trait]
impl FleetImageServiceTrait for ImageService {
    type PrepareStream = Pin<Box<dyn Stream<Item = Result<PrepareResponse, Status>> + Send>>;

    async fn prepare(
        &self,
        request: Request<PrepareRequest>,
    ) -> Result<Response<Self::PrepareStream>, Status> {
        let kinds = resolve_kinds(&request.into_inner().kinds).map_err(Status::invalid_argument)?;
        let busy = Arc::clone(&self.busy)
            .try_lock_owned()
            .map_err(|_| Status::aborted("another prepare is already in progress"))?;
        let state = self.state.clone();
        let docker = self.docker.clone();

        // The work runs inside the stream itself, not a detached task, so a
        // client disconnect drops it mid-pull: no promotion happens, and a
        // re-run resumes from whatever the runtime already cached.
        let stream = async_stream::try_stream! {
            let _busy = busy;
            for kind in kinds {
                // `resolve_kinds` admits no other variant.
                debug_assert_eq!(kind, ImageKind::LinuxRunnerImage);
                let target = state.linux_runner_image_target();
                match &docker {
                    Some(docker) => {
                        // All-or-nothing: every advertised arch must pull
                        // before promotion, so a partial-arch image can
                        // never become current while the full capability
                        // set is still advertised. Fail-fast on the first
                        // arch that can't — `current` is left untouched.
                        for arch in docker.linux_arches() {
                            let platform = format!("linux/{arch}");
                            yield event(kind, &platform, "pulling", 0.0);
                            docker.pull(&target, &arch).await.map_err(|e| {
                                Status::failed_precondition(format!(
                                    "linux_runner_image {target} is not pullable for \
                                     {platform}; current image left unchanged: {e:#}"
                                ))
                            })?;
                            yield event(kind, &platform, "pulling", 1.0);
                        }
                    }
                    // Without Docker no Linux job can dispatch, so there is
                    // nothing to verify the image against — promote rather
                    // than leave the setting pending forever on a
                    // host-runner-only box. (Startup behaves the same way:
                    // `AgentState::new` seeds current == target, and it is
                    // `init_docker` that verifies the seed when Docker is on.)
                    None => yield event(kind, "docker not configured", "skipped", 1.0),
                }
                state.set_linux_runner_image_current(&target);
                yield event(kind, "", "promoted", 1.0);
            }
        };
        Ok(Response::new(Box::pin(stream)))
    }
}

#[cfg(test)]
mod tests {
    use tokio_stream::StreamExt;

    use super::*;
    use crate::config::DockerMode;
    use crate::settings::PersistedSettings;

    fn seed() -> PersistedSettings {
        PersistedSettings {
            load_ceiling: 0.9,
            mem_floor_mib: 2048,
            linux_runner_image: "ghcr.io/actions/actions-runner:latest".to_owned(),
            gateway: "https://fleet.arcbox.dev".to_owned(),
            docker_mode: DockerMode::Disabled,
            runner_script: None,
        }
    }

    #[test]
    fn empty_kinds_resolve_to_every_supported_kind() {
        assert_eq!(
            resolve_kinds(&[]).unwrap(),
            vec![ImageKind::LinuxRunnerImage]
        );
    }

    #[test]
    fn duplicate_kinds_collapse() {
        let raw = [
            ImageKind::LinuxRunnerImage as i32,
            ImageKind::LinuxRunnerImage as i32,
        ];
        assert_eq!(
            resolve_kinds(&raw).unwrap(),
            vec![ImageKind::LinuxRunnerImage]
        );
    }

    #[test]
    fn unknown_and_unspecified_kinds_are_rejected() {
        for bad in [0, 999] {
            assert!(resolve_kinds(&[bad]).is_err(), "accepted kind {bad}");
        }
    }

    /// The real pull path needs a live Docker daemon (see `docker.rs`, which
    /// has no unit tests for the same reason); the no-Docker branch is the
    /// unit-testable half of the promotion contract: nothing to verify
    /// against, so the target is promoted rather than pending forever.
    #[tokio::test]
    async fn prepare_without_docker_promotes_target() {
        let state = AgentState::new(&seed());
        state.set_linux_runner_image_target("ghcr.io/acme/runner:v2");
        let service = ImageService::new(state.clone(), None);

        let mut stream = service
            .prepare(Request::new(PrepareRequest { kinds: Vec::new() }))
            .await
            .expect("Prepare")
            .into_inner();
        let mut stages = Vec::new();
        while let Some(item) = stream.next().await {
            stages.push(item.expect("event").stage);
        }

        assert_eq!(stages, ["skipped", "promoted"]);
        assert_eq!(state.linux_runner_image_current(), "ghcr.io/acme/runner:v2");
        assert_eq!(
            state.linux_runner_image_current(),
            state.linux_runner_image_target()
        );
    }

    /// A second Prepare while one is live must be refused, not queued — and
    /// dropping the live stream (client disconnect) must release the slot.
    #[tokio::test]
    async fn concurrent_prepare_is_refused_until_the_first_stream_drops() {
        let service = ImageService::new(AgentState::new(&seed()), None);

        let held = service
            .prepare(Request::new(PrepareRequest { kinds: Vec::new() }))
            .await
            .expect("first Prepare");
        let Err(err) = service
            .prepare(Request::new(PrepareRequest { kinds: Vec::new() }))
            .await
        else {
            panic!("second Prepare while the first is live must be refused");
        };
        assert_eq!(err.code(), tonic::Code::Aborted);

        drop(held);
        service
            .prepare(Request::new(PrepareRequest { kinds: Vec::new() }))
            .await
            .expect("Prepare after the first stream dropped");
    }
}
