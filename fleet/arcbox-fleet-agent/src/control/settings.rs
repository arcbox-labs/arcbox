//! `FleetSettingsService` — the tonic server impl. Reads/writes
//! [`AgentState`] directly; no `AgentSupervisor` dependency, even for
//! `participate` — the one setting that deliberately touches the attach
//! lifecycle. This service only writes its target; the supervisor's
//! participation reconciler observes the same watch channel and converges
//! (`AgentSupervisor::spawn_participation_reconciler`), so lifecycle
//! ownership stays in exactly one place.

use std::path::Path;

use arcbox_fleet_control_proto::v1::fleet_settings_service_server::FleetSettingsService as FleetSettingsServiceTrait;
use arcbox_fleet_control_proto::v1::{
    Enrollment, GetSettingsRequest, GetSettingsResponse, UpdateSettingsRequest,
    UpdateSettingsResponse,
};
use tonic::transport::Endpoint;
use tonic::{Request, Response, Status};

use super::Internal;
use crate::config::DockerMode;
use crate::settings::SettingsStore;
use crate::state::{AgentState, docker_mode_from_wire};

pub struct SettingsService {
    state: AgentState,
    store: SettingsStore,
}

impl SettingsService {
    pub fn new(state: AgentState, store: SettingsStore) -> Self {
        Self { state, store }
    }
}

#[tonic::async_trait]
impl FleetSettingsServiceTrait for SettingsService {
    async fn get_settings(
        &self,
        _request: Request<GetSettingsRequest>,
    ) -> Result<Response<GetSettingsResponse>, Status> {
        Ok(Response::new(GetSettingsResponse {
            settings: Some(self.state.settings()),
        }))
    }

    async fn update_settings(
        &self,
        request: Request<UpdateSettingsRequest>,
    ) -> Result<Response<UpdateSettingsResponse>, Status> {
        let req = request.into_inner();
        validate(&req, &self.state).map_err(Status::invalid_argument)?;

        // Apply the fallible gateway write first so the whole in-memory
        // phase is all-or-nothing: `try_set_gateway_target` is the only
        // setter in this method that can refuse (a concurrent `Enroll`
        // flipped enrollment to `Attaching` between `validate` and here),
        // and returning after any infallible setter has already written
        // in-memory state would show up as a partial update on
        // `Watch`/`GetSettings` while the response says failure and
        // `settings.json` is never written.
        if let Some(v) = &req.gateway {
            if let Err(observed) = self.state.try_set_gateway_target(v) {
                return Err(Status::failed_precondition(format!(
                    "gateway change refused: enrollment is {observed:?} — unenroll first, then \
                     set the gateway and re-enroll"
                )));
            }
        }
        if let Some(v) = req.load_ceiling {
            self.state.set_load_ceiling(v);
        }
        if let Some(v) = req.mem_floor_mib {
            self.state.set_mem_floor_mib(v);
        }
        // Target only — `FleetImageService.Prepare` is what verifies the
        // image and promotes it to `current`.
        if let Some(v) = &req.linux_runner_image {
            self.state.set_linux_runner_image_target(v);
        }
        if let Some(v) = req.docker_mode {
            self.state.set_docker_mode_target(docker_mode_from_wire(v));
        }
        if let Some(v) = &req.runner_script {
            let path = (!v.is_empty()).then_some(Path::new(v));
            self.state.set_runner_script_target(path);
        }
        // Target only — the supervisor's participation reconciler performs
        // the detach/reattach and flips `current` when it completes.
        if let Some(v) = req.participate {
            self.state.set_participate_target(v);
        }

        self.store
            .store(&self.state.persisted_settings())
            .map_err(Internal)?;

        Ok(Response::new(UpdateSettingsResponse {
            settings: Some(self.state.settings()),
        }))
    }
}

/// Per-field validation, then the cross-field docker_mode/runner_script
/// invariant (see this module's doc and RUN-35's design notes): computed
/// against the *effective* post-update values — the request's, where
/// present, else whatever is already persisted as `target`.
///
/// Returns a plain message rather than `Status` — every failure here maps
/// to the same `INVALID_ARGUMENT` code, so the caller does that one
/// conversion, and `tonic::Status` is large enough that clippy flags
/// returning it from a plain (non-trait) function.
fn validate(req: &UpdateSettingsRequest, state: &AgentState) -> Result<(), String> {
    if let Some(load_ceiling) = req.load_ceiling {
        if load_ceiling <= 0.0 {
            return Err("load_ceiling must be a positive number".to_owned());
        }
    }
    if let Some(linux_runner_image) = &req.linux_runner_image {
        if linux_runner_image.trim().is_empty() {
            return Err("linux_runner_image must not be empty".to_owned());
        }
    }
    if let Some(gateway) = &req.gateway {
        Endpoint::from_shared(gateway.clone()).map_err(|e| format!("invalid gateway URI: {e}"))?;
        // A credential is bound to the gateway it enrolled against — the
        // keychain keys its entry by gateway URI, and the machine record
        // lives in that gateway's database — so moving the target under an
        // enrollment could only strand it (a startup lookup under the new
        // key would miss the credential; the old gateway would never see
        // this machine again). Every enrollment state except Unenrolled
        // implies a credential on disk.
        let enrollment =
            Enrollment::try_from(state.current().enrollment).unwrap_or(Enrollment::Unenrolled);
        if enrollment != Enrollment::Unenrolled {
            return Err(
                "cannot change the gateway while enrolled — unenroll first, then set the \
                 gateway and re-enroll"
                    .to_owned(),
            );
        }
    }
    if let Some(runner_script) = &req.runner_script {
        if !runner_script.is_empty() && !Path::new(runner_script).is_file() {
            return Err(format!("runner_script {runner_script} does not exist"));
        }
    }

    // Only gate this request if it actually touches docker_mode or
    // runner_script — a host that already has this combination from its
    // env-derived seed (a legitimate, existing deployment shape; see this
    // module's doc) must not have every *unrelated* UpdateSettings call
    // (e.g. just load_ceiling) rejected because of it.
    if req.docker_mode.is_some() || req.runner_script.is_some() {
        let persisted = state.persisted_settings();
        let effective_docker_mode = req
            .docker_mode
            .map_or(persisted.docker_mode, docker_mode_from_wire);
        let effective_runner_script = req.runner_script.clone().unwrap_or_else(|| {
            persisted
                .runner_script
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default()
        });
        let leaves_nothing_servable = matches!(
            effective_docker_mode,
            DockerMode::Auto | DockerMode::Disabled
        ) && effective_runner_script.is_empty();
        if leaves_nothing_servable {
            return Err(
                "cannot leave docker_mode as auto/disabled with no runner_script configured — \
                 this would leave the host advertising no capabilities at all; supply \
                 runner_script in the same request or set docker_mode to enabled"
                    .to_owned(),
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use arcbox_fleet_control_proto::v1 as control_proto;

    use super::*;
    use crate::settings::PersistedSettings;

    fn seed() -> PersistedSettings {
        PersistedSettings {
            load_ceiling: 0.9,
            mem_floor_mib: 2048,
            linux_runner_image: "ghcr.io/actions/actions-runner:latest".to_owned(),
            gateway: "https://fleet.arcbox.dev".to_owned(),
            docker_mode: DockerMode::Auto,
            runner_script: None,
            participate: true,
        }
    }

    fn request() -> UpdateSettingsRequest {
        UpdateSettingsRequest {
            load_ceiling: None,
            mem_floor_mib: None,
            linux_runner_image: None,
            gateway: None,
            docker_mode: None,
            runner_script: None,
            participate: None,
        }
    }

    #[test]
    fn rejects_docker_disabled_with_no_runner_script() {
        let state = AgentState::new(&seed());
        let req = UpdateSettingsRequest {
            docker_mode: Some(control_proto::DockerMode::Disabled as i32),
            ..request()
        };
        assert!(validate(&req, &state).is_err());
    }

    #[test]
    fn accepts_docker_disabled_with_runner_script_in_same_request() {
        let dir =
            std::env::temp_dir().join(format!("fleet-settings-validate-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("run.sh");
        std::fs::write(&script, "#!/bin/sh\n").unwrap();

        let state = AgentState::new(&seed());
        let req = UpdateSettingsRequest {
            docker_mode: Some(control_proto::DockerMode::Disabled as i32),
            runner_script: Some(script.to_string_lossy().into_owned()),
            ..request()
        };
        assert!(validate(&req, &state).is_ok());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn rejects_nonexistent_runner_script() {
        let state = AgentState::new(&seed());
        let req = UpdateSettingsRequest {
            runner_script: Some("/does/not/exist/run.sh".to_owned()),
            ..request()
        };
        assert!(validate(&req, &state).is_err());
    }

    #[test]
    fn unrelated_field_update_succeeds_despite_preexisting_unsafe_combination() {
        // A host whose env-derived seed already has docker_mode=Disabled and
        // no runner_script (a legitimate, existing Docker-only deployment)
        // must not have every future, unrelated UpdateSettings rejected
        // because of that pre-existing combination.
        let state = AgentState::new(&crate::settings::PersistedSettings {
            docker_mode: DockerMode::Disabled,
            runner_script: None,
            participate: true,
            ..seed()
        });
        let req = UpdateSettingsRequest {
            load_ceiling: Some(0.5),
            ..request()
        };
        assert!(validate(&req, &state).is_ok());
    }

    #[test]
    fn accepts_docker_enabled_with_no_runner_script() {
        let state = AgentState::new(&seed());
        let req = UpdateSettingsRequest {
            docker_mode: Some(control_proto::DockerMode::Enabled as i32),
            ..request()
        };
        assert!(validate(&req, &state).is_ok());
    }

    #[test]
    fn rejects_non_positive_load_ceiling() {
        let state = AgentState::new(&seed());
        let req = UpdateSettingsRequest {
            load_ceiling: Some(0.0),
            ..request()
        };
        assert!(validate(&req, &state).is_err());
    }

    #[test]
    fn rejects_malformed_gateway() {
        let state = AgentState::new(&seed());
        let req = UpdateSettingsRequest {
            gateway: Some("not a uri".to_owned()),
            ..request()
        };
        assert!(validate(&req, &state).is_err());
    }

    /// The gateway is only settable while unenrolled: every other
    /// enrollment state implies a credential keyed by the current gateway,
    /// which a moved target would strand.
    #[test]
    fn gateway_change_requires_unenrolled() {
        let req = UpdateSettingsRequest {
            gateway: Some("https://other.gateway.test".to_owned()),
            ..request()
        };

        let state = AgentState::new(&seed());
        assert!(validate(&req, &state).is_ok(), "unenrolled may retarget");

        for enrollment in [
            control_proto::Enrollment::Attaching,
            control_proto::Enrollment::Attached,
            control_proto::Enrollment::Detached,
            control_proto::Enrollment::CredentialRejected,
        ] {
            state.set_enrollment(enrollment, "fltm_test");
            let err = validate(&req, &state).expect_err("credential exists");
            assert!(err.contains("unenroll first"), "{enrollment:?}: {err}");
        }

        // Other settings stay updatable regardless of enrollment.
        let unrelated = UpdateSettingsRequest {
            load_ceiling: Some(0.5),
            ..request()
        };
        assert!(validate(&unrelated, &state).is_ok());
    }

    /// `linux_runner_image` is prepare-scoped: `UpdateSettings` must move
    /// only `target`, leaving `current` (what dispatch actually uses) for
    /// `FleetImageService.Prepare` to promote after verification.
    #[tokio::test]
    async fn update_settings_moves_linux_runner_image_target_only() {
        let dir = std::env::temp_dir().join(format!("fleet-settings-image-{}", std::process::id()));
        let state = AgentState::new(&seed());
        let service =
            SettingsService::new(state.clone(), SettingsStore::new(dir.join("settings.json")));
        service
            .update_settings(Request::new(UpdateSettingsRequest {
                linux_runner_image: Some("ghcr.io/acme/runner:v2".to_owned()),
                ..request()
            }))
            .await
            .expect("UpdateSettings");

        assert_eq!(
            state.linux_runner_image_current(),
            "ghcr.io/actions/actions-runner:latest"
        );
        assert_eq!(state.linux_runner_image_target(), "ghcr.io/acme/runner:v2");

        let _ = std::fs::remove_dir_all(dir);
    }
}
