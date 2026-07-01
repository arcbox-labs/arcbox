//! `FleetSettingsService` — the tonic server impl. Reads/writes
//! [`AgentState`] directly; no `AgentSupervisor` dependency, since settings
//! never touch the attach lifecycle (see `state.rs`'s module doc and
//! RUN-35's design notes: no setting ever forces a reattach).

use std::path::Path;

use arcbox_fleet_control_proto::v1::fleet_settings_service_server::FleetSettingsService as FleetSettingsServiceTrait;
use arcbox_fleet_control_proto::v1::{
    GetSettingsRequest, GetSettingsResponse, UpdateSettingsRequest, UpdateSettingsResponse,
};
use tonic::transport::Endpoint;
use tonic::{Request, Response, Status};

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

        if let Some(v) = req.load_ceiling {
            self.state.set_load_ceiling(v);
        }
        if let Some(v) = req.mem_floor_mib {
            self.state.set_mem_floor_mib(v);
        }
        if let Some(v) = req.runner_image {
            self.state.set_runner_image(v);
        }
        if let Some(v) = &req.gateway {
            self.state.set_gateway_target(v);
        }
        if let Some(v) = req.docker_mode {
            self.state.set_docker_mode_target(docker_mode_from_wire(v));
        }
        if let Some(v) = &req.runner_script {
            let path = (!v.is_empty()).then_some(Path::new(v));
            self.state.set_runner_script_target(path);
        }

        self.store
            .store(&self.state.persisted_settings())
            .map_err(|e| Status::internal(e.to_string()))?;

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
    if let Some(runner_image) = &req.runner_image {
        if runner_image.trim().is_empty() {
            return Err("runner_image must not be empty".to_owned());
        }
    }
    if let Some(gateway) = &req.gateway {
        Endpoint::from_shared(gateway.clone()).map_err(|e| format!("invalid gateway URI: {e}"))?;
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
            runner_image: "ghcr.io/actions/actions-runner:latest".to_owned(),
            gateway: "https://fleet.arcbox.dev".to_owned(),
            docker_mode: DockerMode::Auto,
            runner_script: None,
        }
    }

    fn request() -> UpdateSettingsRequest {
        UpdateSettingsRequest {
            load_ceiling: None,
            mem_floor_mib: None,
            runner_image: None,
            gateway: None,
            docker_mode: None,
            runner_script: None,
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
}
