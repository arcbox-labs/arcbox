//! `FleetLifecycleService` — the tonic server impl, backed by
//! [`AgentSupervisor`](super::AgentSupervisor).

use std::sync::Arc;

use arcbox_fleet_control_proto::v1::fleet_lifecycle_service_server::FleetLifecycleService;
use arcbox_fleet_control_proto::v1::{
    DrainRequest, DrainResponse, EnrollRequest, EnrollResponse, GetAgentInfoRequest,
    GetAgentInfoResponse, GetStatusRequest, GetStatusResponse, ResumeRequest, ResumeResponse,
    UnenrollRequest, UnenrollResponse,
};
use tonic::{Request, Response, Status};

use super::AgentSupervisor;

/// Bumped only on breaking control-API changes. Clients call `GetAgentInfo`
/// and adapt to what it reports rather than gating behavior on an exact
/// match — the agent and its clients ship and self-update independently.
const API_VERSION: u32 = 1;

pub struct LifecycleService {
    supervisor: Arc<AgentSupervisor>,
}

impl LifecycleService {
    pub fn new(supervisor: Arc<AgentSupervisor>) -> Self {
        Self { supervisor }
    }
}

#[tonic::async_trait]
impl FleetLifecycleService for LifecycleService {
    async fn get_agent_info(
        &self,
        _request: Request<GetAgentInfoRequest>,
    ) -> Result<Response<GetAgentInfoResponse>, Status> {
        Ok(Response::new(GetAgentInfoResponse {
            agent_version: env!("CARGO_PKG_VERSION").to_owned(),
            api_version: API_VERSION,
            features: Vec::new(),
        }))
    }

    async fn enroll(
        &self,
        request: Request<EnrollRequest>,
    ) -> Result<Response<EnrollResponse>, Status> {
        let req = request.into_inner();
        if req.enrollment_token.trim().is_empty() {
            return Err(Status::invalid_argument("enrollment_token is required"));
        }
        let control_plane = (!req.control_plane.is_empty()).then_some(req.control_plane.as_str());
        let machine_id = self
            .supervisor
            .enroll(req.enrollment_token, control_plane)
            .await?;
        Ok(Response::new(EnrollResponse { machine_id }))
    }

    async fn drain(
        &self,
        _request: Request<DrainRequest>,
    ) -> Result<Response<DrainResponse>, Status> {
        self.supervisor.drain().await?;
        Ok(Response::new(DrainResponse {}))
    }

    async fn resume(
        &self,
        _request: Request<ResumeRequest>,
    ) -> Result<Response<ResumeResponse>, Status> {
        self.supervisor.resume().await?;
        Ok(Response::new(ResumeResponse {}))
    }

    async fn unenroll(
        &self,
        _request: Request<UnenrollRequest>,
    ) -> Result<Response<UnenrollResponse>, Status> {
        self.supervisor.unenroll().await?;
        Ok(Response::new(UnenrollResponse {}))
    }

    async fn get_status(
        &self,
        _request: Request<GetStatusRequest>,
    ) -> Result<Response<GetStatusResponse>, Status> {
        let (state, machine_id) = self.supervisor.status().await;
        Ok(Response::new(GetStatusResponse {
            state: state as i32,
            machine_id,
        }))
    }
}
