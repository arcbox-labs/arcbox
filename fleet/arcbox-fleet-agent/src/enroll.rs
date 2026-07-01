//! One-shot enrollment: exchange an enrollment token for the machine credential.

use anyhow::{Context, Result};
use arcbox_fleet_proto::v1::fleet_gateway_service_client::FleetGatewayServiceClient;
use arcbox_fleet_proto::v1::{Capability, EnrollRequest};
use tracing::info;

use crate::config::{AgentConfig, PROTOCOL_VERSION};
use crate::credentials::Credential;
use crate::host;

/// Call `Enroll` on `gateway` and return the machine credential — persisting
/// it is the caller's job, done only once the caller has committed to the
/// result: the CLI `enroll` subcommand stores it straight away, while the
/// control-plane `Enroll` RPC stores it only after winning the enrollment
/// race, so a losing concurrent enroll never overwrites the winner's
/// credential (see `AgentSupervisor::enroll`). The caller also resolves
/// `gateway`: the CLI uses the persisted-settings (or configured default)
/// gateway; the RPC uses its `control_plane` override if given, else the
/// current settings target.
pub async fn enroll(
    config: &AgentConfig,
    token: String,
    capabilities: Vec<Capability>,
    gateway: &str,
) -> Result<Credential> {
    let channel = config
        .endpoint_for(gateway)?
        .connect()
        .await
        .with_context(|| format!("connecting to fleet gateway at {gateway}"))?;
    let mut client = FleetGatewayServiceClient::new(channel);

    let request = EnrollRequest {
        enrollment_token: token,
        machine_name: host::machine_name(),
        host_arch: host::host_arch(),
        cpu_cores: host::cpu_cores(),
        mem_mib: host::mem_mib(),
        capabilities,
        host_info_json: host::host_info_json(),
        protocol_version: PROTOCOL_VERSION,
    };

    let response = client
        .enroll(request)
        .await
        .context("Enroll RPC failed")?
        .into_inner();

    let credential = Credential {
        machine_id: response.machine_id,
        machine_token: response.machine_token,
    };
    info!(machine_id = %credential.machine_id, "enrolled");
    Ok(credential)
}
