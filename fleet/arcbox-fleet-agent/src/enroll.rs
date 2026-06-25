//! One-shot enrollment: exchange an enrollment token for the machine credential.

use anyhow::{Context, Result};
use arcbox_fleet_proto::v1::fleet_gateway_service_client::FleetGatewayServiceClient;
use arcbox_fleet_proto::v1::{Capability, EnrollRequest};
use tracing::info;

use crate::config::{AgentConfig, PROTOCOL_VERSION};
use crate::credentials::{Credential, CredentialStore};
use crate::host;

/// Call `Enroll` on the gateway and persist the returned credential.
pub async fn enroll(
    config: &AgentConfig,
    token: String,
    capabilities: Vec<Capability>,
) -> Result<Credential> {
    let channel = config
        .endpoint()?
        .connect()
        .await
        .with_context(|| format!("connecting to fleet gateway at {}", config.gateway))?;
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
    CredentialStore::new(config.credentials_path()).store(&credential)?;
    info!(machine_id = %credential.machine_id, "enrolled");
    Ok(credential)
}
