//! One-shot enrollment: exchange an enrollment token for the machine credential.

use anyhow::{Context, Result};
use arcbox_fleet_proto::v1::fleet_gateway_service_client::FleetGatewayServiceClient;
use arcbox_fleet_proto::v1::{Capability, EnrollRequest};
use tracing::info;

use crate::config::{AgentConfig, PROTOCOL_VERSION};
use crate::credentials::{Credential, CredentialStore};
use crate::host;

/// Call `Enroll` on the gateway and persist the returned credential.
///
/// `control_plane` overrides the agent's configured default gateway for
/// this enrollment (the desktop-managed handoff's per-enrollment gateway);
/// `None` uses `config.gateway`, as the CLI's `enroll` subcommand always
/// does. Whichever gateway is used is persisted onto the returned
/// [`Credential`] so later reconnects target the same one.
pub async fn enroll(
    config: &AgentConfig,
    token: String,
    capabilities: Vec<Capability>,
    control_plane: Option<&str>,
) -> Result<Credential> {
    let gateway = control_plane.unwrap_or(&config.gateway);
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
        control_plane: control_plane.map(str::to_owned),
    };
    CredentialStore::new(
        config.credential_store,
        config.credentials_path(),
        &config.gateway,
    )
    .store(&credential)?;
    info!(machine_id = %credential.machine_id, "enrolled");
    Ok(credential)
}
