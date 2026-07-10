//! One-shot gateway RPCs: enroll (exchange an enrollment token for the
//! machine credential) and unenroll (decommission the machine, revoking
//! that credential server-side).

use std::time::Duration;

use anyhow::{Context, Result};
use arcbox_fleet_proto::v1::fleet_gateway_service_client::FleetGatewayServiceClient;
use arcbox_fleet_proto::v1::{Capability, EnrollRequest, UnenrollRequest, enroll_response};
use tracing::{info, warn};

use crate::attach::authenticated_request;
use crate::config::AgentConfig;
use crate::credentials::Credential;
use crate::host;

/// Bound on the best-effort gateway `Unenroll` call. Generous for a healthy
/// round-trip, but a blackholed gateway must not prevent the terminal local
/// credential clear.
const GATEWAY_UNENROLL_TIMEOUT: Duration = Duration::from_secs(10);

/// Call `Enroll` on `gateway` and return the machine credential — persisting
/// it is the caller's job, done only once the caller has committed to the
/// result: the CLI `quick enroll` subcommand stores it straight away, while
/// the control-plane `Enroll` RPC stores it only after winning the enrollment
/// race, so a losing concurrent enroll never overwrites the winner's
/// credential (see `AgentSupervisor::enroll`). The caller also resolves
/// `gateway`: `quick enroll` uses the persisted-settings (or configured
/// default) gateway; the RPC uses its `control_plane` override if given, else
/// the current settings target.
///
/// A gateway that expects a different agent build refuses enrollment with
/// `EnrollResponse::update_required`; surface the expected version so the
/// operator installs the right binary instead of a stringly-typed error.
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
        agent_version: env!("CARGO_PKG_VERSION").to_owned(),
        host_os: host::host_os(),
    };

    let response = client
        .enroll(request)
        .await
        .context("Enroll RPC failed")?
        .into_inner();

    match response.result {
        Some(enroll_response::Result::Enrolled(enrolled)) => {
            let credential = Credential {
                machine_id: enrolled.machine_id,
                machine_token: enrolled.machine_token,
            };
            info!(machine_id = %credential.machine_id, "enrolled");
            Ok(credential)
        }
        Some(enroll_response::Result::UpdateRequired(update)) => {
            anyhow::bail!(
                "enrollment refused: gateway expects agent version {}, this binary is {}",
                update.expected_version,
                env!("CARGO_PKG_VERSION"),
            );
        }
        None => anyhow::bail!("gateway returned an empty EnrollResponse"),
    }
}

/// Decommission the machine at `gateway` on a best-effort, time-bounded basis,
/// then remove its persisted credential unconditionally. Both control-plane
/// and socketless unenrollment use this terminal workflow so remote failures
/// cannot leave the host believing it is still enrolled.
pub async fn unenroll_and_clear(
    config: &AgentConfig,
    gateway: &str,
    credential: &Credential,
) -> Result<()> {
    match tokio::time::timeout(
        GATEWAY_UNENROLL_TIMEOUT,
        unenroll_gateway(config, gateway, &credential.machine_token),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            warn!(
                error = %e,
                gateway,
                "gateway unenroll failed; clearing the local credential anyway"
            );
        }
        Err(_) => {
            warn!(
                gateway,
                "gateway unenroll timed out; clearing the local credential anyway"
            );
        }
    }

    config.credential_store_for(gateway).clear()
}

/// Call `Unenroll` on `gateway`, authenticated with `machine_token`. An
/// already-revoked credential is the desired outcome and counts as success.
async fn unenroll_gateway(config: &AgentConfig, gateway: &str, machine_token: &str) -> Result<()> {
    let channel = config
        .endpoint_for(gateway)?
        .connect()
        .await
        .with_context(|| format!("connecting to fleet gateway at {gateway}"))?;
    let mut client = FleetGatewayServiceClient::new(channel);

    let request = authenticated_request(UnenrollRequest {}, machine_token)?;
    match client.unenroll(request).await {
        Ok(_) => {
            info!("unenrolled at gateway (machine decommissioned)");
            Ok(())
        }
        Err(status) if status.code() == tonic::Code::Unauthenticated => {
            info!("gateway reports the credential already revoked");
            Ok(())
        }
        Err(status) => Err(status).context("Unenroll RPC failed"),
    }
}
