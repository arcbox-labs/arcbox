//! The durable outbound `Attach` stream: heartbeats out, dispatch in, with
//! exponential-backoff reconnect.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use arcbox_fleet_proto::v1::fleet_gateway_service_client::FleetGatewayServiceClient;
use arcbox_fleet_proto::v1::{AttachRequest, Heartbeat, attach_request, attach_response};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::Request;
use tonic::metadata::MetadataValue;
use tracing::{info, warn};

use crate::config::AgentConfig;
use crate::credentials::Credential;
use crate::host;
use crate::runner::RunnerSupervisor;

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);
const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(60);
const OUTBOUND_CAPACITY: usize = 64;
const MACHINE_TOKEN_HEADER: &str = "x-arcbox-machine-token";

/// Connect and serve the attach stream forever, reconnecting on any failure.
pub async fn run(config: AgentConfig, credential: Credential) -> Result<()> {
    let runner_dir = config.require_runner_dir()?.to_path_buf();
    let mut backoff = INITIAL_BACKOFF;

    loop {
        match attach_once(&config, &credential, runner_dir.clone()).await {
            Ok(()) => {
                info!("attach stream closed by gateway; reconnecting");
                backoff = INITIAL_BACKOFF;
            }
            Err(e) => {
                warn!(error = %e, backoff_secs = backoff.as_secs(), "attach failed; retrying")
            }
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

/// One connect + stream lifetime. Returns `Ok(())` on a clean close.
async fn attach_once(
    config: &AgentConfig,
    credential: &Credential,
    runner_dir: PathBuf,
) -> Result<()> {
    let channel = config
        .endpoint()?
        .connect()
        .await
        .with_context(|| format!("connecting to {}", config.gateway))?;
    let mut client = FleetGatewayServiceClient::new(channel);

    let (outbound, rx) = mpsc::channel::<AttachRequest>(OUTBOUND_CAPACITY);
    let supervisor = RunnerSupervisor::new(outbound.clone(), runner_dir, config.max_concurrent);
    let heartbeat = spawn_heartbeat(outbound, config.max_concurrent);

    let mut request = Request::new(ReceiverStream::new(rx));
    let token: MetadataValue<_> = credential
        .machine_token
        .parse()
        .context("machine token is not a valid metadata value")?;
    request.metadata_mut().insert(MACHINE_TOKEN_HEADER, token);

    let mut inbound = client
        .attach(request)
        .await
        .context("Attach RPC failed")?
        .into_inner();
    info!("attached to gateway");

    let outcome = loop {
        match inbound.message().await {
            Ok(Some(message)) => dispatch(&supervisor, message.msg).await,
            Ok(None) => break Ok(()),
            Err(status) => break Err(anyhow::Error::from(status)),
        }
    };

    heartbeat.abort();
    outcome
}

/// Route one inbound `AttachResponse` to the supervisor.
async fn dispatch(supervisor: &RunnerSupervisor, msg: Option<attach_response::Msg>) {
    match msg {
        Some(attach_response::Msg::ProvisionRunner(order)) => {
            supervisor.handle_provision(order).await;
        }
        Some(attach_response::Msg::Cancel(cancel)) => supervisor.handle_cancel(&cancel.job_id),
        Some(attach_response::Msg::Drain(_)) => supervisor.handle_drain(),
        None => {}
    }
}

/// Periodically push a declarative capacity heartbeat until the channel closes.
fn spawn_heartbeat(
    outbound: mpsc::Sender<AttachRequest>,
    max_concurrent: usize,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // `interval` fires its first tick immediately, so the gateway sees us
        // online without waiting a full period.
        let mut ticker = tokio::time::interval(HEARTBEAT_INTERVAL);
        loop {
            ticker.tick().await;
            let msg = attach_request::Msg::Heartbeat(Heartbeat {
                capacities: host::capacities(max_concurrent),
                host_info_json: host::host_info_json(),
            });
            if outbound
                .send(AttachRequest { msg: Some(msg) })
                .await
                .is_err()
            {
                break;
            }
        }
    })
}
