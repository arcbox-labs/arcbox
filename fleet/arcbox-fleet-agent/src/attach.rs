//! The durable outbound `Attach` stream: heartbeats out, dispatch in, with
//! exponential-backoff reconnect.
//!
//! The [`RunnerSupervisor`] and the egress queue of runner lifecycle events are
//! created once and reused across every reconnect. A job dispatched before a
//! reconnect keeps running, and its terminal event is forwarded to whichever
//! stream is live instead of being lost into the dropped connection's channel.

use std::time::Duration;

use anyhow::{Context, Result};
use arcbox_fleet_proto::v1::fleet_gateway_service_client::FleetGatewayServiceClient;
use arcbox_fleet_proto::v1::{AttachRequest, Heartbeat, attach_request, attach_response};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use tonic::Request;
use tonic::metadata::MetadataValue;
use tracing::{info, warn};

use crate::config::AgentConfig;
use crate::credentials::Credential;
use crate::docker::{self, DockerCapabilities};
use crate::host;
use crate::runner::RunnerSupervisor;

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);
const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(60);
const OUTBOUND_CAPACITY: usize = 64;
const MACHINE_TOKEN_HEADER: &str = "x-arcbox-machine-token";
/// How long to wait for runner process groups to be killed and reaped on
/// shutdown before giving up. Reaping a SIGKILLed group is near-instant, so this
/// is a generous ceiling rather than an expected wait.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(15);

/// Connect and serve the attach stream, reconnecting on any failure until
/// `shutdown` fires, then stop runners cleanly.
///
/// The supervisor and the egress queue carrying runner lifecycle events are
/// built once and reused across reconnects, so in-flight jobs survive a dropped
/// connection and their terminal events reach the next live stream. On shutdown
/// the loop exits and hands off to [`RunnerSupervisor::shutdown`], which tears
/// down any in-flight runners (host process groups and Docker containers).
pub async fn run(
    config: AgentConfig,
    credential: Credential,
    docker: Option<docker::DockerRunner>,
    shutdown: CancellationToken,
) -> Result<()> {
    let runner_dir = config.runner_dir.clone();
    let docker_caps = docker
        .as_ref()
        .map(|d| d.capabilities(config.max_concurrent));

    let (egress_tx, mut egress_rx) = mpsc::channel::<AttachRequest>(OUTBOUND_CAPACITY);
    let supervisor = RunnerSupervisor::new(egress_tx, runner_dir, docker, config.max_concurrent);

    let mut backoff = INITIAL_BACKOFF;
    // An event pulled from the egress queue but not yet delivered when the
    // connection dropped; re-sent first on the next connection so a terminal
    // event is never lost to a closed stream.
    let mut pending: Option<AttachRequest> = None;

    while !shutdown.is_cancelled() {
        let outcome = connect_and_serve(
            &config,
            &credential,
            &supervisor,
            &mut egress_rx,
            &mut pending,
            &mut backoff,
            &shutdown,
            docker_caps.as_ref(),
        )
        .await;
        // A shutdown during the connection is a clean exit, not a failure to log
        // or back off from.
        if shutdown.is_cancelled() {
            break;
        }
        match outcome {
            Ok(()) => info!("attach stream closed by gateway; reconnecting"),
            Err(e) => {
                warn!(error = %e, backoff_secs = backoff.as_secs(), "attach failed; retrying");
            }
        }
        tokio::select! {
            biased;
            () = shutdown.cancelled() => break,
            () = tokio::time::sleep(backoff) => {}
        }
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }

    info!("shutdown signal received; stopping runners");
    supervisor.shutdown(SHUTDOWN_GRACE).await;
    Ok(())
}

/// One connect + stream lifetime. Returns `Ok(())` on a clean close. Resets
/// `backoff` once the stream is established, so a connection that succeeds and
/// later drops reconnects promptly instead of inheriting the escalated delay
/// from earlier connect failures.
///
/// Outbound traffic is multiplexed onto a fresh per-connection request channel:
/// connection-scoped heartbeats are sent directly, while runner lifecycle
/// events are forwarded from the shared egress queue. Inbound orders are routed
/// to the persistent `supervisor`.
async fn connect_and_serve(
    config: &AgentConfig,
    credential: &Credential,
    supervisor: &RunnerSupervisor,
    egress_rx: &mut mpsc::Receiver<AttachRequest>,
    pending: &mut Option<AttachRequest>,
    backoff: &mut Duration,
    shutdown: &CancellationToken,
    docker_caps: Option<&DockerCapabilities>,
) -> Result<()> {
    let channel = config
        .endpoint()?
        .connect()
        .await
        .with_context(|| format!("connecting to {}", config.gateway))?;
    let mut client = FleetGatewayServiceClient::new(channel);

    let (req_tx, req_rx) = mpsc::channel::<AttachRequest>(OUTBOUND_CAPACITY);

    let mut request = Request::new(ReceiverStream::new(req_rx));
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
    *backoff = INITIAL_BACKOFF;
    info!("attached to gateway");

    // Re-send the event stranded by the previous connection before anything else.
    if let Some(msg) = pending.take() {
        if let Err(err) = req_tx.send(msg).await {
            *pending = Some(err.0);
            anyhow::bail!("request stream closed before the pending event could be re-sent");
        }
    }

    let heartbeat = spawn_heartbeat(req_tx.clone(), config.max_concurrent, docker_caps.cloned());

    let outcome = loop {
        tokio::select! {
            () = shutdown.cancelled() => break Ok(()),
            event = egress_rx.recv() => match event {
                Some(msg) => {
                    if let Err(err) = req_tx.send(msg).await {
                        // Stream is gone; hold the event for the next connection.
                        *pending = Some(err.0);
                        break Err(anyhow::anyhow!("request stream closed while forwarding event"));
                    }
                }
                // The supervisor holds the only egress sender, so this cannot
                // happen while the agent runs; treat it as a clean shutdown.
                None => break Ok(()),
            },
            message = inbound.message() => match message {
                Ok(Some(message)) => dispatch(supervisor, message.msg).await,
                Ok(None) => break Ok(()),
                Err(status) => break Err(anyhow::Error::from(status)),
            },
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
///
/// Heartbeats are connection-scoped: the task is spawned per connection and
/// aborted when it drops, so a momentary disconnect does not leave stale
/// heartbeats queued for the next stream.
fn spawn_heartbeat(
    outbound: mpsc::Sender<AttachRequest>,
    max_concurrent: usize,
    docker_caps: Option<DockerCapabilities>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(HEARTBEAT_INTERVAL);
        loop {
            ticker.tick().await;
            let msg = attach_request::Msg::Heartbeat(Heartbeat {
                capacities: host::capacities(max_concurrent, docker_caps.as_ref()),
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
