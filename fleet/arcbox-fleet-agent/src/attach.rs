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
use arcbox_fleet_proto::v1::{
    AttachRequest, Capability, Heartbeat, attach_request, attach_response,
};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use tonic::Request;
use tonic::metadata::MetadataValue;
use tracing::{info, warn};

use crate::config::{AgentConfig, PROTOCOL_VERSION};
use crate::credentials::Credential;
use crate::docker;
use crate::host;
use crate::runner::RunnerSupervisor;

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);
/// How often to resend verdicts still awaiting an `OfferVerdictAck`. Comfortably
/// longer than normal ack latency (sub-second), so the steady state is zero
/// resends, yet short enough to recover a lost verdict within a placement window.
const VERDICT_RESEND_INTERVAL: Duration = Duration::from_secs(10);
const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(60);
const OUTBOUND_CAPACITY: usize = 64;
const MACHINE_TOKEN_HEADER: &str = "x-arcbox-machine-token";
const PROTOCOL_VERSION_HEADER: &str = "x-arcbox-protocol-version";
/// How long to wait for runners to be torn down and reaped on shutdown before
/// giving up. Killing a process group or container is near-instant, so this is a
/// generous ceiling rather than an expected wait.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(15);

/// Connect and serve the attach stream, reconnecting on any failure until
/// `shutdown` fires, then stop runners cleanly.
///
/// The supervisor and the egress queue carrying runner lifecycle events are
/// built once and reused across reconnects, so in-flight jobs survive a dropped
/// connection and their verdicts reach the next live stream. On shutdown the
/// loop exits and hands off to [`RunnerSupervisor::shutdown`], which tears down
/// any in-flight runners.
pub async fn run(
    config: AgentConfig,
    credential: Credential,
    docker: Option<docker::DockerRunner>,
    capabilities: Vec<Capability>,
    shutdown: CancellationToken,
) -> Result<()> {
    let runner_dir = config.runner_dir.clone();

    let (egress_tx, mut egress_rx) = mpsc::channel::<AttachRequest>(OUTBOUND_CAPACITY);
    let supervisor = RunnerSupervisor::new(
        egress_tx,
        runner_dir,
        docker,
        capabilities.clone(),
        config.load_ceiling,
        config.mem_floor_mib,
    );

    // Process-scoped: resend unacked verdicts across reconnects. Re-emitted
    // verdicts ride the same egress queue, so the reconnect-survival machinery
    // below (egress forwarding + `pending`) delivers them to whichever stream is
    // live. Detached for the agent's lifetime; the agent never shuts down here.
    spawn_verdict_resend(supervisor.clone());

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
            &capabilities,
            &shutdown,
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
#[allow(
    clippy::too_many_arguments,
    reason = "one connection's lifecycle genuinely needs all of: endpoint config, \
              credential, the persistent supervisor, the cross-reconnect egress queue \
              and its pending slot, the mutable backoff, advertised capabilities, and \
              the shutdown token"
)]
async fn connect_and_serve(
    config: &AgentConfig,
    credential: &Credential,
    supervisor: &RunnerSupervisor,
    egress_rx: &mut mpsc::Receiver<AttachRequest>,
    pending: &mut Option<AttachRequest>,
    backoff: &mut Duration,
    capabilities: &[Capability],
    shutdown: &CancellationToken,
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
    // Protocol-version handshake: the gateway rejects an unsupported version.
    let version: MetadataValue<_> = PROTOCOL_VERSION
        .to_string()
        .parse()
        .expect("protocol version is a valid metadata value");
    request
        .metadata_mut()
        .insert(PROTOCOL_VERSION_HEADER, version);

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

    let heartbeat = spawn_heartbeat(req_tx.clone(), capabilities.to_vec());

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
                Ok(Some(message)) => dispatch(supervisor, message.msg),
                Ok(None) => break Ok(()),
                Err(status) => break Err(anyhow::Error::from(status)),
            },
        }
    };

    heartbeat.abort();
    outcome
}

/// Route one inbound `AttachResponse` to the supervisor. Synchronous: every
/// handler only mutates supervisor state and spawns work, so dispatch can never
/// stall the stream loop.
fn dispatch(supervisor: &RunnerSupervisor, msg: Option<attach_response::Msg>) {
    match msg {
        Some(attach_response::Msg::ProvisionRunner(order)) => {
            supervisor.handle_provision(order);
        }
        Some(attach_response::Msg::Cancel(cancel)) => supervisor.handle_cancel(&cancel.job_id),
        Some(attach_response::Msg::Drain(_)) => supervisor.handle_drain(),
        Some(attach_response::Msg::OfferVerdictAck(ack)) => {
            supervisor.handle_ack(&ack.offer_token);
        }
        None => {}
    }
}

/// Periodically resend verdicts still awaiting an `OfferVerdictAck`, until the
/// gateway settles them (delivered to the workflow, or found obsolete).
/// Process-scoped so it spans reconnects; the supervisor holds the egress
/// sender, so resends route through the same outbound path as fresh verdicts.
fn spawn_verdict_resend(supervisor: RunnerSupervisor) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(VERDICT_RESEND_INTERVAL);
        // Skip the immediate first tick: a verdict just sent has not had time to
        // be acked, so there is nothing to resend yet.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            supervisor.resend_outstanding();
        }
    })
}

/// Periodically push a declarative capability + telemetry heartbeat until the
/// channel closes.
///
/// Heartbeats are connection-scoped: the task is spawned per connection and
/// aborted when it drops, so a momentary disconnect does not leave stale
/// heartbeats queued for the next stream.
fn spawn_heartbeat(
    outbound: mpsc::Sender<AttachRequest>,
    capabilities: Vec<Capability>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(HEARTBEAT_INTERVAL);
        loop {
            ticker.tick().await;
            let msg = attach_request::Msg::Heartbeat(Heartbeat {
                capabilities: capabilities.clone(),
                host_info_json: host::host_info_json(),
                telemetry: Some(host::telemetry()),
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
