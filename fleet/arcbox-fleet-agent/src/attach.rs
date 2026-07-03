//! The durable outbound `Attach` stream: heartbeats out, dispatch in, with
//! exponential-backoff reconnect.
//!
//! The [`RunnerSupervisor`] and the egress queue of runner lifecycle events are
//! created once and reused across every reconnect. A job dispatched before a
//! reconnect keeps running, and its terminal event is forwarded to whichever
//! stream is live instead of being lost into the dropped connection's channel.

use std::time::Duration;

use anyhow::{Context, Result};
use arcbox_fleet_control_proto::v1 as control_proto;
use arcbox_fleet_proto::v1::fleet_gateway_service_client::FleetGatewayServiceClient;
use arcbox_fleet_proto::v1::{
    AttachRequest, Capability, Heartbeat, HostTelemetry, attach_request, attach_response,
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
use crate::state::AgentState;

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

/// Wrap `message` with the machine-credential and protocol-version metadata
/// every authenticated gateway RPC carries (`Attach` here,
/// `enroll::unenroll`'s `Unenroll`).
pub fn authenticated_request<T>(message: T, machine_token: &str) -> Result<Request<T>> {
    let mut request = Request::new(message);
    let token: MetadataValue<_> = machine_token
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
    Ok(request)
}

/// Convert a gateway-facing telemetry reading into its control-plane
/// counterpart. A plain function, not `From`: both `HostTelemetry` types
/// are generated in other crates, so Rust's orphan rule blocks implementing
/// a foreign trait for two foreign types here.
fn telemetry_to_control(t: &HostTelemetry) -> control_proto::HostTelemetry {
    control_proto::HostTelemetry {
        load_avg_1m: t.load_avg_1m,
        cpu_count: t.cpu_count,
        mem_total_mib: t.mem_total_mib,
        mem_available_mib: t.mem_available_mib,
    }
}

/// Build the [`RunnerSupervisor`] and its egress queue. The verdict-resend
/// loop is started by [`run`] instead, so it shares the attachment's shutdown
/// token and is reaped with it.
///
/// Split from [`run`] so a caller — the local control-plane's
/// `AgentSupervisor` — can hold the returned `RunnerSupervisor` handle for
/// `Drain`/`Resume`/`GetStatus` while [`run`] drives the reconnect loop in
/// its own task.
pub fn spawn_supervisor(
    config: &AgentConfig,
    docker: Option<docker::DockerRunner>,
    capabilities: Vec<Capability>,
    state: AgentState,
) -> (RunnerSupervisor, mpsc::Receiver<AttachRequest>) {
    let (egress_tx, egress_rx) = mpsc::channel::<AttachRequest>(OUTBOUND_CAPACITY);
    let supervisor = RunnerSupervisor::new(
        egress_tx,
        config.runner_script.clone(),
        docker,
        capabilities,
        state,
    );
    (supervisor, egress_rx)
}

/// Connect and serve the attach stream, reconnecting on any failure until
/// `shutdown` fires, then stop runners cleanly.
///
/// `supervisor` and `egress_rx` come from [`spawn_supervisor`] and are reused
/// across reconnects, so in-flight jobs survive a dropped connection and
/// their verdicts reach the next live stream. On shutdown the loop exits and
/// hands off to [`RunnerSupervisor::shutdown`], which tears down any
/// in-flight runners.
#[allow(
    clippy::too_many_arguments,
    reason = "the reconnect loop genuinely needs all of: endpoint config, credential, the \
              persistent supervisor, the cross-reconnect egress queue, advertised \
              capabilities, the shutdown token, and the observable state handle"
)]
pub async fn run(
    config: AgentConfig,
    credential: Credential,
    supervisor: RunnerSupervisor,
    mut egress_rx: mpsc::Receiver<AttachRequest>,
    capabilities: Vec<Capability>,
    shutdown: CancellationToken,
    state: AgentState,
) -> Result<()> {
    let mut backoff = INITIAL_BACKOFF;
    // An event pulled from the egress queue but not yet delivered when the
    // connection dropped; re-sent first on the next connection so a terminal
    // event is never lost to a closed stream.
    let mut pending: Option<AttachRequest> = None;

    // Attachment-scoped: resend unacked verdicts across reconnects within this
    // attachment, exiting when `shutdown` fires. Tied to the attachment rather
    // than the process because `AgentSupervisor::attach` spawns a fresh `run`
    // per enrollment — a process-lifetime task here would leak one per
    // unenroll/re-enroll cycle.
    let resend = spawn_verdict_resend(supervisor.clone(), shutdown.clone());

    while !shutdown.is_cancelled() {
        state.set_enrollment(control_proto::Enrollment::Attaching, &credential.machine_id);
        let outcome = connect_and_serve(
            &config,
            &credential,
            &supervisor,
            &mut egress_rx,
            &mut pending,
            &mut backoff,
            &capabilities,
            &shutdown,
            &state,
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
    // The loop only exits once `shutdown` is cancelled, so the resend task has
    // already broken out of its own loop; await it so it's fully reaped before
    // this attachment's task returns.
    let _ = resend.await;
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
              and its pending slot, the mutable backoff, advertised capabilities, the \
              shutdown token, and the observable state handle"
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
    state: &AgentState,
) -> Result<()> {
    // The desired (`target`) gateway, not `config.gateway` directly —
    // `AgentSupervisor` seeds it from config and `UpdateSettings` can move
    // it from there. Re-read on every attempt so a change takes effect on
    // whatever reconnect happens next, without this loop ever being forced
    // to one; `current` only moves to match once this actually succeeds,
    // below.
    let gateway = state.gateway_target();
    let (req_tx, req_rx) = mpsc::channel::<AttachRequest>(OUTBOUND_CAPACITY);

    // The connect + Attach-RPC handshake can block indefinitely — no connect
    // timeout is configured on the tonic `Endpoint` — and, unlike the
    // message loop below, has no cancellation awareness of its own. Without
    // this race, a reconnect attempt straddling an `unenroll()` could
    // complete the handshake and write `Attached` after `unenroll()`
    // already wrote `Unenrolled`, with nothing to undo it (see
    // `AgentSupervisor::unenroll`'s doc). `req_rx` moves into the connect
    // future and is dropped with it if cancellation wins; `req_tx` stays
    // available in this outer scope for the rest of the connection.
    let connect = async {
        let channel = config
            .endpoint_for(&gateway)?
            .connect()
            .await
            .with_context(|| format!("connecting to {gateway}"))?;
        let mut client = FleetGatewayServiceClient::new(channel);

        let request =
            authenticated_request(ReceiverStream::new(req_rx), &credential.machine_token)?;

        client
            .attach(request)
            .await
            .context("Attach RPC failed")
            .map(|response| response.into_inner())
    };
    let mut inbound = tokio::select! {
        biased;
        () = shutdown.cancelled() => return Ok(()),
        result = connect => result?,
    };
    *backoff = INITIAL_BACKOFF;
    state.set_enrollment(control_proto::Enrollment::Attached, &credential.machine_id);
    state.set_gateway_current(&gateway);
    info!("attached to gateway");

    // Re-send the event stranded by the previous connection before anything else.
    if let Some(msg) = pending.take() {
        if let Err(err) = req_tx.send(msg).await {
            *pending = Some(err.0);
            anyhow::bail!("request stream closed before the pending event could be re-sent");
        }
    }

    let heartbeat = spawn_heartbeat(req_tx.clone(), capabilities.to_vec(), state.clone());

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
/// Attachment-scoped: it spans reconnects within one attachment and exits when
/// `shutdown` fires, so it's reaped on unenroll instead of outliving the
/// attachment that spawned it. The supervisor holds the egress sender, so
/// resends route through the same outbound path as fresh verdicts.
fn spawn_verdict_resend(
    supervisor: RunnerSupervisor,
    shutdown: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(VERDICT_RESEND_INTERVAL);
        // Skip the immediate first tick: a verdict just sent has not had time to
        // be acked, so there is nothing to resend yet.
        ticker.tick().await;
        loop {
            tokio::select! {
                biased;
                () = shutdown.cancelled() => break,
                _ = ticker.tick() => supervisor.resend_outstanding(),
            }
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
    state: AgentState,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(HEARTBEAT_INTERVAL);
        loop {
            ticker.tick().await;
            let telemetry = host::telemetry();
            state.set_telemetry(telemetry_to_control(&telemetry));
            let msg = attach_request::Msg::Heartbeat(Heartbeat {
                capabilities: capabilities.clone(),
                host_info_json: host::host_info_json(),
                telemetry: Some(telemetry),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DockerMode;
    use crate::settings::PersistedSettings;

    fn seed() -> PersistedSettings {
        PersistedSettings {
            load_ceiling: 0.9,
            mem_floor_mib: 2048,
            linux_runner_image: "img".to_owned(),
            gateway: "https://fleet.arcbox.dev".to_owned(),
            docker_mode: DockerMode::Disabled,
            runner_script: None,
            participate: true,
        }
    }

    /// The verdict-resend loop is attachment-scoped: cancelling the shutdown
    /// token must reap it. Otherwise every unenroll/re-enroll cycle would
    /// leak a task holding a supervisor clone (DashMaps, egress sender, Docker
    /// handle) for the life of the process.
    #[tokio::test]
    async fn verdict_resend_task_exits_when_shutdown_fires() {
        let (events, _rx) = mpsc::channel(1);
        let supervisor =
            RunnerSupervisor::new(events, None, None, Vec::new(), AgentState::new(&seed()));
        let shutdown = CancellationToken::new();
        let handle = spawn_verdict_resend(supervisor, shutdown.clone());

        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(1), handle)
            .await
            .expect("resend task must exit promptly once shutdown is cancelled")
            .expect("resend task must not panic");
    }

    fn config() -> AgentConfig {
        AgentConfig {
            gateway: "http://127.0.0.1:1".to_owned(),
            runner_script: None,
            load_ceiling: 0.9,
            mem_floor_mib: 2048,
            data_dir: std::env::temp_dir(),
            docker: crate::config::DockerConfig {
                mode: DockerMode::Disabled,
                linux_runner_image: "img".to_owned(),
            },
            credential_store: crate::config::CredentialMode::File,
        }
    }

    fn credential() -> Credential {
        Credential {
            machine_id: "fltm_test".to_owned(),
            machine_token: "secret".to_owned(),
        }
    }

    /// The connect + Attach-RPC handshake has no cancellation awareness of
    /// its own (see this fn's own doc in the non-test code above) — without
    /// racing it against `shutdown`, a reconnect attempt could complete the
    /// handshake and write `Attached` after an `unenroll()` already wrote
    /// `Unenrolled`. Cancelling before this call even starts must bail out
    /// immediately, attempting no connect at all and touching no state.
    #[tokio::test]
    async fn connect_and_serve_bails_out_immediately_when_already_cancelled() {
        let state = AgentState::new(&seed());
        let (events, _rx) = mpsc::channel(1);
        let supervisor =
            RunnerSupervisor::new(events, None, None, Vec::new(), AgentState::new(&seed()));
        let (_egress_tx, mut egress_rx) = mpsc::channel::<AttachRequest>(1);
        let mut pending = None;
        let mut backoff = INITIAL_BACKOFF;
        let shutdown = CancellationToken::new();
        shutdown.cancel();

        let config = config();
        let credential = credential();

        let result = tokio::time::timeout(
            Duration::from_secs(1),
            connect_and_serve(
                &config,
                &credential,
                &supervisor,
                &mut egress_rx,
                &mut pending,
                &mut backoff,
                &[],
                &shutdown,
                &state,
            ),
        )
        .await
        .expect("must return promptly once already cancelled, not attempt a connect");

        assert!(result.is_ok());
        assert_eq!(
            state.current().enrollment,
            control_proto::Enrollment::Unenrolled as i32,
            "must never have written Attaching/Attached"
        );
    }
}
