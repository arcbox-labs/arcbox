//! The durable outbound `Attach` stream: heartbeats out, dispatch in, with
//! exponential-backoff reconnect.
//!
//! The [`RunnerSupervisor`] and the egress queue of runner lifecycle events are
//! created once and reused across every reconnect. A job dispatched before a
//! reconnect keeps running, and its terminal event is forwarded to whichever
//! stream is live instead of being lost into the dropped connection's channel.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use arcbox_fleet_control_proto::v1 as control_proto;
use arcbox_fleet_proto::v1::fleet_gateway_service_client::FleetGatewayServiceClient;
use arcbox_fleet_proto::v1::{
    Attach, AttachRequest, Heartbeat, HostTelemetry, attach_request, attach_response,
};
use tokio::sync::{mpsc, watch};
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use tokio_util::task::AbortOnDropHandle;
use tonic::Request;
use tonic::metadata::MetadataValue;
use tracing::{info, warn};

use crate::backends::Backends;
use crate::config::AgentConfig;
use crate::credentials::Credential;
use crate::handover::{Handover, Reason};
use crate::host;
use crate::runner::RunnerSupervisor;
use crate::state::AgentState;
use crate::update;

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);
/// How often to resend verdicts still awaiting an `OfferVerdictAck`. Comfortably
/// longer than normal ack latency (sub-second), so the steady state is zero
/// resends, yet short enough to recover a lost verdict within a placement window.
const VERDICT_RESEND_INTERVAL: Duration = Duration::from_secs(10);
const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(60);
const OUTBOUND_CAPACITY: usize = 64;
const MACHINE_TOKEN_HEADER: &str = "x-arcbox-machine-token";
/// How long to wait for runners to be torn down and reaped on shutdown before
/// giving up. Killing a process group or container is near-instant, so this is a
/// generous ceiling rather than an expected wait.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(15);

/// Wrap `message` with the machine-credential metadata every authenticated
/// gateway RPC carries (`Attach` here, `enroll::unenroll`'s `Unenroll`). The
/// agent build identity travels as the first in-band `Attach` message rather
/// than as a metadata header; see [`connect_and_serve`].
pub fn authenticated_request<T>(message: T, machine_token: &str) -> Result<Request<T>> {
    let mut request = Request::new(message);
    let token: MetadataValue<_> = machine_token
        .parse()
        .context("machine token is not a valid metadata value")?;
    request.metadata_mut().insert(MACHINE_TOKEN_HEADER, token);
    Ok(request)
}

/// Error returned by the attach loop when the gateway requires a different
/// build — at the handshake (`AttachRejected`) or pushed mid-stream on a
/// `HeartbeatAck` after draining. The reconnect loop matches on this: with a
/// `payload` it self-updates and re-execs; without one it parks visibly
/// (analogous to [`is_unauthenticated`]) — a different binary is what's
/// required, not another connection attempt.
#[derive(Debug, thiserror::Error)]
#[error("gateway refused agent build; expected version {expected_version}")]
struct AgentUpdateRequired {
    expected_version: String,
    /// The pushed download, when the gateway carried one.
    payload: Option<update::UpdatePayload>,
}

impl From<arcbox_fleet_proto::v1::AgentUpdate> for AgentUpdateRequired {
    fn from(update: arcbox_fleet_proto::v1::AgentUpdate) -> Self {
        Self {
            payload: update::UpdatePayload::from_wire(&update),
            expected_version: update.expected_version,
        }
    }
}

fn as_agent_update_required(error: &anyhow::Error) -> Option<&AgentUpdateRequired> {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<AgentUpdateRequired>())
}

/// Whether the error chain contains an `UNAUTHENTICATED` gRPC status — the
/// gateway's definitive "this credential is revoked" (a RUN-40
/// decommission), surfaced either by the Attach handshake or as a
/// mid-stream eviction item. Transport failures are not `Status` values,
/// so an unreachable gateway never matches.
fn is_unauthenticated(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<tonic::Status>()
            .is_some_and(|status| status.code() == tonic::Code::Unauthenticated)
    })
}

/// Why one connection's serve loop ended without an error.
enum StreamEnd {
    /// The gateway closed the stream; reconnect after backoff.
    Closed,
    /// The backend registry changed, so the capability set this stream
    /// declared is stale — re-attach immediately (no backoff): the gateway
    /// rewrites the machine's capability pools from each `Attach`
    /// handshake, so the reconnect is what propagates the change.
    Reattach,
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
    backends: Arc<Backends>,
    state: AgentState,
    handover: Arc<Handover>,
) -> (RunnerSupervisor, mpsc::Receiver<AttachRequest>) {
    let (egress_tx, egress_rx) = mpsc::channel::<AttachRequest>(OUTBOUND_CAPACITY);
    let supervisor = RunnerSupervisor::new(
        egress_tx,
        config.runner_script.clone(),
        backends,
        state,
        handover,
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
              persistent supervisor, the cross-reconnect egress queue, the backend \
              registry, the shutdown token, the observable state handle, and the handover \
              a pushed self-update records itself on"
)]
pub async fn run(
    config: AgentConfig,
    credential: Credential,
    supervisor: RunnerSupervisor,
    mut egress_rx: mpsc::Receiver<AttachRequest>,
    backends: Arc<Backends>,
    shutdown: CancellationToken,
    state: AgentState,
    handover: Arc<Handover>,
) -> Result<()> {
    let mut backoff = INITIAL_BACKOFF;
    // Activation notifications; each connection marks the current value
    // seen before it snapshots the capability set it declares.
    let mut backends_rx = backends.subscribe();
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
            &backends,
            &mut backends_rx,
            &shutdown,
            &state,
            &handover,
        )
        .await;
        // A shutdown during the connection is a clean exit, not a failure to log
        // or back off from.
        if shutdown.is_cancelled() {
            break;
        }
        match outcome {
            Ok(StreamEnd::Reattach) => {
                info!("backend registry changed; re-attaching with the fresh capability set");
                continue;
            }
            Ok(StreamEnd::Closed) => info!("attach stream closed by gateway; reconnecting"),
            Err(e) if is_unauthenticated(&e) => {
                // The gateway definitively rejected the credential — the
                // machine was decommissioned server-side (RUN-40), whether
                // at the handshake or as a mid-stream eviction. Retrying can
                // never succeed; park visibly instead, keeping the
                // credential on disk until an operator unenrolls, so a
                // server-side auth regression can never make agents wipe
                // their own credentials.
                warn!("gateway rejected the machine credential; parked until an explicit unenroll");
                state.set_enrollment(
                    control_proto::Enrollment::CredentialRejected,
                    &credential.machine_id,
                );
                shutdown.cancelled().await;
                break;
            }
            Err(e) if as_agent_update_required(&e).is_some() => {
                let required = as_agent_update_required(&e).expect("just matched above");
                let Some(payload) = required.payload.clone() else {
                    // The gateway pins a different build but carried no
                    // download (pre-registry gateway, or no asset for this
                    // platform). Retrying will keep hitting the same
                    // rejection; park until the operator installs the
                    // expected binary. Reuses `CredentialRejected` for the
                    // parked-state signal — `Updating` is the in-progress
                    // state, not this dead end.
                    warn!(
                        expected = %required.expected_version,
                        current = env!("CARGO_PKG_VERSION"),
                        "gateway refused the agent build; parked until the expected binary is installed"
                    );
                    state.set_enrollment(
                        control_proto::Enrollment::CredentialRejected,
                        &credential.machine_id,
                    );
                    shutdown.cancelled().await;
                    break;
                };
                info!(
                    expected = %payload.expected_version,
                    current = env!("CARGO_PKG_VERSION"),
                    "gateway requires a different build; self-updating"
                );
                state.set_enrollment(control_proto::Enrollment::Updating, &credential.machine_id);
                // Off-stream no new offers can arrive, but jobs may still be
                // running (a mid-stream drain that lost its connection, or a
                // reconnect that got version-rejected). Never kill them for
                // an update.
                handover.request(Reason::Update);
                // Off-stream, so no ack can arrive: waiting one out would only
                // delay the swap by the full grace on every version refusal.
                tokio::select! {
                    biased;
                    () = shutdown.cancelled() => break,
                    () = supervisor.quiesce(Duration::ZERO) => {}
                }
                let error = match update::apply(&config, &payload).await {
                    Ok(managed) => {
                        // The swap is done; committing brings the process down
                        // through this same loop's shutdown so runners are torn
                        // down and the log buffer flushed before `main` execs
                        // the new image.
                        handover.commit(managed);
                        break;
                    }
                    Err(error) => error,
                };
                if error
                    .chain()
                    .any(|c| c.downcast_ref::<update::UnmanagedBinary>().is_some())
                {
                    // Not our binary to manage — same dead end as an update
                    // without a download: park for the operator.
                    warn!(
                        error = %error,
                        "self-update declined; parked until the expected binary is installed"
                    );
                    state.set_enrollment(
                        control_proto::Enrollment::CredentialRejected,
                        &credential.machine_id,
                    );
                    shutdown.cancelled().await;
                    break;
                }
                warn!(error = %error, backoff_secs = backoff.as_secs(), "self-update failed; retrying");
            }
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

    // Reached on a shutdown (signal, unenroll, operator restart) and on a
    // staged self-update alike — the swap goes out through the same teardown
    // so no runner is left orphaned by the exec that follows.
    info!("attachment ending; stopping runners");
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
              shutdown token, the observable state handle, and the cross-reconnect \
              update-drain flag"
)]
async fn connect_and_serve(
    config: &AgentConfig,
    credential: &Credential,
    supervisor: &RunnerSupervisor,
    egress_rx: &mut mpsc::Receiver<AttachRequest>,
    pending: &mut Option<AttachRequest>,
    backoff: &mut Duration,
    backends: &Backends,
    backends_rx: &mut watch::Receiver<()>,
    shutdown: &CancellationToken,
    state: &AgentState,
    handover: &Arc<Handover>,
) -> Result<StreamEnd> {
    // The desired (`target`) gateway, not `config.gateway` directly —
    // `AgentSupervisor` seeds it from config, and an `Enroll` gateway
    // override can have moved it from there. It cannot move while this
    // attachment lives (`UpdateSettings` refuses gateway changes whenever a
    // credential exists), so the per-attempt re-read is for freshness of
    // the enrolled value, not to chase a live retarget; `current` only
    // moves to match once this actually succeeds, below.
    let gateway = state.gateway_target();
    let (req_tx, req_rx) = mpsc::channel::<AttachRequest>(OUTBOUND_CAPACITY);

    // Mark the current registry generation seen BEFORE snapshotting the
    // capability set: an activation racing this window still trips the
    // re-attach arm below, which is harmless — the set it re-declares is
    // already fresh. The reverse order could declare a stale set and eat
    // the notification.
    backends_rx.mark_unchanged();
    let capabilities = backends.capabilities();

    // Send `Attach` as the very first outbound message, buffered on `req_tx`
    // before the gRPC call runs. Three reasons: it's the handshake message
    // the gateway checks agent_version against; it declares the capabilities
    // and host facts for this connection (the gateway treats them as
    // per-attachment declarative state and Heartbeat carries only what
    // changes mid-stream — a capability change re-attaches instead); and it
    // satisfies the PLAT-34 "speak first" property — the gateway (or a
    // proxy in front) will not release its response headers until it sees
    // the client say something, and if the client waits for the response
    // before sending anything the whole stream idle-times-out. The mpsc
    // buffer holds the message until tonic drains it once the stream opens.
    let attach_msg = AttachRequest {
        msg: Some(attach_request::Msg::Attach(Attach {
            agent_version: env!("CARGO_PKG_VERSION").to_owned(),
            capabilities,
            host_info_json: host::host_info_json(),
            host_os: host::host_os(),
            host_arch: host::host_arch(),
        })),
    };
    req_tx
        .send(attach_msg)
        .await
        .context("outbound stream closed before Attach could be buffered")?;

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
        () = shutdown.cancelled() => return Ok(StreamEnd::Closed),
        result = connect => result?,
    };

    // First inbound message is the handshake result: `AttachAccepted` and we
    // proceed, or `AttachRejected(AgentUpdate)` and we park the reconnect
    // loop by returning [`AgentUpdateRequired`].
    let handshake = inbound
        .message()
        .await
        .context("Attach handshake response failed")?
        .ok_or_else(|| anyhow::anyhow!("attach stream closed before handshake response"))?;
    match handshake.msg {
        Some(attach_response::Msg::AttachAccepted(_)) => {
            // A drain begun for an update that never happened (the pin moved
            // back to this build before the swap) is moot once the gateway
            // accepts this build again.
            handover.update_became_moot();
        }
        Some(attach_response::Msg::AttachRejected(update)) => {
            return Err(anyhow::Error::new(AgentUpdateRequired::from(update)));
        }
        other => anyhow::bail!("unexpected first response from gateway: {other:?}"),
    }

    // Only start heartbeating once the handshake succeeded; a rejected
    // machine has no business pushing telemetry, and the mpsc would fill
    // with heartbeats a closing stream can never deliver. Held only for its
    // abort-on-drop side effect: it must outlive every exit path below.
    let _heartbeat = spawn_heartbeat(req_tx.clone(), state.clone());

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

    // A mid-stream update pushed on a HeartbeatAck. The stream stays live
    // while the supervisor quiesces — cancels keep arriving and verdicts keep
    // delivering, which is why the ack grace is worth paying here — and only
    // then does the loop leave with `AgentUpdateRequired`, handing the swap to
    // the reconnect loop.
    let mut pending_update: Option<AgentUpdateRequired> = None;
    // Built once and polled across iterations, not rebuilt per `select!` pass:
    // a fresh future each time round would restart the ack grace every time
    // any other branch fired, and a stream carrying heartbeats never goes
    // quiet for that long. Futures are lazy, so the grace starts on the first
    // poll — which the guard below defers until an update is actually pending.
    let mut quiescing = std::pin::pin!(supervisor.quiesce(crate::runner::VERDICT_ACK_GRACE));

    loop {
        tokio::select! {
            () = shutdown.cancelled() => break Ok(StreamEnd::Closed),
            () = &mut quiescing, if pending_update.is_some() => {
                break Err(anyhow::Error::new(
                    pending_update.take().expect("guarded by is_some"),
                ));
            }
            // A backend activated: leave cleanly so the reconnect declares
            // the fresh capability set. In-flight jobs survive (they live
            // in the supervisor), and a pending mid-stream update is safe
            // to abandon — the next handshake re-derives it (AttachRejected
            // or a re-pushed HeartbeatAck). Err means the registry dropped,
            // which only happens at process teardown.
            result = backends_rx.changed() => {
                break Ok(match result {
                    Ok(()) => StreamEnd::Reattach,
                    Err(_) => StreamEnd::Closed,
                });
            }
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
                None => break Ok(StreamEnd::Closed),
            },
            message = inbound.message() => match message {
                Ok(Some(message)) => {
                    tracing::debug!(msg = ?message.msg, "inbound attach message");
                    if let Some(update) = pushed_update(&message) {
                        if pending_update.is_none()
                            && update.expected_version != env!("CARGO_PKG_VERSION")
                        {
                            info!(
                                expected = %update.expected_version,
                                current = env!("CARGO_PKG_VERSION"),
                                "gateway pushed an update; draining before the swap"
                            );
                            handover.request(Reason::Update);
                            pending_update = Some(AgentUpdateRequired::from(update.clone()));
                        }
                        continue;
                    }
                    dispatch(supervisor, message.msg);
                }
                Ok(None) => break Ok(StreamEnd::Closed),
                Err(status) => break Err(anyhow::Error::from(status)),
            },
        }
    }
}

/// The update payload riding on a `HeartbeatAck`, if any. Extracted before
/// [`dispatch`] because acting on it (drain, then leave the stream) belongs
/// to the connection loop, not the synchronous dispatcher.
fn pushed_update(
    message: &arcbox_fleet_proto::v1::AttachResponse,
) -> Option<&arcbox_fleet_proto::v1::AgentUpdate> {
    match &message.msg {
        Some(attach_response::Msg::HeartbeatAck(ack)) => ack.update.as_ref(),
        _ => None,
    }
}

/// Route one inbound `AttachResponse` to the supervisor. Synchronous: every
/// handler only mutates supervisor state and spawns work, so dispatch can never
/// stall the stream loop. The handshake variants (`AttachAccepted`/
/// `AttachRejected`) are consumed by [`connect_and_serve`] before this runs;
/// seeing either mid-stream is a gateway bug, logged and ignored.
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
        // Each heartbeat gets an ack, whose sole purpose is to keep
        // server->client traffic flowing so a proxy in front of the gateway
        // (e.g. Cloudflare) doesn't idle-cut the stream (PLAT-34).
        Some(attach_response::Msg::HeartbeatAck(_)) => {
            tracing::debug!("received heartbeat ack from gateway");
        }
        Some(attach_response::Msg::AttachAccepted(_)) => {
            warn!("unexpected AttachAccepted after handshake; ignoring");
        }
        Some(attach_response::Msg::AttachRejected(_)) => {
            warn!("unexpected AttachRejected after handshake; ignoring");
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

/// Periodically push a live telemetry pulse until the channel closes.
///
/// Heartbeats are connection-scoped: the task is spawned per connection and
/// aborted when it drops, so a momentary disconnect does not leave stale
/// heartbeats queued for the next stream. Capability set and host facts are
/// declared once per stream in the `Attach` handshake (a capability change
/// re-attaches instead — see [`StreamEnd::Reattach`]), so this loop carries
/// only what actually changes mid-stream.
fn spawn_heartbeat(
    outbound: mpsc::Sender<AttachRequest>,
    state: AgentState,
) -> AbortOnDropHandle<()> {
    AbortOnDropHandle::new(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(HEARTBEAT_INTERVAL);
        loop {
            ticker.tick().await;
            let telemetry = host::telemetry();
            state.set_telemetry(telemetry_to_control(&telemetry));
            let msg = attach_request::Msg::Heartbeat(Heartbeat {
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
    }))
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
            windows_runner_script: None,
            participate: true,
            vm_mode: crate::config::VmMode::Auto,
            macos_runner_image: "tahoe-base".to_owned(),
        }
    }

    /// A gateway that rejects every call with `UNAUTHENTICATED` — what a
    /// decommissioned machine's revoked credential meets (RUN-40).
    struct RejectingGateway;

    #[tonic::async_trait]
    impl arcbox_fleet_proto::v1::fleet_gateway_service_server::FleetGatewayService
        for RejectingGateway
    {
        async fn enroll(
            &self,
            _: Request<arcbox_fleet_proto::v1::EnrollRequest>,
        ) -> Result<tonic::Response<arcbox_fleet_proto::v1::EnrollResponse>, tonic::Status>
        {
            Err(tonic::Status::unauthenticated("machine decommissioned"))
        }

        type AttachStream = tokio_stream::wrappers::ReceiverStream<
            Result<arcbox_fleet_proto::v1::AttachResponse, tonic::Status>,
        >;

        async fn attach(
            &self,
            _: Request<tonic::Streaming<AttachRequest>>,
        ) -> Result<tonic::Response<Self::AttachStream>, tonic::Status> {
            Err(tonic::Status::unauthenticated("machine decommissioned"))
        }

        async fn unenroll(
            &self,
            _: Request<arcbox_fleet_proto::v1::UnenrollRequest>,
        ) -> Result<tonic::Response<arcbox_fleet_proto::v1::UnenrollResponse>, tonic::Status>
        {
            Err(tonic::Status::unauthenticated("machine decommissioned"))
        }
    }

    /// A revoked credential parks the attach loop: `CREDENTIAL_REJECTED` is
    /// observable, no reconnect attempts follow, and the loop still exits
    /// cleanly on shutdown (so unenroll's teardown works from parked).
    #[tokio::test]
    async fn attach_parks_visibly_when_the_gateway_rejects_the_credential() {
        use arcbox_fleet_proto::v1::fleet_gateway_service_server::FleetGatewayServiceServer;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gateway = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(FleetGatewayServiceServer::new(RejectingGateway))
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener)),
        );

        let state = AgentState::new(&PersistedSettings {
            gateway: gateway.clone(),
            ..seed()
        });
        let config = AgentConfig {
            gateway,
            runner_script: None,
            windows_runner_script: None,
            load_ceiling: 0.9,
            mem_floor_mib: 2048,
            data_dir: std::env::temp_dir(),
            docker: crate::config::DockerConfig {
                mode: DockerMode::Disabled,
                linux_runner_image: "img".to_owned(),
            },
            vm: crate::config::VmConfig {
                mode: crate::config::VmMode::Disabled,
                macos_runner_image: "tahoe-base".to_owned(),
                daemon_socket: std::path::PathBuf::from("/nonexistent/arcbox.sock"),
            },
            credential_store: crate::config::CredentialMode::File,
        };
        let credential = Credential {
            machine_id: "fltm_parked".to_owned(),
            machine_token: "flt_revoked".to_owned(),
        };
        let backends = Backends::fixed(Vec::new(), state.clone());
        let handover = Handover::new(state.clone());
        let (supervisor, egress_rx) = spawn_supervisor(
            &config,
            Arc::clone(&backends),
            state.clone(),
            Arc::clone(&handover),
        );
        let shutdown = CancellationToken::new();
        let run = tokio::spawn(run(
            config,
            credential,
            supervisor,
            egress_rx,
            backends,
            shutdown.clone(),
            state.clone(),
            handover,
        ));

        // The loop must reach the parked state rather than retry-looping.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let snapshot = state.current();
            if snapshot.enrollment == control_proto::Enrollment::CredentialRejected as i32 {
                assert_eq!(snapshot.machine_id, "fltm_parked");
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "never parked on the rejected credential"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        // Parked is not exited: the task is still alive, waiting on shutdown.
        assert!(!run.is_finished());

        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(5), run)
            .await
            .expect("parked loop exits on shutdown")
            .expect("attach task must not panic")
            .expect("clean exit");
    }

    /// A gateway that never sends a response until it has read the agent's
    /// first request message — replicating a load balancer that won't relay
    /// a quiet response and instead idle-times it out (PLAT-34: the real
    /// deployment held the response for a full 60s, then reset the stream,
    /// because neither side ever sent anything first).
    struct SilentUntilFirstMessageGateway;

    #[tonic::async_trait]
    impl arcbox_fleet_proto::v1::fleet_gateway_service_server::FleetGatewayService
        for SilentUntilFirstMessageGateway
    {
        async fn enroll(
            &self,
            _: Request<arcbox_fleet_proto::v1::EnrollRequest>,
        ) -> Result<tonic::Response<arcbox_fleet_proto::v1::EnrollResponse>, tonic::Status>
        {
            Err(tonic::Status::unimplemented("not used by this test"))
        }

        type AttachStream = tokio_stream::wrappers::ReceiverStream<
            Result<arcbox_fleet_proto::v1::AttachResponse, tonic::Status>,
        >;

        async fn attach(
            &self,
            request: Request<tonic::Streaming<AttachRequest>>,
        ) -> Result<tonic::Response<Self::AttachStream>, tonic::Status> {
            request
                .into_inner()
                .message()
                .await
                .map_err(|e| tonic::Status::internal(e.to_string()))?
                .ok_or_else(|| tonic::Status::internal("closed before any message arrived"))?;
            // Send AttachAccepted then immediately close — under the redesigned
            // handshake, the client waits for this before proceeding. Without
            // it the client would treat the empty stream as a handshake
            // failure. This test only cares that response headers were
            // unblocked once the client spoke first, not about dispatch.
            let (tx, rx) = mpsc::channel(1);
            let _ = tx
                .send(Ok(arcbox_fleet_proto::v1::AttachResponse {
                    msg: Some(attach_response::Msg::AttachAccepted(
                        arcbox_fleet_proto::v1::AttachAccepted {},
                    )),
                }))
                .await;
            Ok(tonic::Response::new(
                tokio_stream::wrappers::ReceiverStream::new(rx),
            ))
        }

        async fn unenroll(
            &self,
            _: Request<arcbox_fleet_proto::v1::UnenrollRequest>,
        ) -> Result<tonic::Response<arcbox_fleet_proto::v1::UnenrollResponse>, tonic::Status>
        {
            Err(tonic::Status::unimplemented("not used by this test"))
        }
    }

    /// Regression test for PLAT-34: if the agent waits for the gateway's
    /// response before sending anything, and the gateway (or a proxy in
    /// front of it) withholds its response until it sees the agent send
    /// something, both sides deadlock — silently, until whatever's fronting
    /// the connection eventually resets it on its own idle timeout. The
    /// agent must speak first.
    #[tokio::test]
    async fn connect_and_serve_sends_a_message_before_the_gateway_ever_responds() {
        use arcbox_fleet_proto::v1::fleet_gateway_service_server::FleetGatewayServiceServer;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gateway = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(FleetGatewayServiceServer::new(
                    SilentUntilFirstMessageGateway,
                ))
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener)),
        );

        // `connect_and_serve` dials `state.gateway_target()`, not
        // `config.gateway` (see that fn's own doc) — the state must be
        // seeded with the mock's address, matching how enrollment does it.
        let state = AgentState::new(&PersistedSettings {
            gateway: gateway.clone(),
            ..seed()
        });
        let supervisor = supervisor();
        let backends = Backends::fixed(Vec::new(), AgentState::new(&seed()));
        let mut backends_rx = backends.subscribe();
        let (_egress_tx, mut egress_rx) = mpsc::channel::<AttachRequest>(1);
        let mut pending = None;
        let mut backoff = INITIAL_BACKOFF;
        let shutdown = CancellationToken::new();

        let config = AgentConfig {
            gateway,
            ..config()
        };
        let credential = credential();

        // A generous-but-bounded deadline distinguishes "worked" from
        // "deadlocked with the mock" without depending on any real network
        // timeout.
        let handover = Handover::new(state.clone());
        tokio::time::timeout(
            Duration::from_secs(3),
            connect_and_serve(
                &config,
                &credential,
                &supervisor,
                &mut egress_rx,
                &mut pending,
                &mut backoff,
                &backends,
                &mut backends_rx,
                &shutdown,
                &state,
                &handover,
            ),
        )
        .await
        .expect("must send a message before waiting on the response, not deadlock with the gateway")
        .expect("clean exit once the mock's response stream closes");

        assert_eq!(
            state.current().enrollment,
            control_proto::Enrollment::Attached as i32,
        );
    }

    /// A gateway that accepts every `Attach`, records each handshake's
    /// capability set, and holds the stream open (draining inbound so
    /// heartbeats don't backpressure) until the client leaves.
    struct RecordingGateway {
        attaches: Arc<tokio::sync::Mutex<Vec<Vec<arcbox_fleet_proto::v1::Capability>>>>,
    }

    #[tonic::async_trait]
    impl arcbox_fleet_proto::v1::fleet_gateway_service_server::FleetGatewayService
        for RecordingGateway
    {
        async fn enroll(
            &self,
            _: Request<arcbox_fleet_proto::v1::EnrollRequest>,
        ) -> Result<tonic::Response<arcbox_fleet_proto::v1::EnrollResponse>, tonic::Status>
        {
            Err(tonic::Status::unimplemented("not used by this test"))
        }

        type AttachStream = tokio_stream::wrappers::ReceiverStream<
            Result<arcbox_fleet_proto::v1::AttachResponse, tonic::Status>,
        >;

        async fn attach(
            &self,
            request: Request<tonic::Streaming<AttachRequest>>,
        ) -> Result<tonic::Response<Self::AttachStream>, tonic::Status> {
            let mut inbound = request.into_inner();
            let first = inbound
                .message()
                .await
                .map_err(|e| tonic::Status::internal(e.to_string()))?
                .ok_or_else(|| tonic::Status::internal("closed before Attach"))?;
            let Some(attach_request::Msg::Attach(attach)) = first.msg else {
                return Err(tonic::Status::internal("first message was not Attach"));
            };
            self.attaches.lock().await.push(attach.capabilities);

            let (tx, rx) = mpsc::channel(4);
            let _ = tx
                .send(Ok(arcbox_fleet_proto::v1::AttachResponse {
                    msg: Some(attach_response::Msg::AttachAccepted(
                        arcbox_fleet_proto::v1::AttachAccepted {},
                    )),
                }))
                .await;
            tokio::spawn(async move {
                // Keep the response stream open while draining heartbeats;
                // dropping `tx` when the client hangs up closes it.
                let _hold = tx;
                while let Ok(Some(_)) = inbound.message().await {}
            });
            Ok(tonic::Response::new(
                tokio_stream::wrappers::ReceiverStream::new(rx),
            ))
        }

        async fn unenroll(
            &self,
            _: Request<arcbox_fleet_proto::v1::UnenrollRequest>,
        ) -> Result<tonic::Response<arcbox_fleet_proto::v1::UnenrollResponse>, tonic::Status>
        {
            Err(tonic::Status::unimplemented("not used by this test"))
        }
    }

    /// The re-attach contract end to end: a backend activating mid-stream
    /// must make the attach loop leave its live stream and re-attach, with
    /// the fresh handshake declaring the grown capability set — that
    /// reconnect is what propagates a capability change to the gateway.
    #[tokio::test]
    async fn backend_activation_reattaches_with_fresh_capabilities() {
        use arcbox_fleet_proto::v1::fleet_gateway_service_server::FleetGatewayServiceServer;

        let attaches = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gateway = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(FleetGatewayServiceServer::new(RecordingGateway {
                    attaches: Arc::clone(&attaches),
                }))
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener)),
        );

        let state = AgentState::new(&PersistedSettings {
            gateway: gateway.clone(),
            ..seed()
        });
        let config = AgentConfig {
            gateway,
            ..config()
        };
        let backends = Backends::new(false, None, None, None, state.clone());
        let handover = Handover::new(state.clone());
        let (supervisor, egress_rx) = spawn_supervisor(
            &config,
            Arc::clone(&backends),
            state.clone(),
            Arc::clone(&handover),
        );
        let shutdown = CancellationToken::new();
        let run_task = tokio::spawn(run(
            config,
            credential(),
            supervisor,
            egress_rx,
            Arc::clone(&backends),
            shutdown.clone(),
            state,
            handover,
        ));

        async fn wait_for_attaches(
            attaches: &tokio::sync::Mutex<Vec<Vec<arcbox_fleet_proto::v1::Capability>>>,
            n: usize,
        ) {
            tokio::time::timeout(Duration::from_secs(5), async {
                while attaches.lock().await.len() < n {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap_or_else(|_| panic!("gateway never saw {n} Attach handshakes"));
        }

        // First attach declares the empty startup set.
        wait_for_attaches(&attaches, 1).await;
        assert!(attaches.lock().await[0].is_empty());

        // Activate the VM backend mid-stream; the loop must re-attach and
        // declare it.
        let daemon = crate::mock_daemon::MockDaemon::spawn(&["tahoe-base"]).await;
        let vm = crate::vm::VmRunner::new(&daemon.socket, "tahoe-base")
            .await
            .expect("probe against the mock daemon");
        backends.activate_vm(vm);

        wait_for_attaches(&attaches, 2).await;
        let second = attaches.lock().await[1].clone();
        assert_eq!(second.len(), 1);
        assert_eq!(
            second[0].backed_by,
            arcbox_fleet_proto::v1::Backend::Vm as i32
        );

        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(5), run_task)
            .await
            .expect("attach loop exits on shutdown")
            .expect("attach task must not panic")
            .expect("clean exit");
    }

    /// The verdict-resend loop is attachment-scoped: cancelling the shutdown
    /// token must reap it. Otherwise every unenroll/re-enroll cycle would
    /// leak a task holding a supervisor clone (DashMaps, egress sender, Docker
    /// handle) for the life of the process.
    #[tokio::test]
    async fn verdict_resend_task_exits_when_shutdown_fires() {
        let shutdown = CancellationToken::new();
        let handle = spawn_verdict_resend(supervisor(), shutdown.clone());

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
            windows_runner_script: None,
            load_ceiling: 0.9,
            mem_floor_mib: 2048,
            data_dir: std::env::temp_dir(),
            docker: crate::config::DockerConfig {
                mode: DockerMode::Disabled,
                linux_runner_image: "img".to_owned(),
            },
            vm: crate::config::VmConfig {
                mode: crate::config::VmMode::Disabled,
                macos_runner_image: "tahoe-base".to_owned(),
                daemon_socket: std::path::PathBuf::from("/nonexistent/arcbox.sock"),
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

    /// A minimal supervisor over an empty fixed-capability registry, with
    /// its own observable state — for tests that only need the handle and
    /// never route a verdict through it (the egress receiver is dropped).
    fn supervisor() -> RunnerSupervisor {
        let (events, _rx) = mpsc::channel(1);
        let state = AgentState::new(&seed());
        RunnerSupervisor::new(
            events,
            None,
            Backends::fixed(Vec::new(), state.clone()),
            state.clone(),
            Handover::new(state),
        )
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
        let supervisor = supervisor();
        let backends = Backends::fixed(Vec::new(), AgentState::new(&seed()));
        let mut backends_rx = backends.subscribe();
        let (_egress_tx, mut egress_rx) = mpsc::channel::<AttachRequest>(1);
        let mut pending = None;
        let mut backoff = INITIAL_BACKOFF;
        let shutdown = CancellationToken::new();
        shutdown.cancel();

        let config = config();
        let credential = credential();

        let handover = Handover::new(state.clone());
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            connect_and_serve(
                &config,
                &credential,
                &supervisor,
                &mut egress_rx,
                &mut pending,
                &mut backoff,
                &backends,
                &mut backends_rx,
                &shutdown,
                &state,
                &handover,
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
