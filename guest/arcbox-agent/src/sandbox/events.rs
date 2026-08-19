//! Sandbox lifecycle event streaming.

use std::collections::HashSet;
use std::time::Duration;

use arcbox_connect::sandbox_v1;
use arcbox_connect::v1::{SandboxCleanupTicket, WatchSandboxCleanupRequest};
use buffa::Message;
use tokio::io::AsyncWrite;
use tokio::sync::mpsc;

use super::{SandboxService, convert};
use crate::error::SandboxError;
use crate::rpc::{ErrorResponse, MessageType, write_message};
use crate::sandbox_cleanup_watch::unseen_rescan_tickets;

/// Events buffered between the filter task and one subscriber.
const EVENT_QUEUE_CAPACITY: usize = 64;

impl SandboxService {
    /// Replay durable cleanup tickets, then stream tickets created by terminal
    /// lifecycle events. The live broadcast subscription is opened before the
    /// snapshot so no event can fall into a subscribe/snapshot gap.
    pub(crate) async fn handle_cleanup_events<S>(
        &self,
        stream: &mut S,
        trace_id: &str,
        payload: &[u8],
    ) -> anyhow::Result<()>
    where
        S: AsyncWrite + Unpin,
    {
        WatchSandboxCleanupRequest::decode_from_slice(payload)
            .map_err(|error| anyhow::anyhow!("decode cleanup watch: {error}"))?;

        let mut lifecycle = self.manager.subscribe_events();
        let mut snapshot = match self.pending_cleanup_tickets().await {
            Ok(tickets) => tickets,
            Err(error) => {
                let response = ErrorResponse::new(error.status_code(), error.to_string());
                write_message(stream, MessageType::Error, trace_id, &response.encode()).await?;
                return Ok(());
            }
        };
        snapshot.sort_by(|left, right| {
            left.startup
                .cmp(&right.startup)
                .then_with(|| left.id.cmp(&right.id))
        });

        let mut sent = HashSet::<(String, String)>::new();
        for ticket in snapshot {
            write_cleanup_ticket(stream, trace_id, &mut sent, ticket).await?;
        }

        let mut rescan = tokio::time::interval(Duration::from_secs(1));
        rescan.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        rescan.tick().await;
        loop {
            tokio::select! {
                event = lifecycle.recv() => match event {
                    // Terminal teardowns release the network, and a pause
                    // quarantines it the same way (CORE-21) — emit the
                    // ticket promptly in both cases so the host finalizes
                    // before a resume needs the allocation back, instead of
                    // waiting for the 1 s rescan below.
                    Ok(event) if event.is_terminal() || event.action == "paused" => {
                        if let Some(ticket) = self
                            .pending_cleanup_ticket(&event.computer_id)
                            .await
                            .map_err(|error| anyhow::anyhow!(error.to_string()))?
                        {
                            write_cleanup_ticket(stream, trace_id, &mut sent, ticket).await?;
                        }
                    }
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        // Ending the stream forces the host to reconnect and replay
                        // the durable snapshot; continuing could silently lose a
                        // terminal generation.
                        tracing::warn!(skipped, "sandbox cleanup receiver lagged; forcing replay");
                        return Ok(());
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return Ok(()),
                },
                _ = rescan.tick() => {
                    // Quarantine can succeed before a later teardown step
                    // fails, in which case no terminal lifecycle event is
                    // emitted. Durable markers are the authority, so poll them
                    // while the connection remains healthy.
                    let tickets = self
                        .pending_cleanup_tickets()
                        .await
                        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
                    for ticket in unseen_rescan_tickets(&mut sent, tickets) {
                        write_cleanup_ticket(stream, trace_id, &mut sent, ticket).await?;
                    }
                }
            }
        }
    }

    /// Stream `SandboxEvent` frames from [`SandboxService::subscribe_events`].
    pub async fn handle_events<S>(
        &self,
        stream: &mut S,
        trace_id: &str,
        payload: &[u8],
    ) -> anyhow::Result<()>
    where
        S: AsyncWrite + Unpin,
    {
        let mut rx = match self.subscribe_events(payload) {
            Ok(r) => r,
            Err(e) => {
                let err = ErrorResponse::new(e.status_code(), e.to_string());
                write_message(stream, MessageType::Error, trace_id, &err.encode()).await?;
                return Ok(());
            }
        };

        while let Some(encoded) = rx.recv().await {
            write_message(stream, MessageType::SandboxEvent, trace_id, &encoded).await?;
        }

        Ok(())
    }

    /// Subscribe to sandbox lifecycle events.  Returns a channel of encoded
    /// [`sandbox_v1::SandboxEvent`] payloads.
    ///
    /// The channel is bounded: a subscriber that stops reading (a wedged
    /// transport write, a stalled client) blocks the filter task, which stops
    /// draining the broadcast and lets it lag — dropping events with a warn,
    /// the designed overflow behavior. An unbounded channel instead grew
    /// guest-agent memory for as long as the stall lasted.
    pub fn subscribe_events(
        &self,
        payload: &[u8],
    ) -> Result<mpsc::Receiver<Vec<u8>>, SandboxError> {
        let req = sandbox_v1::SandboxEventsRequest::decode_from_slice(payload)
            .map_err(|e| SandboxError::Decode(e.to_string()))?;
        let filter_id = req.sandbox_id.clone();
        // Unknown wire values fall back to UNSPECIFIED (no filter).
        let filter_kind = req.kind.as_known().unwrap_or_default();

        let mut bcast_rx = self.manager.subscribe_events();
        let (tx, out_rx) = mpsc::channel::<Vec<u8>>(EVENT_QUEUE_CAPACITY);

        tokio::spawn(async move {
            loop {
                match bcast_rx.recv().await {
                    Ok(event) => {
                        // Apply filters.
                        if !filter_id.is_empty() && event.computer_id != filter_id {
                            continue;
                        }
                        if filter_kind != sandbox_v1::SandboxEventKind::Unspecified
                            && convert::event_kind(&event.action) != filter_kind
                        {
                            continue;
                        }
                        let msg = convert::vm_event_to_proto(event);
                        if tx.send(msg.encode_to_vec()).await.is_err() {
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(skipped = n, "sandbox events receiver lagged");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        break;
                    }
                }
            }
        });

        Ok(out_rx)
    }
}

async fn write_cleanup_ticket<S>(
    stream: &mut S,
    trace_id: &str,
    sent: &mut HashSet<(String, String)>,
    ticket: SandboxCleanupTicket,
) -> anyhow::Result<()>
where
    S: AsyncWrite + Unpin,
{
    if sent.insert((ticket.id.clone(), ticket.token.clone())) {
        write_message(
            stream,
            MessageType::SandboxCleanupEvent,
            trace_id,
            &ticket.encode_to_vec(),
        )
        .await?;
    }
    Ok(())
}
