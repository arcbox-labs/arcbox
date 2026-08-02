//! Sandbox lifecycle event streaming.

use arcbox_connect::sandbox_v1;
use buffa::Message;
use tokio::io::AsyncWrite;
use tokio::sync::mpsc;

use super::{SandboxService, convert};
use crate::error::SandboxError;
use crate::rpc::{ErrorResponse, MessageType, write_message};

/// Events buffered between the filter task and one subscriber.
const EVENT_QUEUE_CAPACITY: usize = 64;

impl SandboxService {
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
                        if !filter_id.is_empty() && event.sandbox_id != filter_id {
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
