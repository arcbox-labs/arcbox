//! VMM event loop.
//!
//! This module provides the main event loop that coordinates vCPU execution,
//! device I/O, and timers.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::sync::mpsc;

use crate::error::{Result, VmmError};
use arcbox_hypervisor::VcpuExit;

/// VMM events.
#[derive(Debug)]
pub enum VmmEvent {
    /// vCPU exit event.
    VcpuExit {
        /// vCPU ID.
        vcpu_id: u32,
        /// Exit reason.
        exit: VcpuExit,
    },
    /// Device I/O event.
    DeviceIo {
        /// Device ID.
        device_id: u32,
        /// Is this a read operation?
        is_read: bool,
        /// Address.
        addr: u64,
        /// Data (for writes).
        data: Option<u64>,
    },
    /// Timer expired.
    Timer {
        /// Timer ID.
        id: u32,
    },
    /// Shutdown requested.
    Shutdown,
}

/// Event loop for the VMM.
///
/// Coordinates events from multiple sources: vCPUs, devices, and timers.
pub struct EventLoop {
    /// Whether the event loop is running.
    running: Arc<AtomicBool>,
    /// Event sender (for posting events).
    event_tx: mpsc::UnboundedSender<VmmEvent>,
    /// Event receiver.
    event_rx: mpsc::UnboundedReceiver<VmmEvent>,
}

impl EventLoop {
    /// Creates a new event loop.
    ///
    /// # Errors
    ///
    /// Returns an error if the event loop cannot be created.
    pub fn new() -> Result<Self> {
        let (event_tx, event_rx) = mpsc::unbounded_channel();

        Ok(Self {
            running: Arc::new(AtomicBool::new(false)),
            event_tx,
            event_rx,
        })
    }

    /// Returns a sender for posting events.
    #[must_use]
    pub fn event_sender(&self) -> mpsc::UnboundedSender<VmmEvent> {
        self.event_tx.clone()
    }

    /// Returns whether the event loop is running.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Starts the event loop.
    ///
    /// # Errors
    ///
    /// Returns an error if the event loop cannot be started.
    pub fn start(&mut self) -> Result<()> {
        self.running.store(true, Ordering::SeqCst);
        tracing::debug!("Event loop started");
        Ok(())
    }

    /// Stops the event loop.
    pub fn stop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        tracing::debug!("Event loop stopped");
    }

    /// Posts an event to the event loop.
    ///
    /// # Errors
    ///
    /// Returns an error if the event cannot be posted.
    pub fn post_event(&self, event: VmmEvent) -> Result<()> {
        self.event_tx
            .send(event)
            .map_err(|e| VmmError::EventLoop(format!("failed to post event: {}", e)))
    }

    /// Polls for the next event.
    ///
    /// Returns `None` if no event is available or the loop is stopped.
    pub async fn poll(&mut self) -> Option<VmmEvent> {
        if !self.is_running() {
            return None;
        }

        // Use a timeout to allow periodic checks
        tokio::select! {
            event = self.event_rx.recv() => {
                event
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                None
            }
        }
    }

    /// Polls for events without blocking.
    pub fn try_poll(&mut self) -> Option<VmmEvent> {
        self.event_rx.try_recv().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_event_loop_creation() {
        let event_loop = EventLoop::new().unwrap();
        assert!(!event_loop.is_running());
    }

    #[tokio::test]
    async fn test_event_posting() {
        let mut event_loop = EventLoop::new().unwrap();
        event_loop.start().unwrap();

        // Post an event
        event_loop.post_event(VmmEvent::Shutdown).unwrap();

        // Poll for it
        let event = event_loop.poll().await;
        assert!(matches!(event, Some(VmmEvent::Shutdown)));
    }

    #[tokio::test]
    async fn test_event_loop_stop() {
        let mut event_loop = EventLoop::new().unwrap();
        event_loop.start().unwrap();
        assert!(event_loop.is_running());

        event_loop.stop();
        assert!(!event_loop.is_running());

        // Polling stopped loop returns None
        let event = event_loop.poll().await;
        assert!(event.is_none());
    }
}
