//! Agent stub for non-Linux platforms (development / testing).
//!
//! On non-Linux hosts vsock is unavailable; this stub keeps the crate
//! buildable on macOS so the rest of the workspace stays green.

use anyhow::Result;

use arcbox_constants::ports::AGENT_PORT;

/// The Guest Agent (stub for non-Linux platforms).
pub struct Agent;

impl Agent {
    /// Creates a new agent.
    pub fn new() -> Self {
        Self
    }

    /// Runs the agent (stub mode).
    ///
    /// On non-Linux platforms (e.g., macOS), vsock is not available.
    /// This stub allows development and testing on the host.
    pub async fn run(&self) -> Result<()> {
        tracing::warn!("Agent is running in stub mode (non-Linux platform)");
        tracing::info!("Agent would listen on vsock port {}", AGENT_PORT);

        // In stub mode, we just keep the agent running
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
            tracing::debug!("Agent stub heartbeat");
        }
    }
}

impl Default for Agent {
    fn default() -> Self {
        Self::new()
    }
}
