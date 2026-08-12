//! Host half of durable sandbox network cleanup.

use std::sync::Arc;
use std::time::Duration;

use arcbox_connect::sandbox_v1::{InspectSandboxRequest, SandboxInfo, SandboxState};
use arcbox_connect::v1::SandboxCleanupTicket;
use arcbox_engine::EngineError;
use arcbox_engine::agent_client::AgentClient;
use arcbox_engine::machine::DEFAULT_MACHINE_NAME;

use crate::host::SandboxHost;

/// Validate a cleanup generation, remove host-owned state, then let the guest
/// recycle its DNAT relay and quarantined IP.
pub async fn complete<H: SandboxHost>(
    host: &H,
    agent: &mut AgentClient,
    ticket: &SandboxCleanupTicket,
) -> arcbox_engine::Result<()> {
    let mut host_generation = host.lock_host_state().await;
    if let Err(error) = agent.sandbox_cleanup_prepare(ticket).await {
        return if obsolete_ticket(&error) {
            Ok(())
        } else {
            Err(error)
        };
    }
    *host_generation = (*host_generation).wrapping_add(1);
    if ticket.startup {
        host.clear_host_state().await;
    } else {
        host.remove_ports(&ticket.id).await;
        host.deregister_dns(&ticket.id).await;
    }
    match agent.sandbox_cleanup_finalize(ticket).await {
        Err(error) if obsolete_ticket(&error) => Ok(()),
        result => result,
    }
}

/// Confirm that a cleanup-raced result still names the live guest sandbox.
pub async fn live_sandbox_matches<H: SandboxHost>(
    host: &H,
    machine: &str,
    sandbox_id: &str,
    ip: std::net::IpAddr,
) -> bool {
    let Ok(mut agent) = host.agent(machine) else {
        return false;
    };
    let Ok(info) = agent
        .sandbox_inspect(InspectSandboxRequest {
            id: sandbox_id.to_owned(),
            ..Default::default()
        })
        .await
    else {
        return false;
    };
    live_sandbox_info_matches(&info, ip)
}

fn live_sandbox_info_matches(info: &SandboxInfo, ip: std::net::IpAddr) -> bool {
    let live = matches!(
        info.state.as_known(),
        Some(SandboxState::Starting | SandboxState::Ready | SandboxState::Running)
    );
    live && info
        .network
        .as_option()
        .and_then(|network| network.ip_address.parse().ok())
        == Some(ip)
}

/// Complete the initial cleanup replay before the daemon publishes its runtime.
/// Returns `false` when nested sandbox virtualization is unavailable.
///
/// # Errors
///
/// Returns an error if the agent is unreachable or the watch stream ends
/// before the startup cleanup completes.
pub async fn initialize<H: SandboxHost>(host: &H) -> arcbox_engine::Result<bool> {
    let watcher = host.agent(DEFAULT_MACHINE_NAME)?;
    let mut events = watcher.sandbox_cleanup_events().await?;
    while let Some(event) = events.recv().await {
        let ticket = match event {
            Ok(ticket) => ticket,
            Err(error) if sandbox_unavailable(&error) => return Ok(false),
            Err(error) => return Err(error),
        };
        let startup = ticket.startup;
        let mut agent = host.agent(DEFAULT_MACHINE_NAME)?;
        complete(host, &mut agent, &ticket).await?;
        if startup {
            return Ok(true);
        }
    }
    Err(EngineError::Machine(
        "sandbox cleanup watch ended before startup cleanup completed".into(),
    ))
}

/// Keep the System VM's durable cleanup stream connected.
///
/// Reconnects replay every unfinalized marker.
pub fn spawn<H: SandboxHost + 'static>(host: Arc<H>) {
    tokio::spawn(async move {
        loop {
            if let Err(error) = watch_once(host.as_ref()).await {
                tracing::warn!(error = %error, "sandbox cleanup watch disconnected");
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });
}

async fn watch_once<H: SandboxHost>(host: &H) -> arcbox_engine::Result<()> {
    let watcher = host.agent(DEFAULT_MACHINE_NAME)?;
    let mut events = watcher.sandbox_cleanup_events().await?;
    while let Some(event) = events.recv().await {
        let ticket = event?;
        let mut agent = host.agent(DEFAULT_MACHINE_NAME)?;
        complete(host, &mut agent, &ticket).await?;
    }
    Err(EngineError::Machine(
        "sandbox cleanup watch ended before reconnect".into(),
    ))
}

fn obsolete_ticket(error: &EngineError) -> bool {
    matches!(
        error,
        EngineError::Agent {
            code: 404 | 412,
            ..
        }
    )
}

fn sandbox_unavailable(error: &EngineError) -> bool {
    matches!(error, EngineError::Agent { code: 412, .. })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_missing_or_wrong_generation_tickets_are_obsolete() {
        for code in [404, 412] {
            assert!(obsolete_ticket(&EngineError::Agent {
                code,
                message: "stale".into(),
            }));
        }
        assert!(!obsolete_ticket(&EngineError::Agent {
            code: 503,
            message: "retry".into(),
        }));
        assert!(sandbox_unavailable(&EngineError::Agent {
            code: 412,
            message: "nested virtualization unavailable".into(),
        }));
        assert!(!sandbox_unavailable(&EngineError::Agent {
            code: 503,
            message: "data volume unavailable".into(),
        }));
    }

    #[test]
    fn only_the_live_matching_network_can_rebuild_host_state() {
        let ip: std::net::IpAddr = "192.0.2.2".parse().unwrap();
        let mut info = SandboxInfo {
            state: SandboxState::Ready.into(),
            network: Some(arcbox_connect::sandbox_v1::SandboxNetwork {
                ip_address: ip.to_string(),
                ..Default::default()
            })
            .into(),
            ..Default::default()
        };
        assert!(live_sandbox_info_matches(&info, ip));

        info.state = SandboxState::Stopped.into();
        assert!(!live_sandbox_info_matches(&info, ip));
        info.state = SandboxState::Ready.into();
        assert!(!live_sandbox_info_matches(
            &info,
            "192.0.2.3".parse().unwrap()
        ));
    }
}
