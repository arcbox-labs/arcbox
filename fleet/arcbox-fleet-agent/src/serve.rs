//! The `serve` subcommand: the long-running agent process.
//!
//! Assembles the backend registry, the enrollment supervisor and the local
//! control-plane server, then runs until a termination signal or an operator
//! `Restart` brings it down. What it returns tells [`crate::main`] how to
//! leave: exit, or replace this process image.

use std::sync::Arc;

use anyhow::Result;

use crate::config::AgentConfig;
use crate::control;
use crate::handover::{Handover, Outcome};
use crate::settings::SettingsStore;
use crate::state::AgentState;
use crate::{backends, init_backends, load_or_seed_settings, shutdown};

/// Start the local control-plane API and run until shutdown, attaching to
/// the gateway whenever a credential is available. Returns
/// [`Outcome::Restart`] when the shutdown was an operator `Restart` rather
/// than a termination signal.
pub async fn serve(config: AgentConfig) -> Result<Outcome> {
    let settings_store = SettingsStore::new(config.settings_path());
    let seed = load_or_seed_settings(&settings_store, &config)?;
    let agent_state = AgentState::new(&seed);
    let backends = init_backends(&config, &seed, agent_state.clone()).await?;
    let socket_path = config.control_socket_path();

    // One shutdown token for every way this process can end, cascading to
    // every attach task's child token so runners drain the same way whichever
    // it is. Which one it was is the handover's to answer, below.
    let handover = Handover::new(agent_state.clone());
    shutdown::arm(
        Arc::clone(&handover),
        "termination signal received; shutting down",
    );
    let shutdown = handover.shutdown().clone();
    backends::spawn_vm_reprobe(
        &backends,
        agent_state.clone(),
        seed.vm_mode,
        config.vm.daemon_socket.clone(),
        shutdown.clone(),
    );

    let supervisor = Arc::new(
        control::AgentSupervisor::new(
            config,
            backends,
            agent_state.clone(),
            settings_store.clone(),
            Arc::clone(&handover),
        )
        .await?,
    );
    let reconciler = supervisor.spawn_participation_reconciler(shutdown.clone());
    control::serve(
        &socket_path,
        Arc::clone(&supervisor),
        agent_state,
        settings_store,
        shutdown,
    )
    .await?;
    // The control server has stopped accepting connections; give any
    // live attach task its own shutdown grace before the process exits.
    supervisor.join().await;
    let _ = reconciler.await;
    Ok(handover.outcome())
}
