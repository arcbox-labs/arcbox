//! The `serve` subcommand: the long-running agent process.
//!
//! Assembles the backend registry, the enrollment supervisor and the local
//! control-plane server, then runs until a termination signal or an operator
//! `Restart` brings it down. What it returns tells [`crate::main`] how to
//! leave: exit, or replace this process image.

use std::sync::Arc;

use anyhow::Result;

use crate::config::AgentConfig;
use crate::control::{self, RestartIntent};
use crate::settings::SettingsStore;
use crate::state::AgentState;
use crate::{backends, init_backends, load_or_seed_settings, shutdown};

/// How the `serve` process is meant to end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Terminate normally.
    Exit,
    /// Re-exec this executable, preserving argv (see [`crate::reexec`]).
    Restart,
}

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

    // Cascades to every attach task's child token, so runners still
    // drain on SIGTERM even though `Unenroll` can also cancel one
    // independently. The signal and the restart path share this token, so
    // the signal vetoes any pending restart before cancelling it: otherwise
    // a SIGTERM landing on an agent that is waiting out its last job would
    // be indistinguishable from the restart it was waiting for, and this
    // process would come back instead of stopping.
    let restart = Arc::new(RestartIntent::default());
    let shutdown = shutdown::spawn_with("termination signal received; shutting down", {
        let restart = Arc::clone(&restart);
        move || restart.terminate()
    });
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
            shutdown.clone(),
            agent_state.clone(),
            settings_store.clone(),
            Arc::clone(&restart),
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
    // Read after the teardown, not at request time: a termination signal
    // arriving mid-restart clears the intent, so "a restart was requested"
    // and "this shutdown is a restart" are not the same question.
    Ok(if restart.mode().is_some() {
        Outcome::Restart
    } else {
        Outcome::Exit
    })
}
