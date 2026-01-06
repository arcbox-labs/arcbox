//! Container state management.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Container identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ContainerId(String);

impl ContainerId {
    /// Creates a new random container ID.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string().replace('-', "")[..12].to_string())
    }

    /// Creates a container ID from a string.
    #[must_use]
    pub fn from_string(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Returns the ID as a string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for ContainerId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ContainerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Container state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ContainerState {
    /// Container created but not started.
    Created,
    /// Container is running.
    Running,
    /// Container is paused.
    Paused,
    /// Container is restarting.
    Restarting,
    /// Container has exited.
    Exited,
    /// Container is being removed.
    Removing,
    /// Container is dead (error state).
    Dead,
}

impl std::fmt::Display for ContainerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Created => write!(f, "created"),
            Self::Running => write!(f, "running"),
            Self::Paused => write!(f, "paused"),
            Self::Restarting => write!(f, "restarting"),
            Self::Exited => write!(f, "exited"),
            Self::Removing => write!(f, "removing"),
            Self::Dead => write!(f, "dead"),
        }
    }
}

/// Container information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Container {
    /// Container ID.
    pub id: ContainerId,
    /// Container name.
    pub name: String,
    /// Image name.
    pub image: String,
    /// Machine name (VM where container runs).
    pub machine_name: Option<String>,
    /// Current state.
    pub state: ContainerState,
    /// Creation time.
    pub created: DateTime<Utc>,
    /// Start time (if running).
    pub started_at: Option<DateTime<Utc>>,
    /// Exit code (if exited).
    pub exit_code: Option<i32>,
}

impl Container {
    /// Creates a new container.
    #[must_use]
    pub fn new(name: impl Into<String>, image: impl Into<String>) -> Self {
        Self {
            id: ContainerId::new(),
            name: name.into(),
            image: image.into(),
            machine_name: None,
            state: ContainerState::Created,
            created: Utc::now(),
            started_at: None,
            exit_code: None,
        }
    }

    /// Creates a new container for a specific machine.
    #[must_use]
    pub fn new_for_machine(
        name: impl Into<String>,
        image: impl Into<String>,
        machine: impl Into<String>,
    ) -> Self {
        Self {
            id: ContainerId::new(),
            name: name.into(),
            image: image.into(),
            machine_name: Some(machine.into()),
            state: ContainerState::Created,
            created: Utc::now(),
            started_at: None,
            exit_code: None,
        }
    }

    /// Returns whether the container is running.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.state == ContainerState::Running
    }
}
