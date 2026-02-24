//! Event system for inter-component communication.

use tokio::sync::broadcast;

/// System events.
#[derive(Debug, Clone)]
pub enum Event {
    /// VM started.
    VmStarted { id: String },
    /// VM stopped.
    VmStopped { id: String },
    /// Machine created.
    MachineCreated { name: String },
    /// Machine started.
    MachineStarted { name: String },
    /// Machine stopped.
    MachineStopped { name: String },
    /// Container created.
    ContainerCreated {
        id: String,
        name: String,
        image: String,
        labels: std::collections::HashMap<String, String>,
    },
    /// Container started.
    ContainerStarted {
        id: String,
        name: String,
        image: String,
        labels: std::collections::HashMap<String, String>,
    },
    /// Container stopped.
    ContainerStopped {
        id: String,
        name: String,
        image: String,
        labels: std::collections::HashMap<String, String>,
        exit_code: Option<i32>,
    },
    /// Container killed.
    ContainerKilled {
        id: String,
        name: String,
        image: String,
        labels: std::collections::HashMap<String, String>,
        signal: String,
        exit_code: Option<i32>,
    },
    /// Container exited.
    ContainerDied {
        id: String,
        name: String,
        image: String,
        labels: std::collections::HashMap<String, String>,
        exit_code: Option<i32>,
    },
    /// Container removed.
    ContainerRemoved {
        id: String,
        name: String,
        image: String,
        labels: std::collections::HashMap<String, String>,
    },
    /// Image pulled.
    ImagePulled { id: String, reference: String },
    /// Image removed.
    ImageRemoved { id: String, reference: String },
    /// Network created.
    NetworkCreated {
        id: String,
        name: String,
        driver: String,
        labels: std::collections::HashMap<String, String>,
    },
    /// Network removed.
    NetworkRemoved {
        id: String,
        name: String,
        driver: String,
        labels: std::collections::HashMap<String, String>,
    },
    /// Volume created.
    VolumeCreated {
        name: String,
        driver: String,
        labels: std::collections::HashMap<String, String>,
    },
    /// Volume removed.
    VolumeRemoved {
        name: String,
        driver: String,
        labels: std::collections::HashMap<String, String>,
    },
}

/// Event bus for system-wide event distribution.
#[derive(Clone)]
pub struct EventBus {
    sender: broadcast::Sender<Event>,
}

impl EventBus {
    /// Creates a new event bus.
    #[must_use]
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(256);
        Self { sender }
    }

    /// Publishes an event.
    pub fn publish(&self, event: Event) {
        let _ = self.sender.send(event);
    }

    /// Subscribes to events.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.sender.subscribe()
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}
