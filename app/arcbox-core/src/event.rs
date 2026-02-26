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
