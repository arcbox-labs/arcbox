//! OCI container state management.
//!
//! This module defines the container state as per OCI runtime specification.
//! Reference: <https://github.com/opencontainers/runtime-spec/blob/main/runtime.md#state>

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{OciError, Result};

/// OCI container state.
///
/// This is the state structure as defined by the OCI runtime specification.
/// It is passed to hooks via stdin and returned by the `state` command.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct State {
    /// OCI specification version.
    pub oci_version: String,

    /// Container ID (unique identifier).
    pub id: String,

    /// Container status.
    pub status: Status,

    /// Process ID of the container's init process (if running).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,

    /// Absolute path to the bundle directory.
    pub bundle: PathBuf,

    /// Annotations from the container configuration.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub annotations: HashMap<String, String>,
}

impl State {
    /// Create a new container state.
    #[must_use]
    pub fn new(id: String, bundle: PathBuf) -> Self {
        Self {
            oci_version: crate::config::OCI_VERSION.to_string(),
            id,
            status: Status::Creating,
            pid: None,
            bundle,
            annotations: HashMap::new(),
        }
    }

    /// Create a new container state with generated ID.
    #[must_use]
    pub fn with_generated_id(bundle: PathBuf) -> Self {
        Self::new(Uuid::new_v4().to_string(), bundle)
    }

    /// Load state from JSON file.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&content)?)
    }

    /// Save state to JSON file.
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Convert to JSON string.
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Set the container PID.
    pub const fn set_pid(&mut self, pid: u32) {
        self.pid = Some(pid);
    }

    /// Clear the container PID.
    pub const fn clear_pid(&mut self) {
        self.pid = None;
    }

    /// Transition to a new status.
    ///
    /// Returns an error if the transition is invalid.
    pub fn transition_to(&mut self, new_status: Status) -> Result<()> {
        if !self.status.can_transition_to(new_status) {
            return Err(OciError::InvalidState {
                expected: self.status.valid_transitions().join(", "),
                actual: new_status.as_str().to_string(),
            });
        }
        self.status = new_status;
        Ok(())
    }
}

/// Container status as defined by OCI.
///
/// Valid state transitions:
/// - Creating -> Created
/// - Created -> Running
/// - Running -> Stopped
/// - Any -> Stopped (on error)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// Container is being created.
    Creating,
    /// Container has been created (create command has finished).
    Created,
    /// Container is running (start command has been invoked).
    Running,
    /// Container has stopped.
    Stopped,
}

impl Status {
    /// Get the status string.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Creating => "creating",
            Self::Created => "created",
            Self::Running => "running",
            Self::Stopped => "stopped",
        }
    }

    /// Check if transition to the given status is valid.
    #[must_use]
    pub const fn can_transition_to(&self, target: Self) -> bool {
        matches!(
            (self, target),
            (Self::Creating, Self::Created | Self::Stopped)
                | (Self::Created, Self::Running | Self::Stopped)
                | (Self::Running, Self::Stopped)
        )
    }

    /// Get valid transitions from current status.
    #[must_use]
    pub fn valid_transitions(&self) -> Vec<&'static str> {
        match self {
            Self::Creating => vec!["created", "stopped"],
            Self::Created => vec!["running", "stopped"],
            Self::Running => vec!["stopped"],
            Self::Stopped => vec![],
        }
    }

    /// Check if container is in a running state.
    #[must_use]
    pub const fn is_running(&self) -> bool {
        matches!(self, Self::Running)
    }

    /// Check if container can be started.
    #[must_use]
    pub const fn can_start(&self) -> bool {
        matches!(self, Self::Created)
    }

    /// Check if container can be killed.
    #[must_use]
    pub const fn can_kill(&self) -> bool {
        matches!(self, Self::Created | Self::Running)
    }

    /// Check if container can be deleted.
    #[must_use]
    pub const fn can_delete(&self) -> bool {
        matches!(self, Self::Stopped)
    }
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for Status {
    type Err = OciError;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "creating" => Ok(Self::Creating),
            "created" => Ok(Self::Created),
            "running" => Ok(Self::Running),
            "stopped" => Ok(Self::Stopped),
            _ => Err(OciError::InvalidConfig(format!("unknown status: {s}"))),
        }
    }
}

/// Extended container state with additional metadata.
///
/// This extends the OCI state with ArcBox-specific information.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContainerState {
    /// OCI state.
    #[serde(flatten)]
    pub oci_state: State,

    /// Creation timestamp.
    pub created: DateTime<Utc>,

    /// Start timestamp (if started).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started: Option<DateTime<Utc>>,

    /// Exit timestamp (if stopped).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finished: Option<DateTime<Utc>>,

    /// Exit code (if stopped).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,

    /// Container name (if named).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Image reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,

    /// Root filesystem path.
    pub rootfs: PathBuf,
}

impl ContainerState {
    /// Create a new container state.
    #[must_use]
    pub fn new(id: String, bundle: PathBuf, rootfs: PathBuf) -> Self {
        Self {
            oci_state: State::new(id, bundle),
            created: Utc::now(),
            started: None,
            finished: None,
            exit_code: None,
            name: None,
            image: None,
            rootfs,
        }
    }

    /// Get the container ID.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.oci_state.id
    }

    /// Get the container status.
    #[must_use]
    pub const fn status(&self) -> Status {
        self.oci_state.status
    }

    /// Get the bundle path.
    #[must_use]
    pub fn bundle(&self) -> &Path {
        &self.oci_state.bundle
    }

    /// Mark container as created.
    pub fn mark_created(&mut self) -> Result<()> {
        self.oci_state.transition_to(Status::Created)
    }

    /// Mark container as started.
    pub fn mark_started(&mut self, pid: u32) -> Result<()> {
        self.oci_state.set_pid(pid);
        self.oci_state.transition_to(Status::Running)?;
        self.started = Some(Utc::now());
        Ok(())
    }

    /// Mark container as stopped.
    pub fn mark_stopped(&mut self, exit_code: i32) -> Result<()> {
        self.oci_state.clear_pid();
        self.oci_state.transition_to(Status::Stopped)?;
        self.finished = Some(Utc::now());
        self.exit_code = Some(exit_code);
        Ok(())
    }

    /// Get the OCI state for hooks.
    #[must_use]
    pub const fn oci_state(&self) -> &State {
        &self.oci_state
    }

    /// Load from JSON file.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&content)?)
    }

    /// Save to JSON file.
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }
}

/// Container state store.
///
/// Manages container state persistence in a directory.
pub struct StateStore {
    /// Root directory for state files.
    root: PathBuf,
}

impl StateStore {
    /// Create a new state store.
    pub fn new<P: Into<PathBuf>>(root: P) -> Result<Self> {
        let root = root.into();
        std::fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    /// Get the state file path for a container.
    fn state_path(&self, id: &str) -> PathBuf {
        self.root.join(id).join("state.json")
    }

    /// Get the container directory path.
    fn container_dir(&self, id: &str) -> PathBuf {
        self.root.join(id)
    }

    /// Save container state.
    pub fn save(&self, state: &ContainerState) -> Result<()> {
        let dir = self.container_dir(state.id());
        std::fs::create_dir_all(&dir)?;
        state.save(self.state_path(state.id()))
    }

    /// Load container state.
    pub fn load(&self, id: &str) -> Result<ContainerState> {
        let path = self.state_path(id);
        if !path.exists() {
            return Err(OciError::ContainerNotFound(id.to_string()));
        }
        ContainerState::load(path)
    }

    /// Check if container exists.
    #[must_use]
    pub fn exists(&self, id: &str) -> bool {
        self.state_path(id).exists()
    }

    /// Delete container state.
    pub fn delete(&self, id: &str) -> Result<()> {
        let dir = self.container_dir(id);
        if dir.exists() {
            std::fs::remove_dir_all(dir)?;
        }
        Ok(())
    }

    /// List all container IDs.
    pub fn list(&self) -> Result<Vec<String>> {
        let mut ids = Vec::new();
        if self.root.exists() {
            for entry in std::fs::read_dir(&self.root)? {
                let entry = entry?;
                if entry.file_type()?.is_dir() {
                    if let Some(name) = entry.file_name().to_str() {
                        if self.state_path(name).exists() {
                            ids.push(name.to_string());
                        }
                    }
                }
            }
        }
        Ok(ids)
    }

    /// List all containers with their states.
    pub fn list_states(&self) -> Result<Vec<ContainerState>> {
        let ids = self.list()?;
        let mut states = Vec::with_capacity(ids.len());
        for id in ids {
            states.push(self.load(&id)?);
        }
        Ok(states)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_transitions() {
        assert!(Status::Creating.can_transition_to(Status::Created));
        assert!(Status::Created.can_transition_to(Status::Running));
        assert!(Status::Running.can_transition_to(Status::Stopped));

        assert!(!Status::Creating.can_transition_to(Status::Running));
        assert!(!Status::Stopped.can_transition_to(Status::Running));
    }

    #[test]
    fn test_state_transition() {
        let mut state = State::new("test".to_string(), PathBuf::from("/bundle"));

        assert_eq!(state.status, Status::Creating);
        assert!(state.transition_to(Status::Created).is_ok());
        assert_eq!(state.status, Status::Created);
        assert!(state.transition_to(Status::Running).is_ok());
        assert_eq!(state.status, Status::Running);
    }

    #[test]
    fn test_invalid_transition() {
        let mut state = State::new("test".to_string(), PathBuf::from("/bundle"));
        assert!(state.transition_to(Status::Running).is_err());
    }

    #[test]
    fn test_state_serialization() {
        let state = State::new("test-container".to_string(), PathBuf::from("/var/run/test"));

        let json = state.to_json().unwrap();
        assert!(json.contains("test-container"));
        assert!(json.contains("creating"));
    }

    #[test]
    fn test_container_state_lifecycle() {
        let mut state = ContainerState::new(
            "test".to_string(),
            PathBuf::from("/bundle"),
            PathBuf::from("/rootfs"),
        );

        assert_eq!(state.status(), Status::Creating);
        assert!(state.mark_created().is_ok());
        assert_eq!(state.status(), Status::Created);
        assert!(state.mark_started(1234).is_ok());
        assert_eq!(state.status(), Status::Running);
        assert!(state.started.is_some());
        assert!(state.mark_stopped(0).is_ok());
        assert_eq!(state.status(), Status::Stopped);
        assert!(state.finished.is_some());
        assert_eq!(state.exit_code, Some(0));
    }

    #[test]
    fn test_status_from_str() {
        assert_eq!("creating".parse::<Status>().unwrap(), Status::Creating);
        assert_eq!("RUNNING".parse::<Status>().unwrap(), Status::Running);
        assert!("invalid".parse::<Status>().is_err());
    }

    #[test]
    fn test_status_display() {
        assert_eq!(Status::Creating.to_string(), "creating");
        assert_eq!(Status::Created.to_string(), "created");
        assert_eq!(Status::Running.to_string(), "running");
        assert_eq!(Status::Stopped.to_string(), "stopped");
    }

    #[test]
    fn test_status_helper_methods() {
        assert!(!Status::Creating.is_running());
        assert!(Status::Running.is_running());

        assert!(!Status::Creating.can_start());
        assert!(Status::Created.can_start());
        assert!(!Status::Running.can_start());

        assert!(!Status::Creating.can_kill());
        assert!(Status::Created.can_kill());
        assert!(Status::Running.can_kill());
        assert!(!Status::Stopped.can_kill());

        assert!(!Status::Creating.can_delete());
        assert!(!Status::Running.can_delete());
        assert!(Status::Stopped.can_delete());
    }

    #[test]
    fn test_status_valid_transitions() {
        assert_eq!(
            Status::Creating.valid_transitions(),
            vec!["created", "stopped"]
        );
        assert_eq!(
            Status::Created.valid_transitions(),
            vec!["running", "stopped"]
        );
        assert_eq!(Status::Running.valid_transitions(), vec!["stopped"]);
        assert!(Status::Stopped.valid_transitions().is_empty());
    }

    #[test]
    fn test_state_pid_operations() {
        let mut state = State::new("test".to_string(), PathBuf::from("/bundle"));
        assert!(state.pid.is_none());

        state.set_pid(1234);
        assert_eq!(state.pid, Some(1234));

        state.clear_pid();
        assert!(state.pid.is_none());
    }

    #[test]
    fn test_state_with_generated_id() {
        let state = State::with_generated_id(PathBuf::from("/bundle"));
        assert!(!state.id.is_empty());
        // UUID v4 format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
        assert_eq!(state.id.len(), 36);
        assert!(state.id.contains('-'));
    }

    #[test]
    fn test_state_annotations() {
        let mut state = State::new("test".to_string(), PathBuf::from("/bundle"));
        assert!(state.annotations.is_empty());

        state
            .annotations
            .insert("key1".to_string(), "value1".to_string());
        state
            .annotations
            .insert("key2".to_string(), "value2".to_string());

        assert_eq!(state.annotations.len(), 2);
        assert_eq!(state.annotations.get("key1"), Some(&"value1".to_string()));
    }

    #[test]
    fn test_state_file_operations() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");

        let state = State::new("test-container".to_string(), PathBuf::from("/bundle"));
        state.save(&state_path).unwrap();

        assert!(state_path.exists());

        let loaded = State::load(&state_path).unwrap();
        assert_eq!(loaded.id, "test-container");
        assert_eq!(loaded.status, Status::Creating);
    }

    #[test]
    fn test_container_state_file_operations() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("container_state.json");

        let mut state = ContainerState::new(
            "test".to_string(),
            PathBuf::from("/bundle"),
            PathBuf::from("/rootfs"),
        );
        state.name = Some("my-container".to_string());
        state.image = Some("alpine:latest".to_string());

        state.save(&state_path).unwrap();
        assert!(state_path.exists());

        let loaded = ContainerState::load(&state_path).unwrap();
        assert_eq!(loaded.id(), "test");
        assert_eq!(loaded.name, Some("my-container".to_string()));
        assert_eq!(loaded.image, Some("alpine:latest".to_string()));
    }

    #[test]
    fn test_container_state_accessors() {
        let state = ContainerState::new(
            "test-id".to_string(),
            PathBuf::from("/path/to/bundle"),
            PathBuf::from("/path/to/rootfs"),
        );

        assert_eq!(state.id(), "test-id");
        assert_eq!(state.status(), Status::Creating);
        assert_eq!(state.bundle(), Path::new("/path/to/bundle"));
        assert_eq!(state.rootfs, PathBuf::from("/path/to/rootfs"));
    }

    #[test]
    fn test_container_state_timestamps() {
        let mut state = ContainerState::new(
            "test".to_string(),
            PathBuf::from("/bundle"),
            PathBuf::from("/rootfs"),
        );

        // Created timestamp is set on construction.
        assert!(state.created <= chrono::Utc::now());

        // Started and finished are initially None.
        assert!(state.started.is_none());
        assert!(state.finished.is_none());

        state.mark_created().unwrap();
        state.mark_started(1234).unwrap();
        assert!(state.started.is_some());
        assert!(state.started.unwrap() <= chrono::Utc::now());

        state.mark_stopped(0).unwrap();
        assert!(state.finished.is_some());
        assert!(state.finished.unwrap() >= state.started.unwrap());
    }

    #[test]
    fn test_container_state_nonzero_exit_code() {
        let mut state = ContainerState::new(
            "test".to_string(),
            PathBuf::from("/bundle"),
            PathBuf::from("/rootfs"),
        );

        state.mark_created().unwrap();
        state.mark_started(1234).unwrap();
        state.mark_stopped(137).unwrap(); // Killed by signal 9

        assert_eq!(state.exit_code, Some(137));
    }

    #[test]
    fn test_state_store_new() {
        let dir = tempfile::tempdir().unwrap();
        let store = StateStore::new(dir.path()).unwrap();
        assert!(dir.path().exists());
        drop(store);
    }

    #[test]
    fn test_state_store_save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let store = StateStore::new(dir.path()).unwrap();

        let state = ContainerState::new(
            "container-1".to_string(),
            PathBuf::from("/bundle"),
            PathBuf::from("/rootfs"),
        );

        store.save(&state).unwrap();
        assert!(store.exists("container-1"));

        let loaded = store.load("container-1").unwrap();
        assert_eq!(loaded.id(), "container-1");
    }

    #[test]
    fn test_state_store_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let store = StateStore::new(dir.path()).unwrap();

        let result = store.load("nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn test_state_store_delete() {
        let dir = tempfile::tempdir().unwrap();
        let store = StateStore::new(dir.path()).unwrap();

        let state = ContainerState::new(
            "to-delete".to_string(),
            PathBuf::from("/bundle"),
            PathBuf::from("/rootfs"),
        );

        store.save(&state).unwrap();
        assert!(store.exists("to-delete"));

        store.delete("to-delete").unwrap();
        assert!(!store.exists("to-delete"));
    }

    #[test]
    fn test_state_store_delete_nonexistent() {
        let dir = tempfile::tempdir().unwrap();
        let store = StateStore::new(dir.path()).unwrap();

        // Should not error when deleting non-existent container.
        let result = store.delete("nonexistent");
        assert!(result.is_ok());
    }

    #[test]
    fn test_state_store_list() {
        let dir = tempfile::tempdir().unwrap();
        let store = StateStore::new(dir.path()).unwrap();

        // Initially empty.
        assert!(store.list().unwrap().is_empty());

        // Add some containers.
        for i in 1..=3 {
            let state = ContainerState::new(
                format!("container-{i}"),
                PathBuf::from("/bundle"),
                PathBuf::from("/rootfs"),
            );
            store.save(&state).unwrap();
        }

        let ids = store.list().unwrap();
        assert_eq!(ids.len(), 3);
        assert!(ids.contains(&"container-1".to_string()));
        assert!(ids.contains(&"container-2".to_string()));
        assert!(ids.contains(&"container-3".to_string()));
    }

    #[test]
    fn test_state_store_list_states() {
        let dir = tempfile::tempdir().unwrap();
        let store = StateStore::new(dir.path()).unwrap();

        for i in 1..=2 {
            let mut state = ContainerState::new(
                format!("container-{i}"),
                PathBuf::from("/bundle"),
                PathBuf::from("/rootfs"),
            );
            state.name = Some(format!("name-{i}"));
            store.save(&state).unwrap();
        }

        let states = store.list_states().unwrap();
        assert_eq!(states.len(), 2);
    }

    #[test]
    fn test_state_store_update() {
        let dir = tempfile::tempdir().unwrap();
        let store = StateStore::new(dir.path()).unwrap();

        let mut state = ContainerState::new(
            "updatable".to_string(),
            PathBuf::from("/bundle"),
            PathBuf::from("/rootfs"),
        );

        store.save(&state).unwrap();

        // Update the state.
        state.mark_created().unwrap();
        state.mark_started(9999).unwrap();
        store.save(&state).unwrap();

        let loaded = store.load("updatable").unwrap();
        assert_eq!(loaded.status(), Status::Running);
        assert_eq!(loaded.oci_state.pid, Some(9999));
    }

    #[test]
    fn test_state_json_roundtrip() {
        let mut state = State::new("roundtrip-test".to_string(), PathBuf::from("/bundle"));
        state.pid = Some(12345);
        state
            .annotations
            .insert("test.key".to_string(), "test.value".to_string());

        let json = state.to_json().unwrap();
        let parsed: State = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.id, state.id);
        assert_eq!(parsed.pid, state.pid);
        assert_eq!(parsed.annotations, state.annotations);
    }

    #[test]
    fn test_transition_creating_to_stopped_on_error() {
        let mut state = State::new("test".to_string(), PathBuf::from("/bundle"));
        // Should be able to go directly to stopped on error during creation.
        assert!(state.transition_to(Status::Stopped).is_ok());
        assert_eq!(state.status, Status::Stopped);
    }

    #[test]
    fn test_transition_created_to_stopped_without_running() {
        let mut state = State::new("test".to_string(), PathBuf::from("/bundle"));
        state.transition_to(Status::Created).unwrap();
        // Can be deleted without ever running.
        assert!(state.transition_to(Status::Stopped).is_ok());
        assert_eq!(state.status, Status::Stopped);
    }
}
