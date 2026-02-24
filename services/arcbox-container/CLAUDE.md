# CLAUDE.md

This file provides guidance to Claude Code when working with the arcbox-container crate.

## Overview

Container state management - handles container lifecycle, configuration, and exec instances. Does not run containers directly; delegates to guest agent via arcbox-core.

## Architecture

```
arcbox-container/src/
├── lib.rs          # Crate entry
├── config.rs       # ContainerConfig
├── state.rs        # Container, ContainerId, ContainerState
├── manager.rs      # ContainerManager
├── exec.rs         # ExecManager, ExecInstance
├── volume.rs       # VolumeManager
└── error.rs        # ContainerError
```

## Key Types

```rust
pub struct Container {
    pub id: ContainerId,
    pub name: String,
    pub image: String,
    pub machine_name: Option<String>,
    pub state: ContainerState,
    pub created: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub exit_code: Option<i32>,
    pub pid: Option<u32>,
    pub config: ContainerConfig,
}

pub enum ContainerState {
    Created,
    Starting,
    Running,
    Paused,
    Restarting,
    Exited,
    Removing,
    Dead,
}
```

## ContainerManager

```rust
impl ContainerManager {
    pub fn create(&self, config: ContainerConfig) -> Result<Container>;
    pub fn get(&self, id: &ContainerId) -> Option<Container>;
    pub fn list(&self) -> Vec<Container>;
    pub fn remove(&self, id: &ContainerId) -> Result<()>;

    // State transitions (called by arcbox-core after agent confirms)
    pub fn mark_running(&self, id: &ContainerId, pid: u32);
    pub fn mark_exited(&self, id: &ContainerId, exit_code: i32);
}
```

## ExecManager

Manages `docker exec` instances:

```rust
pub struct ExecInstance {
    pub id: ExecId,
    pub config: ExecConfig,
    pub running: bool,
    pub exit_code: Option<i32>,
    pub pid: Option<u32>,
}

impl ExecManager {
    pub fn create(&self, config: ExecConfig) -> Result<ExecId>;
    pub fn start(&self, id: &ExecId, detach: bool) -> Result<ExecResult>;
    pub fn resize(&self, id: &ExecId, width: u32, height: u32) -> Result<()>;
}
```

## Error Handling

```rust
pub enum ContainerError {
    NotFound(String),
    AlreadyExists(String),
    InvalidState(String),
    Image(String),
    Volume(String),
    Config(String),
    Runtime(String),
    Io(std::io::Error),
    LockPoisoned,
}
```

## Common Commands

```bash
cargo build -p arcbox-container
cargo test -p arcbox-container
```
