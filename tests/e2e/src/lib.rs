//! End-to-end integration test framework for ArcBox.
//!
//! This crate provides utilities for running end-to-end tests that exercise
//! the full ArcBox stack: daemon, VM, agent, and container runtime.
//!
//! ## Test Levels
//!
//! 1. **VM Lifecycle** - Test VM creation, startup, shutdown
//! 2. **Agent Connectivity** - Test host-guest communication via vsock
//! 3. **Image Operations** - Test image pull and layer extraction
//! 4. **Container Lifecycle** - Test container create/start/stop/remove
//! 5. **Full Workflow** - Test `arcbox run` equivalent flows

pub mod harness;
pub mod vm;
pub mod agent;
pub mod fixtures;
pub mod assertions;

pub use harness::{TestHarness, TestConfig};
pub use vm::VmController;
pub use agent::AgentClient;
pub use fixtures::TestFixtures;
