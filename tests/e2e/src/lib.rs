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

#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(clippy::all)]

pub mod agent;
pub mod assertions;
pub mod fixtures;
pub mod harness;
pub mod vm;

pub use agent::AgentClient;
pub use fixtures::{TestBackend, TestDistro, TestFixtures};
pub use harness::{TestConfig, TestHarness};
pub use vm::VmController;
