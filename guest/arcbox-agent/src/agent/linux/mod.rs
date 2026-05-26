//! Linux implementation of the Guest Agent.
//!
//! Listens on vsock and dispatches RPC requests on the Linux guest.
//! Non-Linux platforms use the stub in `super::stub`.

mod agent;
mod btrfs;
mod cmdline;
mod disk;
mod kubernetes;
mod probe;
mod proxy;
mod rpc;
mod runtime;
mod sandbox;
mod system_info;
mod vsock;

pub use agent::Agent;
