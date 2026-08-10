//! `arcbox` — run isolated microVM sandboxes on the local ArcBox
//! daemon, over the Connect protocol on its Unix socket.
//!
//! ```no_run
//! use arcbox::{ArcBox, CreateOptions};
//!
//! # async fn demo() -> arcbox::Result<()> {
//! let client = ArcBox::new()?;
//! let sandbox = client.create("", CreateOptions::default()).await?;
//! println!("sandbox {} is ready", sandbox.id());
//! sandbox.kill().await?;
//! # Ok(())
//! # }
//! ```
//!
//! Public shapes are hand-written and mapped at the transport boundary;
//! generated wire code never appears in a signature. The error type
//! derives from the daemon's error registry (`errors.proto`), so
//! failures carry a machine-usable [`ErrorKind`], the registry code,
//! an actionable suggestion, and the failed operation.

mod client;
mod commands;
mod connection;
mod error;
mod sandbox;
mod types;

pub use commands::{
    Channel, Cmd, CommandHandle, CommandInfo, CommandResult, CommandState, Commands, OutputChunk,
    OutputStream, PtySize, RunOptions, Signal, Stdin, StdinStatus,
};
pub use connection::Connection;
pub use error::{Error, ErrorKind, Result};
pub use sandbox::{ArcBox, ConnectOptions, CreateOptions, ListOptions, Sandbox};
pub use types::{
    Capabilities, IdlePolicy, LifecycleUpdate, NestedVirtCapability, SandboxInfo, SandboxState,
    SandboxSummary, Update,
};
