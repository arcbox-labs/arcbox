//! `VirtIO` console device (virtio-console).
//!
//! Implements the `VirtIO` console device for serial I/O.
//!
//! Supports multiple console backends:
//! - Standard I/O (stdin/stdout)
//! - Buffer-based (for testing)
//! - PTY (pseudo-terminal) for real terminal emulation
//! - Socket-based for network console
//!
//! ## Module layout
//!
//! - `io`: `ConsoleIo` trait + in-process backends (`StdioConsole`, `BufferConsole`)
//! - `pty`: PTY backend (Unix only)
//! - `socket`: Unix-socket backend (Unix only)
//! - `device`: `VirtioConsole` device + `VirtioDevice` impl

#![allow(clippy::ptr_as_ptr)]
#![allow(clippy::borrow_as_ptr)]
#![allow(clippy::unnecessary_cast)]
#![allow(clippy::cognitive_complexity)]
#![allow(clippy::map_unwrap_or)]
#![allow(clippy::useless_vec)]
#![allow(clippy::unnecessary_wraps)]
#![allow(clippy::redundant_clone)]
#![allow(clippy::unnecessary_map_or)]
#![allow(clippy::missing_fields_in_debug)]
#![allow(clippy::needless_lifetimes)]
#![allow(clippy::needless_collect)]
#![allow(mismatched_lifetime_syntaxes)]

mod device;
mod io;
#[cfg(unix)]
mod pty;
#[cfg(unix)]
mod socket;

pub use device::{ConsoleConfig, VirtioConsole};
pub use io::{BufferConsole, ConsoleIo, StdioConsole};
#[cfg(unix)]
pub use pty::PtyConsole;
#[cfg(unix)]
pub use socket::SocketConsole;
