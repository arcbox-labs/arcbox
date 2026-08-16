//! Exec channel: the guest vsock port the agent serves exec/run sessions
//! and control commands on, plus the readiness dial-out port.
//!
//! ## Frame format
//!
//! Every message (in both directions) is:
//!
//! ```text
//! [u8: msg_type][u32 LE: payload_len][payload_len bytes: payload]
//! ```
//!
//! | Type | Direction   | Payload                                    |
//! |------|-------------|--------------------------------------------|
//! | 0x01 | Host→Agent  | JSON-encoded [`StartCommand`]              |
//! | 0x02 | Host→Agent  | raw stdin bytes                            |
//! | 0x03 | Host→Agent  | `[u16 LE width][u16 LE height]`            |
//! | 0x04 | Host→Agent  | empty — signals stdin EOF                  |
//! | 0x05 | Host→Agent  | `[i64 LE secs][u32 LE nanos]` — clock sync |
//! | 0x06 | Host→Agent  | JSON `NetReconfigCommand` — re-address eth0 |
//! | 0x07 | Host→Agent  | `[i32 LE signal]` — deliver to workload    |
//! | 0x08 | Host→Agent  | JSON [`WaitPortReq`] — wait for a listener |
//! | 0x10 | Agent→Host  | raw stdout bytes                           |
//! | 0x11 | Agent→Host  | raw stderr bytes                           |
//! | 0x12 | Agent→Host  | `[i32 LE code][i32 LE signal]` (signal 0 = normal exit; old agents send only the 4-byte code). Net-reconfig replies append six `u32 LE` micros. Readers key on payload length. |
//!
//! Agents ignore frame types they do not know, so a new host→agent opcode
//! is a silent no-op against an agent from before it.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Host-side port the guest agent dials once it is fully serving.
///
/// Firecracker hybrid vsock forwards a guest-initiated connect to host port
/// `P` onto the host Unix socket at `{uds_path}_{P}`, so a pre-bound
/// listener's `accept()` IS the "vm-agent is up" event — no connect
/// polling involved.
pub const READY_PORT: u32 = 51;

/// Guest-side vsock port the agent listens on (exec channel).
pub const AGENT_PORT: u32 = 52;

/// Start a session. Payload: JSON [`StartCommand`].
pub const MSG_START: u8 = 0x01;
/// Raw stdin bytes for the session's process.
pub const MSG_STDIN: u8 = 0x02;
/// Resize the session's pseudo-TTY. Payload: `[u16 LE width][u16 LE height]`.
pub const MSG_RESIZE: u8 = 0x03;
/// Signal EOF on the process's stdin. Empty payload.
pub const MSG_EOF: u8 = 0x04;
/// Synchronise the guest clock to the host (after snapshot restore, and as
/// the cold-boot agent-readiness gate).
/// Payload: `[i64 LE unix_seconds][u32 LE nanos]` (12 bytes).
pub const MSG_CLOCK_SYNC: u8 = 0x05;
/// Re-address the guest network after a fresh-network snapshot restore.
/// Payload: JSON [`NetReconfigCommand`](crate::boot::NetReconfigCommand).
pub const MSG_NET_RECONFIG: u8 = 0x06;
/// Deliver a POSIX signal to the workload's process group.
/// Payload: `[i32 LE signal]` (4 bytes).
pub const MSG_SIGNAL: u8 = 0x07;
/// Wait until the guest's TCP listen table has a listener on a port.
/// Payload: JSON [`WaitPortReq`]; answered with [`MSG_EXIT`] carrying `0`
/// (listening) or `1` (deadline elapsed).
pub const MSG_WAIT_PORT: u8 = 0x08;

/// Raw stdout bytes from the session's process (the merged PTY stream for
/// `tty` sessions).
pub const MSG_STDOUT: u8 = 0x10;
/// Raw stderr bytes from the session's process (never sent for `tty`
/// sessions).
pub const MSG_STDERR: u8 = 0x11;
/// The process terminated, or a control command completed.
/// Payload: `[i32 LE code][i32 LE signal]`; see the module table for the
/// legacy 4-byte form and the net-reconfig timing suffix.
pub const MSG_EXIT: u8 = 0x12;

/// Maximum allowed frame payload size (16 MiB) on every channel.
pub const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;

/// Parameters forwarded to the guest agent as the session-start frame.
///
/// The host always serializes every field; the defaults exist for the
/// decoder, so an agent reads a start frame from any host generation.
#[derive(Debug, Serialize, Deserialize)]
pub struct StartCommand {
    /// Program and arguments (`argv`), never empty.
    pub cmd: Vec<String>,
    /// Environment for the process, replacing the agent's own.
    #[serde(default)]
    pub env: HashMap<String, String>,
    /// Working directory; empty leaves the agent's own cwd in place.
    #[serde(default)]
    pub working_dir: String,
    /// Docker-style user spec (`uid`, `uid:gid`, `name`, `name:group`)
    /// resolved against the sandbox rootfs; empty runs as the agent's own
    /// user (root inside the microVM).
    #[serde(default)]
    pub user: String,
    /// Allocate a pseudo-TTY and merge stdout/stderr into it.
    #[serde(default)]
    pub tty: bool,
    /// Initial PTY width in columns.
    #[serde(default = "default_tty_width")]
    pub tty_width: u16,
    /// Initial PTY height in rows.
    #[serde(default = "default_tty_height")]
    pub tty_height: u16,
    /// Kill the process after this many seconds; `0` means no timeout.
    #[serde(default)]
    pub timeout_seconds: u32,
}

const fn default_tty_width() -> u16 {
    80
}

const fn default_tty_height() -> u16 {
    24
}

/// [`MSG_WAIT_PORT`] payload.
#[derive(Debug, Serialize, Deserialize)]
pub struct WaitPortReq {
    /// TCP port a workload is expected to listen on.
    pub port: u16,
    /// Give up after this long (0 = check once and answer immediately).
    pub timeout_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_command_decodes_with_only_cmd() {
        // Old hosts (inside restored snapshots the roles invert: a new host
        // talks to an old agent, but the decoder tolerance is the same
        // contract) may omit every field but `cmd`.
        let cmd: StartCommand = serde_json::from_str(r#"{"cmd":["sh"]}"#).unwrap();
        assert_eq!(cmd.cmd, ["sh"]);
        assert!(cmd.env.is_empty());
        assert_eq!(cmd.working_dir, "");
        assert_eq!(cmd.user, "");
        assert!(!cmd.tty);
        assert_eq!((cmd.tty_width, cmd.tty_height), (80, 24));
        assert_eq!(cmd.timeout_seconds, 0);
    }

    #[test]
    fn start_command_round_trips_every_field() {
        let cmd = StartCommand {
            cmd: vec!["env".into()],
            env: HashMap::from([("K".to_owned(), "v".to_owned())]),
            working_dir: "/w".into(),
            user: "1000:1000".into(),
            tty: true,
            tty_width: 120,
            tty_height: 40,
            timeout_seconds: 7,
        };
        let json = serde_json::to_string(&cmd).unwrap();
        let back: StartCommand = serde_json::from_str(&json).unwrap();
        assert_eq!(back.cmd, cmd.cmd);
        assert_eq!(back.env, cmd.env);
        assert_eq!(back.working_dir, cmd.working_dir);
        assert_eq!(back.user, cmd.user);
        assert_eq!(back.tty, cmd.tty);
        assert_eq!((back.tty_width, back.tty_height), (120, 40));
        assert_eq!(back.timeout_seconds, 7);
    }
}
