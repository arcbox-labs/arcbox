//! Machine-level command execution.
//!
//! Handles [`MessageType::MachineExecRequest`] by spawning the command in the
//! agent's own mount namespace — which for a distro machine is the machine's
//! overlay root — and streaming stdout/stderr back as
//! [`MessageType::MachineExecOutput`] frames. The final frame carries
//! `done == true` and the exit code.
//!
//! Non-interactive only: stdin is closed and `tty` requests are rejected. The
//! interactive PTY session (stdin + resize) is the planned bidi follow-up —
//! see `internal-docs/plans/machine-boot-shim.md`.

use std::process::Stdio;

use anyhow::Context;
use prost::Message;
use tokio::io::{AsyncReadExt, AsyncWrite};
use tokio::process::Command;

use crate::rpc::{ErrorResponse, MessageType, write_message};

/// Handles a machine-level exec request on the current connection.
pub(super) async fn handle_machine_exec<S>(
    stream: &mut S,
    trace_id: &str,
    payload: &[u8],
) -> anyhow::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let req = arcbox_protocol::MachineExecRequest::decode(payload)
        .context("failed to decode MachineExecRequest")?;

    if req.cmd.is_empty() {
        let err = ErrorResponse::new(400, "cmd must not be empty");
        write_message(stream, MessageType::Error, trace_id, &err.encode()).await?;
        return Ok(());
    }
    if req.tty {
        let err = ErrorResponse::new(
            400,
            "interactive (tty) machine exec is not supported yet; run without a TTY",
        );
        write_message(stream, MessageType::Error, trace_id, &err.encode()).await?;
        return Ok(());
    }

    let mut cmd = Command::new(&req.cmd[0]);
    if req.cmd.len() > 1 {
        cmd.args(&req.cmd[1..]);
    }
    if !req.working_dir.is_empty() {
        cmd.current_dir(&req.working_dir);
    }
    for (k, v) in &req.env {
        cmd.env(k, v);
    }

    if !req.user.is_empty() {
        let uid = match resolve_uid(&req.user) {
            Ok(uid) => uid,
            Err(e) => {
                let err = ErrorResponse::new(400, e.to_string());
                write_message(stream, MessageType::Error, trace_id, &err.encode()).await?;
                return Ok(());
            }
        };
        // SAFETY: `setuid` is async-signal-safe and `uid` came from the
        // passwd database (or a numeric literal) above.
        unsafe {
            cmd.pre_exec(move || {
                if libc::setuid(uid) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }

    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let err = ErrorResponse::new(500, format!("failed to spawn process: {e}"));
            write_message(stream, MessageType::Error, trace_id, &err.encode()).await?;
            return Ok(());
        }
    };

    let mut stdout = child.stdout.take().expect("stdout piped");
    let mut stderr = child.stderr.take().expect("stderr piped");

    let mut stdout_buf = [0u8; 8192];
    let mut stderr_buf = [0u8; 8192];
    let mut stdout_done = false;
    let mut stderr_done = false;

    while !stdout_done || !stderr_done {
        tokio::select! {
            res = stdout.read(&mut stdout_buf), if !stdout_done => {
                match res {
                    Ok(0) => stdout_done = true,
                    Ok(n) => {
                        write_output(stream, trace_id, "stdout", &stdout_buf[..n]).await?;
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "machine exec stdout read error");
                        stdout_done = true;
                    }
                }
            }
            res = stderr.read(&mut stderr_buf), if !stderr_done => {
                match res {
                    Ok(0) => stderr_done = true,
                    Ok(n) => {
                        write_output(stream, trace_id, "stderr", &stderr_buf[..n]).await?;
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "machine exec stderr read error");
                        stderr_done = true;
                    }
                }
            }
        }
    }

    let status = child.wait().await.context("failed to wait for child")?;
    let final_out = arcbox_protocol::MachineExecOutput {
        done: true,
        exit_code: status.code().unwrap_or(-1),
        ..Default::default()
    };
    write_message(
        stream,
        MessageType::MachineExecOutput,
        trace_id,
        &final_out.encode_to_vec(),
    )
    .await?;

    Ok(())
}

async fn write_output<S>(
    stream: &mut S,
    trace_id: &str,
    name: &str,
    data: &[u8],
) -> anyhow::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let out = arcbox_protocol::MachineExecOutput {
        stream: name.to_string(),
        data: data.to_vec(),
        ..Default::default()
    };
    write_message(
        stream,
        MessageType::MachineExecOutput,
        trace_id,
        &out.encode_to_vec(),
    )
    .await?;
    Ok(())
}

/// Resolves a username or numeric UID string to a `uid_t`.
fn resolve_uid(user: &str) -> anyhow::Result<libc::uid_t> {
    if let Ok(uid) = user.parse::<libc::uid_t>() {
        return Ok(uid);
    }
    let c_name = std::ffi::CString::new(user).context("invalid user name")?;
    // SAFETY: `c_name` is a valid nul-terminated C string; `getpwnam` returns
    // a pointer to a static passwd struct (or null).
    let pw = unsafe { libc::getpwnam(c_name.as_ptr()) };
    if pw.is_null() {
        anyhow::bail!("unknown user: {user}");
    }
    // SAFETY: `pw` is non-null and points to a valid passwd struct.
    Ok(unsafe { (*pw).pw_uid })
}
