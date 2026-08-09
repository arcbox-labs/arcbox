//! Machine-level command execution.
//!
//! Handles [`MessageType::MachineExecRequest`] by spawning the command in the
//! agent's own mount namespace — which for a distro machine is the machine's
//! overlay root.
//!
//! Two modes share the entry point:
//! - **piped** (`tty == false`): stdin closed, stdout/stderr streamed as
//!   separate [`MessageType::MachineExecOutput`] frames;
//! - **interactive** (`tty == true`): the command runs as a session leader on
//!   a PTY (primitives from `arcbox-pty`); output is a single merged stream,
//!   and the host feeds [`MessageType::MachineExecInput`] /
//!   [`MessageType::MachineExecResize`] frames on the same connection.
//!
//! Both end with a `done == true` frame carrying the exit code.

use std::process::Stdio;

use anyhow::Context;
use buffa::Message;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::process::Command;

use super::super::exec_error::spawn_error;
use crate::rpc::{ErrorResponse, MessageType, write_message};

/// Handles a machine-level exec request on the current connection.
pub(super) async fn handle_machine_exec<S>(
    stream: &mut S,
    trace_id: &str,
    payload: &[u8],
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let req = arcbox_connect::v1::MachineExecRequest::decode_from_slice(payload)
        .context("failed to decode MachineExecRequest")?;

    if req.cmd.is_empty() {
        let err = ErrorResponse::new(400, "cmd must not be empty");
        write_message(stream, MessageType::Error, trace_id, &err.encode()).await?;
        return Ok(());
    }
    if req.tty {
        return tty_session(stream, trace_id, &req).await;
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
        let (uid, gid) = match resolve_user(&req.user) {
            Ok(ids) => ids,
            Err(e) => {
                let err = ErrorResponse::new(400, e.to_string());
                write_message(stream, MessageType::Error, trace_id, &err.encode()).await?;
                return Ok(());
            }
        };
        // Full privilege drop, in the one order that works: supplementary
        // groups, then gid, then uid — the reverse would lose the right to
        // change groups before using it (setuid alone would leave the child
        // in root's group).
        // SAFETY: async-signal-safe syscalls; the ids came from the passwd
        // database (or a numeric literal) above.
        unsafe {
            cmd.pre_exec(move || {
                if libc::setgroups(1, &raw const gid) != 0
                    || libc::setgid(gid) != 0
                    || libc::setuid(uid) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }

    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    // A host disconnect mid-stream aborts this handler via `?`; the dropped
    // child must not keep running detached in the machine.
    cmd.kill_on_drop(true);

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let err = spawn_error(&req.cmd[0], e);
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
    let final_out = arcbox_connect::v1::MachineExecOutput {
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
    let out = arcbox_connect::v1::MachineExecOutput {
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

/// Interactive PTY session on the current connection.
///
/// The command runs as a session leader with the PTY slave as its
/// controlling terminal (child setup and privilege drop live in
/// `arcbox-pty`). Output is pumped from the PTY master on a blocking thread
/// (bounded channel); input/resize frames are read from the connection in
/// the same select loop, so a single writer owns the stream.
async fn tty_session<S>(
    stream: &mut S,
    trace_id: &str,
    req: &arcbox_connect::v1::MachineExecRequest,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;

    let run_as = if req.user.is_empty() {
        None
    } else {
        match arcbox_pty::resolve_user(&req.user) {
            Ok(r) => Some(r),
            Err(e) => {
                let err = ErrorResponse::new(400, e.to_string());
                write_message(stream, MessageType::Error, trace_id, &err.encode()).await?;
                return Ok(());
            }
        }
    };

    let size = req.tty_size.as_option().map(|s| arcbox_pty::WinSize {
        cols: u16::try_from(s.width).unwrap_or(80),
        rows: u16::try_from(s.height).unwrap_or(24),
    });
    let pty = match arcbox_pty::openpty_sized(size) {
        Ok(pty) => pty,
        Err(e) => {
            let err = ErrorResponse::new(500, format!("openpty: {e}"));
            write_message(stream, MessageType::Error, trace_id, &err.encode()).await?;
            return Ok(());
        }
    };

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
    // The pre_exec closure dup2s the slave over stdin/stdout/stderr, so the
    // Command-level stdio configuration is irrelevant (pre_exec runs after
    // it); null keeps no stray pipes open.
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::null());
    cmd.kill_on_drop(true);
    // SAFETY: the closure runs post-fork pre-exec and only makes
    // async-signal-safe calls; the slave stays open in the parent until
    // after spawn.
    unsafe {
        cmd.pre_exec(arcbox_pty::child_terminal_setup(
            pty.slave.as_raw_fd(),
            run_as,
        ));
    }
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let err = spawn_error(&req.cmd[0], e);
            write_message(stream, MessageType::Error, trace_id, &err.encode()).await?;
            return Ok(());
        }
    };
    // The child holds its own slave via the controlling-terminal dup2s; the
    // parent copy must close so master read hits EOF when the child exits.
    drop(pty.slave);

    let mut master_write = std::fs::File::from(pty.master.try_clone()?);
    let master_read = std::fs::File::from(pty.master.try_clone()?);
    let master_resize = pty.master;

    // Output pump: blocking PTY reads on a dedicated thread, handed to the
    // session loop over a bounded channel (backpressure caps buffering).
    let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(16);
    let reader = tokio::task::spawn_blocking(move || {
        let mut master = master_read;
        let mut buf = [0u8; 8192];
        loop {
            match master.read(&mut buf) {
                // EIO is the normal PTY EOF once the child exits.
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if out_tx.blocking_send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
            }
        }
    });

    let (mut conn_rd, mut conn_wr) = tokio::io::split(stream);
    let mut host_gone = false;
    loop {
        tokio::select! {
            chunk = out_rx.recv() => match chunk {
                Some(data) => {
                    let out = arcbox_connect::v1::MachineExecOutput {
                        stream: "stdout".to_string(),
                        data,
                        ..Default::default()
                    };
                    if write_message(
                        &mut conn_wr,
                        MessageType::MachineExecOutput,
                        trace_id,
                        &out.encode_to_vec(),
                    )
                    .await
                    .is_err()
                    {
                        host_gone = true;
                        break;
                    }
                }
                // Master EOF: the child exited and released the slave.
                None => break,
            },
            frame = crate::rpc::read_message(&mut conn_rd) => match frame {
                Ok((MessageType::MachineExecInput, _, payload)) => {
                    // Empty payload signals stdin EOF; an interactive shell
                    // ends via in-band ^D, so there is nothing to forward.
                    if !payload.is_empty() {
                        // Keystroke-sized writes into the kernel PTY buffer;
                        // blocking only if the child stops draining input.
                        if let Err(e) = master_write.write_all(&payload) {
                            tracing::warn!(error = %e, "pty stdin write failed");
                        }
                    }
                }
                Ok((MessageType::MachineExecResize, _, payload)) => {
                    if let Ok(ts) = arcbox_connect::v1::TerminalSize::decode_from_slice(&payload) {
                        let _ = arcbox_pty::resize(
                            &master_resize,
                            arcbox_pty::WinSize {
                                cols: u16::try_from(ts.width).unwrap_or(80),
                                rows: u16::try_from(ts.height).unwrap_or(24),
                            },
                        );
                    }
                }
                Ok((other, _, _)) => {
                    tracing::warn!(?other, "unexpected frame during machine exec session");
                }
                Err(_) => {
                    host_gone = true;
                    break;
                }
            },
        }
    }

    if host_gone {
        // Kill the whole session (the child is its leader after setsid), not
        // just the direct child — an orphaned interactive shell must not
        // keep its descendants running.
        if let Some(pid) = child.id() {
            // SAFETY: plain kill on a process group we created.
            unsafe {
                libc::kill(-(pid as libc::pid_t), libc::SIGKILL);
            }
        }
    }

    let exit_code = match child.wait().await {
        Ok(status) => status.code().unwrap_or(-1),
        Err(e) => {
            tracing::warn!(error = %e, "failed to wait for exec child");
            -1
        }
    };
    let _ = reader.await;

    if !host_gone {
        let final_out = arcbox_connect::v1::MachineExecOutput {
            done: true,
            exit_code,
            ..Default::default()
        };
        let _ = write_message(
            &mut conn_wr,
            MessageType::MachineExecOutput,
            trace_id,
            &final_out.encode_to_vec(),
        )
        .await;
    }

    Ok(())
}

/// Resolves a username or numeric UID string to `(uid, gid)`.
///
/// A numeric string is taken as a UID with GID equal to it.
fn resolve_user(user: &str) -> anyhow::Result<(libc::uid_t, libc::gid_t)> {
    if let Ok(uid) = user.parse::<libc::uid_t>() {
        return Ok((uid, uid));
    }
    let c_name = std::ffi::CString::new(user).context("invalid user name")?;
    // SAFETY: `c_name` is a valid nul-terminated C string; `getpwnam` returns
    // a pointer to a static passwd struct (or null).
    let pw = unsafe { libc::getpwnam(c_name.as_ptr()) };
    if pw.is_null() {
        anyhow::bail!("unknown user: {user}");
    }
    // SAFETY: `pw` is non-null and points to a valid passwd struct.
    Ok(unsafe { ((*pw).pw_uid, (*pw).pw_gid) })
}
