//! Exec command implementation.

use anyhow::Result;
use arcbox_cli::client::{self, DaemonClient, ExecCreateRequest, ExecCreateResponse};
use arcbox_cli::terminal::InteractiveSession;
use clap::Args;
use tokio::time::{Duration, sleep};

/// Arguments for the exec command.
#[derive(Args)]
pub struct ExecArgs {
    /// Container name or ID
    pub container: String,

    /// Command to execute
    #[arg(trailing_var_arg = true, required = true)]
    pub command: Vec<String>,

    /// Allocate a pseudo-TTY
    #[arg(short, long)]
    pub tty: bool,

    /// Keep STDIN open
    #[arg(short, long)]
    pub interactive: bool,

    /// Run in detached mode
    #[arg(short, long)]
    pub detach: bool,

    /// Environment variables
    #[arg(short, long)]
    pub env: Vec<String>,

    /// Working directory inside the container
    #[arg(short, long)]
    pub workdir: Option<String>,

    /// Username or UID
    #[arg(short, long)]
    pub user: Option<String>,

    /// Run in privileged mode
    #[arg(long)]
    pub privileged: bool,
}

/// Executes the exec command.
pub async fn execute(args: ExecArgs) -> Result<()> {
    let daemon = client::get_client().await?;

    // Create exec instance
    let create_path = format!("/v1.43/containers/{}/exec", args.container);
    let create_request = ExecCreateRequest {
        attach_stdin: args.interactive && !args.detach,
        attach_stdout: !args.detach,
        attach_stderr: !args.detach,
        tty: args.tty,
        cmd: args.command.clone(),
        env: args.env.clone(),
        working_dir: args.workdir.clone(),
    };

    let create_response: ExecCreateResponse =
        daemon.post(&create_path, Some(&create_request)).await?;
    let exec_id = create_response.id;

    // Start exec instance
    let start_request = ExecStartRequest {
        detach: args.detach,
        tty: args.tty,
    };
    let start_path = format!("/v1.43/exec/{}/start", exec_id);

    if args.detach {
        // Detached mode: just start and return
        daemon.post_empty(&start_path, Some(&start_request)).await?;
        println!("{}", exec_id);
    } else if args.interactive || args.tty {
        // Interactive/TTY mode: upgrade connection for bidirectional streaming
        let stream = daemon.upgrade_exec(&exec_id, Some(&start_request)).await?;
        let (reader, writer) = tokio::io::split(stream);

        // Run interactive session
        let session = InteractiveSession::new(reader, writer, args.tty);
        session.run().await?;

        // Wait for exec completion and preserve exit code.
        let inspect = wait_exec_exit(&daemon, &exec_id).await?;
        if inspect.exit_code != 0 {
            std::process::exit(inspect.exit_code);
        }
    } else {
        // Non-interactive mode uses regular HTTP response body.
        let output = daemon.post_raw(&start_path, Some(&start_request)).await?;
        let output = decode_exec_output(&output, args.tty);

        // Print output
        if !output.is_empty() {
            if let Ok(s) = std::str::from_utf8(&output) {
                print!("{}", s);
            }
        }

        // Wait for exec completion and preserve exit code.
        let inspect = wait_exec_exit(&daemon, &exec_id).await?;
        if inspect.exit_code != 0 {
            std::process::exit(inspect.exit_code);
        }
    }

    Ok(())
}

/// Exec start request.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "PascalCase")]
struct ExecStartRequest {
    detach: bool,
    tty: bool,
}

/// Exec inspect response.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ExecInspect {
    #[serde(default)]
    exit_code: i32,
    /// Whether exec is still running (required for deserialization).
    #[allow(dead_code)]
    running: bool,
}

async fn wait_exec_exit(daemon: &DaemonClient, exec_id: &str) -> Result<ExecInspect> {
    let inspect_path = format!("/v1.43/exec/{}/json", exec_id);
    let mut last = daemon.get::<ExecInspect>(&inspect_path).await?;
    if !last.running {
        return Ok(last);
    }

    for _ in 0..50 {
        sleep(Duration::from_millis(100)).await;
        last = daemon.get::<ExecInspect>(&inspect_path).await?;
        if !last.running {
            return Ok(last);
        }
    }

    Ok(last)
}

fn decode_exec_output(data: &[u8], tty: bool) -> Vec<u8> {
    if tty || data.is_empty() {
        return data.to_vec();
    }

    let mut output = Vec::with_capacity(data.len());
    let mut offset = 0;

    while offset + 8 <= data.len() {
        let size = u32::from_be_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]) as usize;

        let end = offset + 8 + size;
        if end > data.len() {
            break;
        }

        output.extend_from_slice(&data[offset + 8..end]);
        offset = end;
    }

    if offset == 0 { data.to_vec() } else { output }
}
