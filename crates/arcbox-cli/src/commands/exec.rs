//! Exec command implementation.

use arcbox_cli::client::{self, ExecCreateRequest, ExecCreateResponse};
use anyhow::Result;
use clap::Args;

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

    let create_response: ExecCreateResponse = daemon.post(&create_path, Some(&create_request)).await?;
    let exec_id = create_response.id;

    // Start exec instance
    let start_path = format!("/v1.43/exec/{}/start", exec_id);
    let start_request = ExecStartRequest {
        detach: args.detach,
        tty: args.tty,
    };

    if args.detach {
        // Detached mode: just start and return
        daemon.post_empty(&start_path, Some(&start_request)).await?;
        println!("{}", exec_id);
    } else {
        // Attached mode: start and get output
        // TODO: Implement proper streaming for interactive mode
        if args.interactive || args.tty {
            tracing::warn!("Interactive/TTY exec mode not fully implemented yet");
        }

        // For now, use post_raw which returns the response body
        let output = daemon.post_raw(&start_path, Some(&start_request)).await?;

        // Print output
        if !output.is_empty() {
            if let Ok(s) = std::str::from_utf8(&output) {
                print!("{}", s);
            }
        }

        // Get exec inspect to get exit code
        let inspect_path = format!("/v1.43/exec/{}/json", exec_id);
        if let Ok(inspect) = daemon.get::<ExecInspect>(&inspect_path).await {
            if inspect.exit_code != 0 {
                std::process::exit(inspect.exit_code);
            }
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
    running: bool,
}
