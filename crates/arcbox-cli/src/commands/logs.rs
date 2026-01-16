//! Logs command implementation.

use anyhow::Result;
use arcbox_cli::client;
use clap::Args;
use tokio_util::sync::CancellationToken;

/// Arguments for the logs command.
#[derive(Args)]
pub struct LogsArgs {
    /// Container name or ID
    pub container: String,

    /// Follow log output
    #[arg(short, long)]
    pub follow: bool,

    /// Show timestamps
    #[arg(short, long)]
    pub timestamps: bool,

    /// Number of lines to show from the end
    #[arg(long, default_value = "all")]
    pub tail: String,

    /// Show logs since timestamp (e.g., 2024-01-01T00:00:00Z or relative like 10m)
    #[arg(long)]
    pub since: Option<String>,

    /// Show logs before timestamp
    #[arg(long)]
    pub until: Option<String>,

    /// Show extra details
    #[arg(long)]
    pub details: bool,
}

/// Executes the logs command.
pub async fn execute(args: LogsArgs) -> Result<()> {
    let daemon = client::get_client().await?;

    // Build query parameters
    let mut params = vec![
        ("stdout".to_string(), "true".to_string()),
        ("stderr".to_string(), "true".to_string()),
    ];

    if args.follow {
        params.push(("follow".to_string(), "true".to_string()));
    }

    if args.timestamps {
        params.push(("timestamps".to_string(), "true".to_string()));
    }

    if args.tail != "all" {
        params.push(("tail".to_string(), args.tail.clone()));
    }

    if let Some(ref since) = args.since {
        params.push(("since".to_string(), since.clone()));
    }

    if let Some(ref until) = args.until {
        params.push(("until".to_string(), until.clone()));
    }

    if args.details {
        params.push(("details".to_string(), "true".to_string()));
    }

    let query = params
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join("&");

    let path = format!("/v1.43/containers/{}/logs?{}", args.container, query);

    if args.follow {
        // Streaming mode with Ctrl+C handling
        let cancel_token = CancellationToken::new();
        let cancel_clone = cancel_token.clone();

        // Setup Ctrl+C handler
        let ctrl_c_task = tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                tracing::debug!("Received Ctrl+C, cancelling log stream");
                cancel_clone.cancel();
            }
        });

        // Stream logs with cancellation support
        let result = daemon
            .stream_logs_with_cancel(&path, &mut print_log_frame, cancel_token)
            .await;

        // Abort the Ctrl+C handler task
        ctrl_c_task.abort();

        result?;
    } else {
        // Non-streaming mode: get all logs at once
        let logs = daemon.get_raw(&path).await?;
        print_logs(&logs);
    }

    Ok(())
}

/// Prints container logs, handling Docker's multiplexed stream format.
fn print_logs(data: &[u8]) {
    // Docker log format: [stream_type (1 byte)][padding (3 bytes)][size (4 bytes)][data]
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

        let content = &data[offset + 8..end];
        if let Ok(s) = std::str::from_utf8(content) {
            print!("{}", s);
        }

        offset = end;
    }

    // If not in Docker format, print as-is
    if offset == 0 && !data.is_empty() {
        if let Ok(s) = std::str::from_utf8(data) {
            print!("{}", s);
        }
    }
}

/// Callback for processing log frames.
fn print_log_frame(data: &[u8]) {
    if let Ok(s) = std::str::from_utf8(data) {
        print!("{}", s);
    }
}
