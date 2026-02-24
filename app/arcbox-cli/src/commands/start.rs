//! Start command implementation.

use anyhow::Result;
use arcbox_cli::client::{self, ContainerInspect, ContainerWaitResponse};
use arcbox_cli::terminal::InteractiveSession;
use clap::Args;

/// Arguments for the start command.
#[derive(Args)]
pub struct StartArgs {
    /// Container ID or name
    pub container: String,

    /// Attach to container
    #[arg(short, long)]
    pub attach: bool,

    /// Attach STDIN
    #[arg(short, long)]
    pub interactive: bool,
}

/// Executes the start command.
pub async fn execute(args: StartArgs) -> Result<()> {
    let daemon = client::get_client().await?;

    if args.attach {
        // Get container info to check TTY setting
        let inspect_path = format!("/v1.43/containers/{}/json", args.container);
        let inspect: ContainerInspect = daemon.get(&inspect_path).await?;
        let tty = inspect.config.tty;

        // Start container
        let start_path = format!("/v1.43/containers/{}/start", args.container);
        daemon.post_empty::<()>(&start_path, None).await?;

        // Attach for bidirectional streaming
        let stream = daemon
            .upgrade_attach(&args.container, args.interactive, tty)
            .await?;
        let (reader, writer) = tokio::io::split(stream);

        // Run interactive session
        let session = InteractiveSession::new(reader, writer, tty);
        session.run().await?;

        // Wait for container to exit and get exit code
        let wait_path = format!("/v1.43/containers/{}/wait", args.container);
        let wait_response: ContainerWaitResponse = daemon.post(&wait_path, None::<()>).await?;

        if wait_response.status_code != 0 {
            std::process::exit(wait_response.status_code as i32);
        }
    } else {
        // Just start the container
        let start_path = format!("/v1.43/containers/{}/start", args.container);
        daemon.post_empty::<()>(&start_path, None).await?;
        println!("{}", args.container);
    }

    Ok(())
}
