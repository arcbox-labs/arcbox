//! Run command implementation.

use anyhow::Result;
use arcbox_cli::client::{
    self, ContainerWaitResponse, CreateContainerRequest, CreateContainerResponse, HostConfig,
    PortBinding,
};
use arcbox_cli::terminal::InteractiveSession;
use clap::Args;
use std::collections::HashMap;

/// Arguments for the run command.
#[derive(Args)]
pub struct RunArgs {
    /// Image to run
    pub image: String,

    /// Command to execute
    #[arg(trailing_var_arg = true)]
    pub command: Vec<String>,

    /// Container name
    #[arg(long)]
    pub name: Option<String>,

    /// Run in detached mode
    #[arg(short, long)]
    pub detach: bool,

    /// Remove container when it exits
    #[arg(long)]
    pub rm: bool,

    /// Allocate a pseudo-TTY
    #[arg(short, long)]
    pub tty: bool,

    /// Keep STDIN open
    #[arg(short, long)]
    pub interactive: bool,

    /// Environment variables
    #[arg(short, long)]
    pub env: Vec<String>,

    /// Volume mounts
    #[arg(short, long)]
    pub volume: Vec<String>,

    /// Port mappings
    #[arg(short, long)]
    pub publish: Vec<String>,

    /// Working directory
    #[arg(short, long)]
    pub workdir: Option<String>,
}

/// Executes the run command.
pub async fn execute(args: RunArgs) -> Result<()> {
    let daemon = client::get_client().await?;

    // Build host config
    let host_config = build_host_config(&args);

    // Build create container request
    let request = CreateContainerRequest {
        image: args.image.clone(),
        cmd: args.command.clone(),
        env: args.env.clone(),
        working_dir: args.workdir.clone(),
        tty: args.tty,
        open_stdin: args.interactive,
        attach_stdin: args.interactive && !args.detach,
        attach_stdout: !args.detach,
        attach_stderr: !args.detach,
        host_config: Some(host_config),
        ..Default::default()
    };

    // Create container
    let name_param = args
        .name
        .as_ref()
        .map(|n| format!("?name={}", n))
        .unwrap_or_default();
    let path = format!("/v1.43/containers/create{}", name_param);

    let response: CreateContainerResponse = daemon.post(&path, Some(&request)).await?;
    let container_id = response.id;

    // Print any warnings
    for warning in &response.warnings {
        eprintln!("WARNING: {}", warning);
    }

    // Start container
    let start_path = format!("/v1.43/containers/{}/start", container_id);
    daemon.post_empty::<()>(&start_path, None).await?;

    if args.detach {
        // Detached mode: print container ID and exit
        println!("{}", client::short_id(&container_id));
    } else if args.tty || args.interactive {
        // Interactive/TTY mode: attach for bidirectional streaming
        let stream = daemon
            .upgrade_attach(&container_id, args.interactive, args.tty)
            .await?;
        let (reader, writer) = tokio::io::split(stream);

        // Run interactive session
        let session = InteractiveSession::new(reader, writer, args.tty);
        session.run().await?;

        // Wait for container to exit and get exit code
        let wait_path = format!("/v1.43/containers/{}/wait", container_id);
        let wait_response: ContainerWaitResponse = daemon.post(&wait_path, None::<()>).await?;

        // Remove container if --rm flag is set
        if args.rm {
            let rm_path = format!("/v1.43/containers/{}", container_id);
            let _ = daemon.delete(&rm_path).await;
        }

        // Exit with container's exit code
        if wait_response.status_code != 0 {
            std::process::exit(wait_response.status_code as i32);
        }
    } else {
        // Non-interactive foreground mode: wait for container and get logs
        let wait_path = format!("/v1.43/containers/{}/wait", container_id);
        let wait_response: ContainerWaitResponse = daemon.post(&wait_path, None::<()>).await?;

        // Get logs
        let logs_path = format!(
            "/v1.43/containers/{}/logs?stdout=true&stderr=true",
            container_id
        );
        if let Ok(logs) = daemon.get_raw(&logs_path).await {
            print_container_logs(&logs);
        }

        // Remove container if --rm flag is set
        if args.rm {
            let rm_path = format!("/v1.43/containers/{}", container_id);
            let _ = daemon.delete(&rm_path).await;
        }

        // Exit with container's exit code
        if wait_response.status_code != 0 {
            std::process::exit(wait_response.status_code as i32);
        }
    }

    Ok(())
}

/// Builds host configuration from run arguments.
fn build_host_config(args: &RunArgs) -> HostConfig {
    let mut host_config = HostConfig {
        binds: args.volume.clone(),
        auto_remove: args.rm && args.detach,
        ..Default::default()
    };

    // Parse port bindings
    if !args.publish.is_empty() {
        let mut port_bindings: HashMap<String, Vec<PortBinding>> = HashMap::new();

        for publish in &args.publish {
            if let Some((host, container)) = parse_port_mapping(publish) {
                let container_port = format!("{}/tcp", container);
                port_bindings
                    .entry(container_port)
                    .or_default()
                    .push(PortBinding {
                        host_ip: String::new(),
                        host_port: host.to_string(),
                    });
            }
        }

        if !port_bindings.is_empty() {
            host_config.port_bindings = Some(port_bindings);
        }
    }

    host_config
}

/// Parses a port mapping string (e.g., "8080:80" or "127.0.0.1:8080:80").
fn parse_port_mapping(s: &str) -> Option<(u16, u16)> {
    let parts: Vec<&str> = s.split(':').collect();
    match parts.len() {
        2 => {
            let host_port = parts[0].parse().ok()?;
            let container_port = parts[1].parse().ok()?;
            Some((host_port, container_port))
        }
        3 => {
            // ip:hostPort:containerPort
            let host_port = parts[1].parse().ok()?;
            let container_port = parts[2].parse().ok()?;
            Some((host_port, container_port))
        }
        _ => None,
    }
}

/// Prints container logs, handling Docker's multiplexed stream format.
fn print_container_logs(data: &[u8]) {
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
