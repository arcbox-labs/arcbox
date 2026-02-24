//! Create command implementation.

use anyhow::Result;
use arcbox_cli::client::{
    self, CreateContainerRequest, CreateContainerResponse, HostConfig, PortBinding,
};
use clap::Args;
use std::collections::HashMap;

/// Arguments for the create command.
#[derive(Args)]
pub struct CreateArgs {
    /// Image to create from
    pub image: String,

    /// Command to execute
    #[arg(trailing_var_arg = true)]
    pub command: Vec<String>,

    /// Assign a name to the container
    #[arg(long)]
    pub name: Option<String>,

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

/// Executes the create command.
pub async fn execute(args: CreateArgs) -> Result<()> {
    let daemon = client::get_client().await?;

    let host_config = build_host_config(&args);
    let request = CreateContainerRequest {
        image: args.image.clone(),
        cmd: args.command.clone(),
        env: args.env.clone(),
        working_dir: args.workdir.clone(),
        tty: args.tty,
        open_stdin: args.interactive,
        attach_stdin: false,
        attach_stdout: false,
        attach_stderr: false,
        host_config: Some(host_config),
        ..Default::default()
    };

    let name_param = args
        .name
        .as_ref()
        .map(|n| format!("?name={}", n))
        .unwrap_or_default();
    let path = format!("/v1.43/containers/create{}", name_param);
    let response: CreateContainerResponse = daemon.post(&path, Some(&request)).await?;

    for warning in &response.warnings {
        eprintln!("WARNING: {}", warning);
    }

    println!("{}", response.id);
    Ok(())
}

fn build_host_config(args: &CreateArgs) -> HostConfig {
    let mut host_config = HostConfig {
        binds: args.volume.clone(),
        auto_remove: false,
        ..Default::default()
    };

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

fn parse_port_mapping(s: &str) -> Option<(u16, u16)> {
    let parts: Vec<&str> = s.split(':').collect();
    match parts.len() {
        2 => {
            let host_port = parts[0].parse().ok()?;
            let container_port = parts[1].parse().ok()?;
            Some((host_port, container_port))
        }
        3 => {
            let host_port = parts[1].parse().ok()?;
            let container_port = parts[2].parse().ok()?;
            Some((host_port, container_port))
        }
        _ => None,
    }
}
