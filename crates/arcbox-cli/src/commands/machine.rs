//! Machine management commands.

use anyhow::{Context, Result};
use arcbox_core::machine::{MachineConfig, MachineState};
use arcbox_core::{Config, Runtime};
use clap::{Args, Subcommand};
use std::collections::HashMap;
use std::io::Write;
use std::sync::OnceLock;

/// Global runtime instance.
static RUNTIME: OnceLock<Runtime> = OnceLock::new();

/// Gets or initializes the global runtime.
fn get_runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| {
        let config = Config::load().unwrap_or_default();
        Runtime::new(config).expect("failed to initialize runtime")
    })
}

/// Machine subcommands.
#[derive(Subcommand)]
pub enum MachineCommands {
    /// Create a new machine
    Create(CreateArgs),
    /// Start a machine
    Start(StartArgs),
    /// Stop a machine
    Stop(StopArgs),
    /// Remove a machine
    #[command(alias = "rm")]
    Remove(RemoveArgs),
    /// List machines
    #[command(name = "ls", alias = "list")]
    List(ListArgs),
    /// Show machine status
    Status(StatusArgs),
    /// SSH into a machine
    Ssh(SshArgs),
    /// Execute a command in a machine
    Exec(ExecArgs),
}

#[derive(Args)]
pub struct CreateArgs {
    /// Machine name
    pub name: String,
    /// Number of CPUs
    #[arg(long, default_value = "4")]
    pub cpus: u32,
    /// Memory in MB
    #[arg(long, default_value = "4096")]
    pub memory: u64,
    /// Disk size in GB
    #[arg(long, default_value = "50")]
    pub disk: u64,
    /// Distribution (ubuntu, alpine, etc.)
    #[arg(long, default_value = "ubuntu")]
    pub distro: String,
    /// Distribution version
    #[arg(long, name = "distro-version")]
    pub distro_version: Option<String>,
    /// Directory mounts (host:guest)
    #[arg(short, long)]
    pub mount: Vec<String>,
    /// Custom kernel path (for advanced users / testing)
    #[arg(long)]
    pub kernel: Option<String>,
    /// Custom initrd/initramfs path (for advanced users / testing)
    #[arg(long)]
    pub initrd: Option<String>,
    /// Custom kernel command line (for advanced users / testing)
    #[arg(long)]
    pub cmdline: Option<String>,
}

#[derive(Args)]
pub struct StartArgs {
    /// Machine name
    pub name: String,
}

#[derive(Args)]
pub struct StopArgs {
    /// Machine name
    pub name: String,
    /// Force stop
    #[arg(short, long)]
    pub force: bool,
}

#[derive(Args)]
pub struct RemoveArgs {
    /// Machine name
    pub name: String,
    /// Force removal
    #[arg(short, long)]
    pub force: bool,
    /// Remove associated volumes
    #[arg(short, long)]
    pub volumes: bool,
}

#[derive(Args)]
pub struct ListArgs {
    /// Show all machines
    #[arg(short, long)]
    pub all: bool,
    /// Only show IDs
    #[arg(short, long)]
    pub quiet: bool,
}

#[derive(Args)]
pub struct StatusArgs {
    /// Machine name
    pub name: String,
}

#[derive(Args)]
pub struct SshArgs {
    /// Machine name
    pub name: String,
    /// Command to run
    #[arg(trailing_var_arg = true)]
    pub command: Vec<String>,
}

#[derive(Args)]
pub struct ExecArgs {
    /// Machine name
    pub name: String,
    /// Command to run
    #[arg(trailing_var_arg = true, required = true)]
    pub command: Vec<String>,
}

/// Executes the machine command.
pub async fn execute(cmd: MachineCommands) -> Result<()> {
    match cmd {
        MachineCommands::Create(args) => execute_create(args).await,
        MachineCommands::Start(args) => execute_start(args).await,
        MachineCommands::Stop(args) => execute_stop(args).await,
        MachineCommands::Remove(args) => execute_remove(args).await,
        MachineCommands::List(args) => execute_list(args).await,
        MachineCommands::Status(args) => execute_status(args).await,
        MachineCommands::Ssh(args) => execute_ssh(args).await,
        MachineCommands::Exec(args) => execute_exec(args).await,
    }
}

async fn execute_create(args: CreateArgs) -> Result<()> {
    let runtime = get_runtime();

    let config = MachineConfig {
        name: args.name.clone(),
        cpus: args.cpus,
        memory_mb: args.memory,
        disk_gb: args.disk,
        kernel: args.kernel.clone(),
        initrd: args.initrd.clone(),
        cmdline: args.cmdline.clone(),
        distro: None,
        distro_version: None,
    };

    runtime
        .machine_manager()
        .create(config)
        .await
        .context("Failed to create machine")?;

    println!("Machine '{}' created successfully", args.name);
    println!("  CPUs:   {}", args.cpus);
    println!("  Memory: {} MB", args.memory);
    println!("  Disk:   {} GB", args.disk);
    println!();
    println!("To start the machine, run:");
    println!("  arcbox machine start {}", args.name);

    Ok(())
}

async fn execute_start(args: StartArgs) -> Result<()> {
    let runtime = get_runtime();

    println!("Starting machine '{}'...", args.name);

    runtime
        .machine_manager()
        .start(&args.name)
        .await
        .context("Failed to start machine")?;

    println!("Machine '{}' started", args.name);

    Ok(())
}

async fn execute_stop(args: StopArgs) -> Result<()> {
    let runtime = get_runtime();

    println!("Stopping machine '{}'...", args.name);

    runtime
        .machine_manager()
        .stop(&args.name)
        .context("Failed to stop machine")?;

    println!("Machine '{}' stopped", args.name);

    Ok(())
}

async fn execute_remove(args: RemoveArgs) -> Result<()> {
    let runtime = get_runtime();

    runtime
        .machine_manager()
        .remove(&args.name, args.force)
        .context("Failed to remove machine")?;

    println!("Machine '{}' removed", args.name);

    Ok(())
}

async fn execute_list(args: ListArgs) -> Result<()> {
    let runtime = get_runtime();
    let machines = runtime.machine_manager().list();

    if args.quiet {
        for machine in &machines {
            println!("{}", machine.name);
        }
        return Ok(());
    }

    if machines.is_empty() {
        println!("No machines found.");
        println!();
        println!("To create a machine, run:");
        println!("  arcbox machine create <name>");
        return Ok(());
    }

    // Print header
    println!(
        "{:<20} {:<12} {:<6} {:<12} {:<10}",
        "NAME", "STATE", "CPUS", "MEMORY", "DISK"
    );

    // Print machines
    for machine in &machines {
        let state_str = match machine.state {
            MachineState::Created => "Created",
            MachineState::Starting => "Starting",
            MachineState::Running => "Running",
            MachineState::Stopping => "Stopping",
            MachineState::Stopped => "Stopped",
        };

        println!(
            "{:<20} {:<12} {:<6} {:<12} {:<10}",
            machine.name,
            state_str,
            machine.cpus,
            format!("{} MB", machine.memory_mb),
            format!("{} GB", machine.disk_gb),
        );
    }

    Ok(())
}

async fn execute_status(args: StatusArgs) -> Result<()> {
    let runtime = get_runtime();

    let machine = runtime
        .machine_manager()
        .get(&args.name)
        .ok_or_else(|| anyhow::anyhow!("Machine '{}' not found", args.name))?;

    let state_str = match machine.state {
        MachineState::Created => "Created",
        MachineState::Starting => "Starting",
        MachineState::Running => "Running",
        MachineState::Stopping => "Stopping",
        MachineState::Stopped => "Stopped",
    };

    println!("Machine: {}", machine.name);
    println!("State:   {}", state_str);
    println!("CPUs:    {}", machine.cpus);
    println!("Memory:  {} MB", machine.memory_mb);
    println!("Disk:    {} GB", machine.disk_gb);
    println!("VM ID:   {}", machine.vm_id);

    Ok(())
}

async fn execute_ssh(args: SshArgs) -> Result<()> {
    let runtime = get_runtime();

    // Check machine exists and is running
    let machine = runtime
        .machine_manager()
        .get(&args.name)
        .ok_or_else(|| anyhow::anyhow!("Machine '{}' not found", args.name))?;

    if machine.state != MachineState::Running {
        anyhow::bail!("Machine '{}' is not running", args.name);
    }

    // Determine command to execute
    let (cmd, tty) = if args.command.is_empty() {
        // Interactive mode: launch default shell
        (vec!["/bin/sh".to_string(), "-l".to_string()], true)
    } else {
        // Execute provided command
        (args.command.clone(), false)
    };

    // Execute command in the VM via agent
    let output = runtime
        .exec_machine(
            &args.name,
            cmd.clone(),
            HashMap::new(),
            String::new(),
            String::new(),
            tty,
        )
        .await
        .context("Failed to execute command in machine")?;

    // Print output based on stream type
    if !output.data.is_empty() {
        match output.stream.as_str() {
            "stderr" => {
                std::io::stderr()
                    .write_all(&output.data)
                    .context("Failed to write stderr")?;
            }
            _ => {
                // Default to stdout for "stdout" or empty stream
                std::io::stdout()
                    .write_all(&output.data)
                    .context("Failed to write stdout")?;
            }
        }
    }

    // Exit with the command's exit code
    if output.exit_code != 0 {
        std::process::exit(output.exit_code);
    }

    Ok(())
}

async fn execute_exec(args: ExecArgs) -> Result<()> {
    let runtime = get_runtime();

    // Check machine exists and is running
    let machine = runtime
        .machine_manager()
        .get(&args.name)
        .ok_or_else(|| anyhow::anyhow!("Machine '{}' not found", args.name))?;

    if machine.state != MachineState::Running {
        anyhow::bail!("Machine '{}' is not running", args.name);
    }

    // Execute command in the VM via agent (non-TTY mode for exec)
    let output = runtime
        .exec_machine(
            &args.name,
            args.command.clone(),
            HashMap::new(),
            String::new(),
            String::new(),
            false, // Non-interactive exec
        )
        .await
        .context("Failed to execute command in machine")?;

    // Print output based on stream type
    if !output.data.is_empty() {
        match output.stream.as_str() {
            "stderr" => {
                std::io::stderr()
                    .write_all(&output.data)
                    .context("Failed to write stderr")?;
            }
            _ => {
                // Default to stdout for "stdout" or empty stream
                std::io::stdout()
                    .write_all(&output.data)
                    .context("Failed to write stdout")?;
            }
        }
    }

    // Exit with the command's exit code
    if output.exit_code != 0 {
        std::process::exit(output.exit_code);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_machine_state_display() {
        assert_eq!(
            match MachineState::Running {
                MachineState::Running => "Running",
                _ => "Other",
            },
            "Running"
        );
    }
}
