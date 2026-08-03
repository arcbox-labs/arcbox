//! Sandbox management commands.
//!
//! Sandboxes are short-lived, strongly-isolated microVMs. The underlying guest
//! VM is managed transparently by the daemon and is not visible to the user.

use anyhow::{Context, Result};
use arcbox_connect::sandbox_v1 as pb;
use arcbox_connect::sandbox_v1::{
    AttachExecutionRequest, CheckpointRequest, CreateSandboxRequest, DeleteSnapshotRequest,
    Execution, ExposePortRequest, FileChunk, InspectSandboxRequest, ListSandboxesRequest,
    ListSnapshotsRequest, PortProtocol, ReadFileRequest, RemoveSandboxRequest,
    ResizeExecutionTtyRequest, ResourceLimits, RestoreRequest, SandboxEventKind,
    SandboxEventsRequest, SandboxState, StartExecutionRequest, StdioChannel, StopSandboxRequest,
    TerminalSize as ProtoTerminalSize, UnexposePortRequest, WaitExecutionRequest, WriteFileOpen,
    WriteFileRequest, WriteStdinRequest, execution_event, exit_status, watch_events_response,
};
use arcbox_connect::sandbox_v1::{
    SandboxFilesystemServiceClient, SandboxProcessServiceClient, SandboxServiceClient,
    SandboxSnapshotServiceClient,
};
use arcbox_core::vm_lifecycle::DEFAULT_MACHINE_NAME;
use buffa_types::google::protobuf::Timestamp;
use clap::{Args, Subcommand};
use std::collections::HashMap;
use std::io::Write;
use tokio::io::AsyncReadExt as _;

use arcbox_cli::terminal::{RawModeGuard, TerminalSize};

/// How many **consecutive** failures to re-establish an interrupted attach
/// stream are tolerated before giving up on streaming and asking the daemon
/// for the execution's outcome directly. Receiving any event resets the
/// budget, so a long session that resumes cleanly many times never
/// exhausts it.
const ATTACH_RESUME_ATTEMPTS: usize = 3;

/// Base pause between attach resume attempts (grows linearly with the
/// attempt number), so a daemon mid-restart is not burned through in
/// milliseconds against a socket that is not listening yet.
const ATTACH_RESUME_BACKOFF: std::time::Duration = std::time::Duration::from_millis(500);

/// Long-poll budget when falling back to `WaitExecution`, in seconds.
const EXEC_WAIT_TIMEOUT_SECS: u32 = 3600;

pub(super) fn sandbox_channel() -> (
    connectrpc::client::SharedHttp2Connection,
    connectrpc::client::ClientConfig,
) {
    crate::connect::daemon_for_machine(&super::resolve_grpc_socket_path(), DEFAULT_MACHINE_NAME)
}

/// Sandbox subcommands.
#[derive(Subcommand)]
pub enum SandboxCommands {
    /// Create a new sandbox
    Create(CreateArgs),
    /// Stop a sandbox gracefully
    Stop(StopArgs),
    /// Remove a sandbox
    #[command(alias = "rm")]
    Remove(RemoveArgs),
    /// List sandboxes
    #[command(name = "ls", alias = "list")]
    List(ListArgs),
    /// Inspect sandbox details
    Inspect(InspectArgs),
    /// Run a command inside a sandbox (streaming output, no stdin)
    Run(RunArgs),
    /// Execute an interactive command inside a sandbox
    Exec(ExecArgs),
    /// Subscribe to sandbox lifecycle events
    Events(EventsArgs),
    /// Copy a file into or out of a sandbox (<id>:<path> denotes the sandbox side)
    Cp(CpArgs),
    /// Expose a sandbox port on the host (via loopback)
    Expose(ExposeArgs),
    /// Remove an exposed sandbox port
    Unexpose(UnexposeArgs),
    /// Checkpoint a sandbox into a snapshot
    Checkpoint(CheckpointArgs),
    /// Restore a sandbox from a snapshot
    Restore(RestoreArgs),
    /// List snapshots
    #[command(name = "snapshots")]
    ListSnapshots(ListSnapshotsArgs),
    /// Delete a snapshot
    #[command(name = "snapshot-rm")]
    DeleteSnapshot(DeleteSnapshotArgs),
    /// List built-in rootfs templates
    Templates(TemplatesArgs),
}

#[derive(Args)]
pub struct CreateArgs {
    /// Caller-supplied sandbox ID (empty = auto-generated)
    #[arg(long)]
    pub id: Option<String>,
    /// Build the sandbox image from a Dockerfile
    #[arg(long, conflicts_with_all = ["from_image", "from_template"])]
    pub from_dockerfile: Option<String>,
    /// Use an existing Docker image as the sandbox image
    #[arg(long, conflicts_with_all = ["from_dockerfile", "from_template"])]
    pub from_image: Option<String>,
    /// Use a built-in template as the sandbox image (see `sandbox templates`)
    #[arg(long, conflicts_with_all = ["from_dockerfile", "from_image"])]
    pub from_template: Option<String>,
    /// Number of vCPUs (0 = daemon default)
    #[arg(long, default_value = "0")]
    pub cpus: u32,
    /// Memory in MiB (0 = daemon default)
    #[arg(long, default_value = "0")]
    pub memory: u64,
    /// Key=value labels
    #[arg(short, long)]
    pub label: Vec<String>,
    /// Sandbox auto-destruction timeout in seconds (0 = no limit)
    #[arg(long, default_value = "0")]
    pub ttl: u32,
}

#[derive(Args)]
pub struct StopArgs {
    /// Sandbox ID
    pub id: String,
    /// Seconds to wait before force-killing (0 = daemon default)
    #[arg(long, default_value = "0")]
    pub timeout: u32,
}

#[derive(Args)]
pub struct RemoveArgs {
    /// Sandbox ID
    pub id: String,
    /// Force removal even if running
    #[arg(short, long)]
    pub force: bool,
}

#[derive(Args)]
pub struct ListArgs {
    /// Filter by state (starting/ready/running/stopping/stopped/failed)
    #[arg(long)]
    pub state: Option<String>,
    /// Only show IDs
    #[arg(short, long)]
    pub quiet: bool,
}

#[derive(Args)]
pub struct InspectArgs {
    /// Sandbox ID
    pub id: String,
}

#[derive(Args)]
pub struct RunArgs {
    /// Sandbox ID
    pub id: String,
    /// Command and arguments
    #[arg(trailing_var_arg = true, required = true)]
    pub cmd: Vec<String>,
    /// Allocate a pseudo-TTY
    #[arg(short, long)]
    pub tty: bool,
    /// Kill after this many seconds (0 = no timeout)
    #[arg(long, default_value = "0")]
    pub timeout: u32,
}

#[derive(Args)]
pub struct ExecArgs {
    /// Sandbox ID
    pub id: String,
    /// Command and arguments
    #[arg(trailing_var_arg = true, required = true)]
    pub cmd: Vec<String>,
    /// Allocate a pseudo-TTY
    #[arg(short = 't', long)]
    pub tty: bool,
    /// Kill after this many seconds (0 = no timeout)
    #[arg(long, default_value = "0")]
    pub timeout: u32,
}

#[derive(Args)]
pub struct EventsArgs {
    /// Filter by sandbox ID (empty = all sandboxes)
    #[arg(long)]
    pub id: Option<String>,
    /// Filter by event kind (created/ready/running/idle/stopping/stopped/failed/removed)
    #[arg(long)]
    pub kind: Option<String>,
}

#[derive(Args)]
pub struct CpArgs {
    /// Source: a local path or <sandbox-id>:<absolute-path>
    pub src: String,
    /// Destination: a local path or <sandbox-id>:<absolute-path>
    pub dst: String,
}

#[derive(Args)]
pub struct ExposeArgs {
    /// Sandbox ID
    pub id: String,
    /// Port the workload listens on inside the sandbox
    pub port: u16,
    /// Host port to bind (0 = pick the guest relay port)
    #[arg(long, default_value = "0")]
    pub host_port: u16,
    /// Protocol: tcp or udp
    #[arg(long, default_value = "tcp")]
    pub protocol: String,
}

#[derive(Args)]
pub struct UnexposeArgs {
    /// Sandbox ID
    pub id: String,
    /// The sandbox port previously exposed
    pub port: u16,
    /// Protocol: tcp or udp
    #[arg(long, default_value = "tcp")]
    pub protocol: String,
}

#[derive(Args)]
pub struct CheckpointArgs {
    /// Sandbox ID to checkpoint
    pub id: String,
    /// Human-readable snapshot name
    #[arg(long, default_value = "")]
    pub name: String,
}

#[derive(Args)]
pub struct RestoreArgs {
    /// Snapshot ID to restore from
    pub snapshot_id: String,
    /// Assign a new sandbox ID (empty = auto-generated)
    #[arg(long)]
    pub sandbox_id: Option<String>,
    /// Sandbox auto-destruction timeout in seconds (0 = no limit)
    #[arg(long, default_value = "0")]
    pub ttl: u32,
}

#[derive(Args)]
pub struct ListSnapshotsArgs {
    /// Filter by origin sandbox ID (empty = all)
    #[arg(long)]
    pub sandbox_id: Option<String>,
}

#[derive(Args)]
pub struct DeleteSnapshotArgs {
    /// Snapshot ID
    pub snapshot_id: String,
}

#[derive(Args)]
pub struct TemplatesArgs {
    /// Print a template's Dockerfile instead of listing names
    ///
    /// Redirect it to a file to customize a template, then build the result
    /// with `--from-dockerfile`.
    #[arg(long, value_name = "NAME")]
    pub show: Option<String>,
}

/// Executes a sandbox subcommand.
pub async fn execute(cmd: SandboxCommands) -> Result<()> {
    match cmd {
        SandboxCommands::Create(args) => execute_create(args).await,
        SandboxCommands::Stop(args) => execute_stop(args).await,
        SandboxCommands::Remove(args) => execute_remove(args).await,
        SandboxCommands::List(args) => execute_list(args).await,
        SandboxCommands::Inspect(args) => execute_inspect(args).await,
        SandboxCommands::Run(args) => execute_run(args).await,
        SandboxCommands::Exec(args) => execute_exec(args).await,
        SandboxCommands::Events(args) => execute_events(args).await,
        SandboxCommands::Cp(args) => execute_cp(args).await,
        SandboxCommands::Expose(args) => execute_expose(args).await,
        SandboxCommands::Unexpose(args) => execute_unexpose(args).await,
        SandboxCommands::Checkpoint(args) => execute_checkpoint(args).await,
        SandboxCommands::Restore(args) => execute_restore(args).await,
        SandboxCommands::ListSnapshots(args) => execute_list_snapshots(args).await,
        SandboxCommands::DeleteSnapshot(args) => execute_delete_snapshot(args).await,
        SandboxCommands::Templates(args) => execute_templates(args),
    }
}

/// Build a built-in template and return its sandbox template reference.
///
/// Shared with the agent-session commands (`abctl claude`), which select their
/// image by template name.
pub(super) async fn resolve_template(name: &str) -> Result<String> {
    let template = arcbox_cli::templates::find(name).with_context(|| {
        format!(
            "unknown template '{name}' (available: {})",
            arcbox_cli::templates::names()
        )
    })?;
    arcbox_cli::rootfs_builder::resolve_from_dockerfile_contents(template.dockerfile.as_bytes())
        .await
        .with_context(|| format!("Failed to build the '{name}' template image"))
}

fn execute_templates(args: TemplatesArgs) -> Result<()> {
    if let Some(name) = args.show {
        let template = arcbox_cli::templates::find(&name).with_context(|| {
            format!(
                "unknown template '{name}' (available: {})",
                arcbox_cli::templates::names()
            )
        })?;
        print!("{}", template.dockerfile);
        return Ok(());
    }

    for template in arcbox_cli::templates::TEMPLATES {
        println!("{:<10} {}", template.name, template.description);
    }
    Ok(())
}

fn parse_labels(raw: &[String]) -> Result<HashMap<String, String>> {
    let mut map = HashMap::new();
    for kv in raw {
        let mut parts = kv.splitn(2, '=');
        let key = parts.next().unwrap_or_default().trim();
        let val = parts.next().unwrap_or_default().trim();
        if key.is_empty() {
            anyhow::bail!("invalid label '{}', expected key=value", kv);
        }
        map.insert(key.to_string(), val.to_string());
    }
    Ok(map)
}

/// Human-readable name of a sandbox state.
pub(super) fn state_name(state: SandboxState) -> &'static str {
    match state {
        SandboxState::Unspecified => "unknown",
        SandboxState::Starting => "starting",
        SandboxState::Ready => "ready",
        SandboxState::Running => "running",
        SandboxState::Stopping => "stopping",
        SandboxState::Stopped => "stopped",
        SandboxState::Failed => "failed",
        SandboxState::Pausing => "pausing",
        SandboxState::Paused => "paused",
    }
}

/// Parse a `--state` filter value.
fn parse_state(value: &str) -> Result<SandboxState> {
    Ok(match value.to_ascii_lowercase().as_str() {
        "starting" => SandboxState::Starting,
        "ready" => SandboxState::Ready,
        "running" => SandboxState::Running,
        "stopping" => SandboxState::Stopping,
        "stopped" => SandboxState::Stopped,
        "failed" => SandboxState::Failed,
        "pausing" => SandboxState::Pausing,
        "paused" => SandboxState::Paused,
        other => anyhow::bail!(
            "unknown state '{other}' (expected starting/ready/running/stopping/\
             stopped/failed/pausing/paused)"
        ),
    })
}

/// Parse a `--kind` event filter value.
fn parse_event_kind(value: &str) -> Result<SandboxEventKind> {
    Ok(match value.to_ascii_lowercase().as_str() {
        "created" => SandboxEventKind::Created,
        "ready" => SandboxEventKind::Ready,
        "running" => SandboxEventKind::Running,
        "idle" => SandboxEventKind::Idle,
        "stopping" => SandboxEventKind::Stopping,
        "stopped" => SandboxEventKind::Stopped,
        "failed" => SandboxEventKind::Failed,
        "removed" => SandboxEventKind::Removed,
        "pausing" => SandboxEventKind::Pausing,
        "paused" => SandboxEventKind::Paused,
        "resumed" => SandboxEventKind::Resumed,
        other => anyhow::bail!(
            "unknown event kind '{other}' (expected \
             created/ready/running/idle/stopping/stopped/failed/removed/\
             pausing/paused/resumed)"
        ),
    })
}

/// Human-readable name of an event kind.
fn event_kind_name(kind: SandboxEventKind) -> &'static str {
    match kind {
        SandboxEventKind::Unspecified => "unknown",
        SandboxEventKind::Created => "created",
        SandboxEventKind::Ready => "ready",
        SandboxEventKind::Running => "running",
        SandboxEventKind::Idle => "idle",
        SandboxEventKind::Stopping => "stopping",
        SandboxEventKind::Stopped => "stopped",
        SandboxEventKind::Failed => "failed",
        SandboxEventKind::Removed => "removed",
        SandboxEventKind::Pausing => "pausing",
        SandboxEventKind::Paused => "paused",
        SandboxEventKind::Resumed => "resumed",
    }
}

/// Parse a `--protocol` flag value.
fn parse_protocol(value: &str) -> Result<PortProtocol> {
    Ok(match value.to_ascii_lowercase().as_str() {
        "" | "tcp" => PortProtocol::Tcp,
        "udp" => PortProtocol::Udp,
        other => anyhow::bail!("unsupported protocol '{other}' (expected tcp or udp)"),
    })
}

/// Render a proto timestamp as RFC3339 (empty when unset).
fn format_timestamp(ts: Option<&Timestamp>) -> String {
    ts.and_then(|t| {
        chrono::DateTime::from_timestamp(t.seconds, u32::try_from(t.nanos).unwrap_or(0))
    })
    .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
    .unwrap_or_default()
}

/// Shell-convention scalar exit code of a finished execution
/// (`128 + signal` for signal deaths; 1 when torn down without an exit).
fn exit_code_of(execution: &Execution) -> i32 {
    // An unset `exit_status` derefs to the default instance, whose oneof is
    // `None` — the same "torn down without an exit" case as before.
    match execution.exit_status.status.as_ref() {
        Some(exit_status::Status::Code(code)) => *code,
        Some(exit_status::Status::Signal(signal)) => 128 + signal,
        None => 1,
    }
}

async fn execute_create(args: CreateArgs) -> Result<()> {
    let (transport, config) = sandbox_channel();
    let client = SandboxServiceClient::new(transport.clone(), config.clone());

    let labels = parse_labels(&args.label)?;

    // Resolve whichever selector was given to a template reference. An
    // absent selector leaves it empty: the built-in minimal image.
    let template = if let Some(path) = &args.from_dockerfile {
        arcbox_cli::rootfs_builder::resolve_from_dockerfile(path)
            .await
            .context("Failed to build Docker image from Dockerfile")?
    } else if let Some(image_ref) = &args.from_image {
        arcbox_cli::rootfs_builder::resolve_from_image(image_ref)
            .await
            .context("Failed to resolve Docker image")?
    } else if let Some(name) = &args.from_template {
        resolve_template(name).await?
    } else {
        String::new()
    };

    let req = CreateSandboxRequest {
        id: args.id.unwrap_or_default(),
        labels: labels.into_iter().collect(),
        template,
        limits: ResourceLimits {
            vcpus: args.cpus,
            memory_mib: args.memory,
            ..Default::default()
        }
        .into(),
        ttl_seconds: args.ttl,
        ..Default::default()
    };

    let resp: pb::CreateSandboxResponse = client
        .create(req)
        .await
        .context("Failed to create sandbox")?
        .into_owned();

    println!("Sandbox created");
    println!("  ID:    {}", resp.id);
    println!("  IP:    {}", resp.ip_address);
    println!(
        "  State: {}",
        state_name(resp.state.as_known().unwrap_or_default())
    );
    Ok(())
}

async fn execute_stop(args: StopArgs) -> Result<()> {
    let (transport, config) = sandbox_channel();
    let client = SandboxServiceClient::new(transport.clone(), config.clone());

    client
        .stop(StopSandboxRequest {
            id: args.id.clone(),
            timeout_seconds: args.timeout,
            ..Default::default()
        })
        .await
        .context("Failed to stop sandbox")?;

    println!("Sandbox '{}' stopped", args.id);
    Ok(())
}

async fn execute_remove(args: RemoveArgs) -> Result<()> {
    let (transport, config) = sandbox_channel();
    let client = SandboxServiceClient::new(transport.clone(), config.clone());

    client
        .remove(RemoveSandboxRequest {
            id: args.id.clone(),
            force: args.force,
            ..Default::default()
        })
        .await
        .context("Failed to remove sandbox")?;

    println!("Sandbox '{}' removed", args.id);
    Ok(())
}

async fn execute_list(args: ListArgs) -> Result<()> {
    let (transport, config) = sandbox_channel();
    let client = SandboxServiceClient::new(transport.clone(), config.clone());

    let state = match &args.state {
        Some(value) => parse_state(value)?,
        None => SandboxState::Unspecified,
    };
    // Follow continuation tokens so the human view stays complete.
    let mut sandboxes = Vec::new();
    let mut page_token = String::new();
    loop {
        let mut resp: pb::ListSandboxesResponse = client
            .list(ListSandboxesRequest {
                state: state.into(),
                page_token: page_token.clone(),
                ..Default::default()
            })
            .await
            .context("Failed to list sandboxes")?
            .into_owned();
        sandboxes.append(&mut resp.sandboxes);
        if resp.next_page_token.is_empty() {
            break;
        }
        page_token = resp.next_page_token;
    }

    if args.quiet {
        for sb in &sandboxes {
            println!("{}", sb.id);
        }
        return Ok(());
    }

    if sandboxes.is_empty() {
        println!("No sandboxes found.");
        return Ok(());
    }

    println!("{:<36} {:<12} {:<18} CREATED", "ID", "STATE", "IP");
    for sb in &sandboxes {
        println!(
            "{:<36} {:<12} {:<18} {}",
            sb.id,
            state_name(sb.state.as_known().unwrap_or_default()),
            sb.ip_address,
            format_timestamp(sb.created_at.as_option()),
        );
    }
    Ok(())
}

async fn execute_inspect(args: InspectArgs) -> Result<()> {
    let (transport, config) = sandbox_channel();
    let client = SandboxServiceClient::new(transport.clone(), config.clone());

    let info: pb::SandboxInfo = client
        .inspect(InspectSandboxRequest {
            id: args.id,
            ..Default::default()
        })
        .await
        .context("Failed to inspect sandbox")?
        .into_owned();

    let last_exit_status = info
        .last_exit_status
        .as_option()
        .and_then(|s| s.status.as_ref())
        .map(|status| match status {
            exit_status::Status::Code(code) => serde_json::json!({ "code": code }),
            exit_status::Status::Signal(signal) => serde_json::json!({ "signal": signal }),
        });
    let payload = serde_json::json!({
        "id": info.id,
        "state": state_name(info.state.as_known().unwrap_or_default()),
        "labels": info.labels,
        "limits": info.limits.as_option().map(|l| serde_json::json!({
            "vcpus": l.vcpus,
            "memory_mib": l.memory_mib,
        })),
        "network": info.network.as_option().map(|n| serde_json::json!({
            "ip_address": n.ip_address,
            "gateway": n.gateway,
        })),
        "created_at": format_timestamp(info.created_at.as_option()),
        "ready_at": format_timestamp(info.ready_at.as_option()),
        "last_exited_at": format_timestamp(info.last_exited_at.as_option()),
        "last_exit_status": last_exit_status,
        "error": info.error,
    });

    println!(
        "{}",
        serde_json::to_string_pretty(&payload).context("Failed to serialize sandbox info")?
    );
    Ok(())
}

async fn execute_run(args: RunArgs) -> Result<()> {
    let (transport, config) = sandbox_channel();

    let start = StartExecutionRequest {
        sandbox_id: args.id,
        cmd: args.cmd,
        tty: args.tty,
        tty_size: current_tty_size(args.tty).into(),
        timeout_seconds: args.timeout,
        stdin: false,
        ..Default::default()
    };

    let exit_code = exec_session(transport, config, start).await?;
    if exit_code != 0 {
        std::process::exit(exit_code);
    }
    Ok(())
}

async fn execute_exec(args: ExecArgs) -> Result<()> {
    let (transport, config) = sandbox_channel();

    let start = StartExecutionRequest {
        sandbox_id: args.id,
        cmd: args.cmd,
        tty: args.tty,
        tty_size: current_tty_size(args.tty).into(),
        timeout_seconds: args.timeout,
        stdin: true,
        ..Default::default()
    };

    let exit_code = exec_session(transport, config, start).await?;
    if exit_code != 0 {
        std::process::exit(exit_code);
    }
    Ok(())
}

/// Initial terminal size to report, when a TTY was requested.
pub(super) fn current_tty_size(tty: bool) -> Option<ProtoTerminalSize> {
    if !tty {
        return None;
    }
    TerminalSize::current().ok().map(|s| ProtoTerminalSize {
        width: u32::from(s.cols),
        height: u32::from(s.rows),
        ..Default::default()
    })
}

/// Start an execution, stream its output, and return the exit code.
///
/// Owns the whole session: StartExecution, the attach stream, raw terminal
/// mode, SIGWINCH forwarding via ResizeExecutionTty, and (when `stdin` is
/// requested) the offset-tracked WriteStdin pump. Callers decide what an exit
/// code means — nothing here terminates the process.
pub(super) async fn exec_session(
    transport: connectrpc::client::SharedHttp2Connection,
    config: connectrpc::client::ClientConfig,
    mut start: StartExecutionRequest,
) -> Result<i32> {
    // Executions are the data plane (CORE-57): a separate service from the
    // lifecycle calls, so this builds its own client rather than borrowing
    // the caller's control-plane one.
    let client = SandboxProcessServiceClient::new(transport.clone(), config.clone());
    let tty = start.tty;
    let stdin = start.stdin;
    let sandbox_id = start.sandbox_id.clone();

    // Choose the execution id here, not server-side: if the StartExecution
    // response is lost in flight the command may already be running, and only
    // an id we picked beforehand lets us retry idempotently (or address the
    // survivor) instead of starting a second process.
    if start.execution_id.is_empty() {
        start.execution_id = uuid::Uuid::new_v4().to_string();
    }
    let execution_id = start.execution_id.clone();

    client
        .start_execution(start)
        .await
        .context("Failed to start execution in sandbox")?;

    // Enable raw terminal mode when TTY is requested.
    let raw_guard = if tty {
        Some(RawModeGuard::new()?)
    } else {
        None
    };

    // Resize pump: SIGWINCH → unary resize calls (TTY sessions only).
    if tty {
        let resize_client = client.clone();
        let sandbox_id = sandbox_id.clone();
        let execution_id = execution_id.clone();
        match arcbox_cli::terminal::ResizeWatcher::new() {
            Ok(mut watcher) => {
                tokio::spawn(async move {
                    while let Some(size) = watcher.recv().await {
                        let req = ResizeExecutionTtyRequest {
                            sandbox_id: sandbox_id.clone(),
                            execution_id: execution_id.clone(),
                            size: ProtoTerminalSize {
                                width: u32::from(size.cols),
                                height: u32::from(size.rows),
                                ..Default::default()
                            }
                            .into(),
                            ..Default::default()
                        };
                        if resize_client.resize_execution_tty(req).await.is_err() {
                            break;
                        }
                    }
                });
            }
            Err(e) => tracing::warn!(error = %e, "terminal resize forwarding disabled"),
        }
    }

    // Stdin pump: local terminal → offset-tracked WriteStdin calls. The
    // returned `bytes_written` is the next offset, so a retried or partially
    // deduplicated write can never double-feed the process.
    let stdin_pump = stdin.then(|| {
        let stdin_client = client.clone();
        let sandbox_id = sandbox_id.clone();
        let execution_id = execution_id.clone();
        tokio::spawn(async move {
            let mut stdin = tokio::io::stdin();
            let mut buf = [0u8; 4096];
            let mut offset = 0u64;
            'pump: loop {
                match stdin.read(&mut buf).await {
                    Ok(0) | Err(_) => {
                        // Local EOF. PTY sessions carry EOF in-band (Ctrl-D);
                        // for pipes, close the remote stdin explicitly.
                        if !tty {
                            let req = WriteStdinRequest {
                                sandbox_id: sandbox_id.clone(),
                                execution_id: execution_id.clone(),
                                offset,
                                data: Vec::new(),
                                eof: true,
                                ..Default::default()
                            };
                            let _ = stdin_client.write_stdin(req).await;
                        }
                        break;
                    }
                    Ok(n) => {
                        // A broken write gets the same grace as the attach
                        // stream: writes are offset-addressed, so retrying
                        // the same chunk can never double-feed the process.
                        let mut failures = 0usize;
                        loop {
                            let req = WriteStdinRequest {
                                sandbox_id: sandbox_id.clone(),
                                execution_id: execution_id.clone(),
                                offset,
                                data: buf[..n].to_vec(),
                                eof: false,
                                ..Default::default()
                            };
                            match stdin_client.write_stdin(req).await {
                                Ok(resp) => {
                                    offset = resp.into_owned().bytes_written;
                                    break;
                                }
                                Err(_) if failures < ATTACH_RESUME_ATTEMPTS => {
                                    failures += 1;
                                    tokio::time::sleep(ATTACH_RESUME_BACKOFF * failures as u32)
                                        .await;
                                }
                                // The execution exited (or the daemon is gone
                                // for good); the attach stream reports the
                                // outcome.
                                Err(_) => break 'pump,
                            }
                        }
                    }
                }
            }
        })
    });

    // Copy output out, re-attaching at the recorded offsets if the stream
    // breaks. The execution outlives the connection, so a daemon restart or
    // a cut connection is a resumable event, not a failed command — this is
    // the client half of what the offset-addressed protocol buys.
    let mut stdout_offset = 0u64;
    let mut stderr_offset = 0u64;
    let mut result: Option<Execution> = None;

    // Consecutive failures to (re-)establish the stream. Reset every time an
    // event arrives, so the budget means "streaming is not coming back", not
    // "the session broke N times over its whole lifetime".
    let mut attempt = 0usize;

    'resume: loop {
        let attach = AttachExecutionRequest {
            sandbox_id: sandbox_id.clone(),
            execution_id: execution_id.clone(),
            stdout_offset,
            stderr_offset,
            ..Default::default()
        };
        let mut stream = match client.attach_execution(attach).await {
            Ok(response) => response,
            Err(status) => {
                attempt += 1;
                if attempt > ATTACH_RESUME_ATTEMPTS {
                    // Streaming is not coming back, but the execution may
                    // have finished fine — fall through to the authoritative
                    // wait rather than reporting a transport error as the
                    // command's outcome.
                    tracing::warn!(%status, "giving up on the attach stream");
                    break 'resume;
                }
                tracing::warn!(%status, "re-attaching to the execution");
                tokio::time::sleep(ATTACH_RESUME_BACKOFF * attempt as u32).await;
                continue;
            }
        };

        loop {
            let event = match stream.message::<pb::ExecutionEvent>().await {
                Ok(Some(item)) => item.to_owned_message(),
                // Clean end without an exit event: fall through to the
                // authoritative wait below.
                Ok(None) => break 'resume,
                Err(status) => {
                    attempt += 1;
                    if attempt > ATTACH_RESUME_ATTEMPTS {
                        tracing::warn!(%status, "giving up on the attach stream");
                        break 'resume;
                    }
                    tracing::warn!(%status, stdout_offset, "attach stream broke; resuming");
                    tokio::time::sleep(ATTACH_RESUME_BACKOFF * attempt as u32).await;
                    continue 'resume;
                }
            };
            // Anything received proves the stream re-established.
            attempt = 0;

            match event.event {
                Some(execution_event::Event::Output(output)) => {
                    // Advance past this chunk even when empty, so a resume
                    // never re-reads it. The server may report a higher
                    // offset than requested when retention dropped bytes.
                    let end = output.offset + output.data.len() as u64;
                    let (target, sink): (&mut u64, &mut dyn Write) =
                        if output.channel == StdioChannel::Stderr {
                            (&mut stderr_offset, &mut std::io::stderr())
                        } else {
                            (&mut stdout_offset, &mut std::io::stdout())
                        };
                    if end > *target {
                        *target = end;
                    }
                    if !output.data.is_empty() {
                        sink.write_all(&output.data)
                            .context("Failed to write execution output")?;
                        sink.flush()?;
                    }
                }
                Some(execution_event::Event::Exited(exited)) => {
                    result = exited.execution.into_option();
                    break 'resume;
                }
                // The Started preamble and idle keepalives carry no output.
                Some(execution_event::Event::Started(_) | execution_event::Event::KeepAlive(_))
                | None => {}
            }
        }
    }

    if let Some(pump) = stdin_pump {
        pump.abort();
    }
    // Drop the raw mode guard before returning so the terminal is restored.
    drop(raw_guard);

    let execution = match result {
        Some(execution) => execution,
        // The stream ended without an exit event and re-attaching did not
        // recover it. The execution itself is unaffected, so block on its
        // real outcome rather than reporting a synthetic failure.
        None => client
            .wait_execution(WaitExecutionRequest {
                sandbox_id,
                execution_id,
                timeout_seconds: EXEC_WAIT_TIMEOUT_SECS,
                ..Default::default()
            })
            .await
            .context("attach stream closed without an exit event")?
            .into_owned(),
    };
    Ok(exit_code_of(&execution))
}

async fn execute_events(args: EventsArgs) -> Result<()> {
    let (transport, config) = sandbox_channel();
    let client = SandboxServiceClient::new(transport.clone(), config.clone());

    let kind = match &args.kind {
        Some(value) => parse_event_kind(value)?,
        None => SandboxEventKind::Unspecified,
    };
    let mut stream = client
        .events(SandboxEventsRequest {
            sandbox_id: args.id.unwrap_or_default(),
            kind: kind.into(),
            ..Default::default()
        })
        .await
        .context("Failed to subscribe to sandbox events")?;

    println!("Listening for sandbox events (Ctrl+C to stop)...");
    while let Some(frame) = stream
        .message::<pb::WatchEventsResponse>()
        .await
        .context("Failed to read sandbox event")?
        .map(|item| item.to_owned_message())
    {
        let Some(watch_events_response::Payload::Event(event)) = frame.payload else {
            continue; // keepalive
        };
        println!(
            "[{}] sandbox={} kind={}",
            format_timestamp(event.time.as_option()),
            event.sandbox_id,
            event_kind_name(event.kind.as_known().unwrap_or_default()),
        );
        if !event.attributes.is_empty() {
            for (k, v) in &event.attributes {
                println!("  {}={}", k, v);
            }
        }
    }
    Ok(())
}

async fn execute_checkpoint(args: CheckpointArgs) -> Result<()> {
    let (transport, config) = sandbox_channel();
    let client = SandboxSnapshotServiceClient::new(transport.clone(), config.clone());

    let resp: pb::CheckpointResponse = client
        .checkpoint(CheckpointRequest {
            sandbox_id: args.id,
            name: args.name,
            ..Default::default()
        })
        .await
        .context("Failed to checkpoint sandbox")?
        .into_owned();

    println!("Snapshot created");
    println!("  Snapshot ID: {}", resp.snapshot_id);
    println!(
        "  Created at:  {}",
        format_timestamp(resp.created_at.as_option())
    );
    Ok(())
}

async fn execute_restore(args: RestoreArgs) -> Result<()> {
    let (transport, config) = sandbox_channel();
    let client = SandboxSnapshotServiceClient::new(transport.clone(), config.clone());

    let resp: pb::RestoreResponse = client
        .restore(RestoreRequest {
            id: args.sandbox_id.unwrap_or_default(),
            snapshot_id: args.snapshot_id,
            ttl_seconds: args.ttl,
            ..Default::default()
        })
        .await
        .context("Failed to restore sandbox")?
        .into_owned();

    println!("Sandbox restored");
    println!("  ID: {}", resp.id);
    println!("  IP: {}", resp.ip_address);
    Ok(())
}

async fn execute_list_snapshots(args: ListSnapshotsArgs) -> Result<()> {
    let (transport, config) = sandbox_channel();
    let client = SandboxSnapshotServiceClient::new(transport.clone(), config.clone());

    // Follow continuation tokens so the human view stays complete.
    let mut snapshots = Vec::new();
    let mut page_token = String::new();
    loop {
        let mut resp: pb::ListSnapshotsResponse = client
            .list_snapshots(ListSnapshotsRequest {
                sandbox_id: args.sandbox_id.clone().unwrap_or_default(),
                page_token: page_token.clone(),
                ..Default::default()
            })
            .await
            .context("Failed to list snapshots")?
            .into_owned();
        snapshots.append(&mut resp.snapshots);
        if resp.next_page_token.is_empty() {
            break;
        }
        page_token = resp.next_page_token;
    }

    if snapshots.is_empty() {
        println!("No snapshots found.");
        return Ok(());
    }

    println!(
        "{:<36} {:<36} {:<20} CREATED",
        "SNAPSHOT ID", "SANDBOX ID", "NAME"
    );
    for snap in &snapshots {
        println!(
            "{:<36} {:<36} {:<20} {}",
            snap.id,
            snap.sandbox_id,
            snap.name,
            format_timestamp(snap.created_at.as_option()),
        );
    }
    Ok(())
}

async fn execute_delete_snapshot(args: DeleteSnapshotArgs) -> Result<()> {
    let (transport, config) = sandbox_channel();
    let client = SandboxSnapshotServiceClient::new(transport.clone(), config.clone());

    client
        .delete_snapshot(DeleteSnapshotRequest {
            snapshot_id: args.snapshot_id.clone(),
            ..Default::default()
        })
        .await
        .context("Failed to delete snapshot")?;

    println!("Snapshot '{}' deleted", args.snapshot_id);
    Ok(())
}

/// One side of a `cp` transfer: local path or `<sandbox-id>:<path>`.
enum CpEndpoint {
    Local(String),
    Sandbox { id: String, path: String },
}

/// Parse docker-cp style endpoints: `<id>:<path>` is a sandbox side when the
/// prefix contains no path separator (so `./a:b` stays a local file).
fn parse_cp_endpoint(spec: &str) -> CpEndpoint {
    if let Some((id, path)) = spec.split_once(':')
        && !id.is_empty()
        && !id.contains('/')
    {
        return CpEndpoint::Sandbox {
            id: id.to_owned(),
            path: path.to_owned(),
        };
    }
    CpEndpoint::Local(spec.to_owned())
}

async fn execute_cp(args: CpArgs) -> Result<()> {
    let (transport, config) = sandbox_channel();
    let client = SandboxFilesystemServiceClient::new(transport.clone(), config.clone());

    match (parse_cp_endpoint(&args.src), parse_cp_endpoint(&args.dst)) {
        (CpEndpoint::Local(src), CpEndpoint::Sandbox { id, path }) => {
            let data = tokio::fs::read(&src)
                .await
                .with_context(|| format!("Failed to read {src}"))?;
            let mode = {
                use std::os::unix::fs::PermissionsExt;
                tokio::fs::metadata(&src)
                    .await
                    .map_or(0o644, |m| m.permissions().mode() & 0o777)
            };
            let total = data.len();

            // Connect's client-streaming call takes an async stream and pulls
            // from it with backpressure; the chunks are ready data (the whole
            // file is already read above), so a `stream_iter` over the built
            // requests is enough — no channel or spawned task.
            const CHUNK: usize = 1024 * 1024;
            let open = WriteFileRequest {
                payload: WriteFileOpen {
                    id,
                    path,
                    mode,
                    ..Default::default()
                }
                .into(),
                ..Default::default()
            };
            let chunks = data.chunks(CHUNK).map(|part| WriteFileRequest {
                payload: FileChunk {
                    data: part.to_vec(),
                    done: false,
                    ..Default::default()
                }
                .into(),
                ..Default::default()
            });
            let done = WriteFileRequest {
                payload: FileChunk {
                    data: Vec::new(),
                    done: true,
                    ..Default::default()
                }
                .into(),
                ..Default::default()
            };
            let requests: Vec<_> = std::iter::once(open)
                .chain(chunks)
                .chain(std::iter::once(done))
                .collect();
            client
                .write_file(connectrpc::client::stream_iter(requests))
                .await
                .context("Failed to write file into sandbox")?;
            println!("Copied {total} bytes to {}", args.dst);
        }
        (CpEndpoint::Sandbox { id, path }, CpEndpoint::Local(dst)) => {
            let mut stream = client
                .read_file(ReadFileRequest {
                    id,
                    path,
                    ..Default::default()
                })
                .await
                .context("Failed to read file from sandbox")?;

            let mut out = tokio::fs::File::create(&dst)
                .await
                .with_context(|| format!("Failed to create {dst}"))?;
            let mut total = 0usize;
            while let Some(chunk) = stream
                .message::<pb::FileChunk>()
                .await
                .context("Failed to read file stream")?
                .map(|item| item.to_owned_message())
            {
                if !chunk.data.is_empty() {
                    tokio::io::AsyncWriteExt::write_all(&mut out, &chunk.data)
                        .await
                        .context("Failed to write local file")?;
                    total += chunk.data.len();
                }
                if chunk.done {
                    break;
                }
            }
            tokio::io::AsyncWriteExt::flush(&mut out).await?;
            println!("Copied {total} bytes to {dst}");
        }
        (CpEndpoint::Local(_), CpEndpoint::Local(_)) => {
            anyhow::bail!("one side must be a sandbox path (<sandbox-id>:<path>)");
        }
        (CpEndpoint::Sandbox { .. }, CpEndpoint::Sandbox { .. }) => {
            anyhow::bail!("sandbox-to-sandbox copies are not supported");
        }
    }
    Ok(())
}

async fn execute_expose(args: ExposeArgs) -> Result<()> {
    let (transport, config) = sandbox_channel();
    let client = SandboxServiceClient::new(transport.clone(), config.clone());
    let protocol = parse_protocol(&args.protocol)?;
    let resp: pb::ExposePortResponse = client
        .expose_port(ExposePortRequest {
            id: args.id.clone(),
            sandbox_port: u32::from(args.port),
            host_port: u32::from(args.host_port),
            protocol: protocol.into(),
            ..Default::default()
        })
        .await
        .context("Failed to expose sandbox port")?
        .into_owned();
    println!(
        "{}:{}/{} exposed on localhost:{}",
        args.id, args.port, args.protocol, resp.host_port
    );
    Ok(())
}

async fn execute_unexpose(args: UnexposeArgs) -> Result<()> {
    let (transport, config) = sandbox_channel();
    let client = SandboxServiceClient::new(transport.clone(), config.clone());
    let protocol = parse_protocol(&args.protocol)?;
    client
        .unexpose_port(UnexposePortRequest {
            id: args.id.clone(),
            sandbox_port: u32::from(args.port),
            protocol: protocol.into(),
            ..Default::default()
        })
        .await
        .context("Failed to unexpose sandbox port")?;
    println!("{}:{}/{} unexposed", args.id, args.port, args.protocol);
    Ok(())
}
