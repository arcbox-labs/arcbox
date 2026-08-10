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
    /// Manage the template catalog (build, publish, list, inspect, delete)
    #[command(subcommand)]
    Template(TemplateCommands),
    /// List built-in Dockerfile presets (see `create --from-preset`)
    Presets(TemplatesArgs),
}

#[derive(Subcommand)]
pub enum TemplateCommands {
    /// Build a template from a source and register it as the catalog draft
    Build(TemplateBuildArgs),
    /// Freeze the template's draft as an immutable version
    Publish(TemplatePublishArgs),
    /// Resolve a `name[:version]` reference and show the template
    #[command(alias = "inspect")]
    Get(TemplateGetArgs),
    /// List catalog templates
    #[command(name = "ls", alias = "list")]
    List(TemplateListArgs),
    /// Delete a template version, or a whole template with its artifacts
    #[command(alias = "rm")]
    Delete(TemplateDeleteArgs),
}

#[derive(Args)]
pub struct TemplateBuildArgs {
    /// Template name to register the result under
    pub name: String,
    /// Build from a local Docker image reference
    #[arg(long, conflicts_with_all = ["from_dockerfile", "from_snapshot"])]
    pub from_image: Option<String>,
    /// Build from a Dockerfile (path; the build context is the file alone)
    #[arg(long, conflicts_with_all = ["from_image", "from_snapshot"])]
    pub from_dockerfile: Option<String>,
    /// Promote an existing checkpoint into the template's warm snapshot
    #[arg(long, conflicts_with_all = ["from_image", "from_dockerfile"])]
    pub from_snapshot: Option<String>,
    /// Also boot once and checkpoint at READY (ignored for --from-snapshot)
    #[arg(long)]
    pub prewarm: bool,
    /// Default vCPUs for sandboxes created from this template (0 = daemon default)
    #[arg(long, default_value = "0")]
    pub cpus: u32,
    /// Default memory in MiB (0 = daemon default)
    #[arg(long, default_value = "0")]
    pub memory: u64,
    /// Template labels (key=value, repeatable)
    #[arg(long = "label")]
    pub labels: Vec<String>,
    /// Emit the result as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Args)]
#[command(disable_version_flag = true)]
pub struct TemplatePublishArgs {
    /// Template name
    pub name: String,
    /// Version to freeze the draft as (e.g. "1.2.0")
    pub version: String,
    /// Emit the result as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Args)]
pub struct TemplateGetArgs {
    /// `name` or `name:version`
    pub reference: String,
    /// Emit the result as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Args)]
pub struct TemplateListArgs {
    /// Emit the result as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Args)]
pub struct TemplateDeleteArgs {
    /// `name` (all versions + draft) or `name:version` (one version)
    pub reference: String,
}

#[derive(Args)]
pub struct CreateArgs {
    /// Caller-supplied sandbox ID (empty = auto-generated)
    #[arg(long)]
    pub id: Option<String>,
    /// Build the sandbox image from a Dockerfile
    #[arg(long, conflicts_with_all = ["from_image", "from_preset", "template"])]
    pub from_dockerfile: Option<String>,
    /// Use an existing Docker image as the sandbox image
    #[arg(long, conflicts_with_all = ["from_dockerfile", "from_preset", "template"])]
    pub from_image: Option<String>,
    /// Use a built-in Dockerfile preset as the sandbox image (see `sandbox presets`)
    #[arg(long, conflicts_with_all = ["from_dockerfile", "from_image", "template"])]
    pub from_preset: Option<String>,
    /// Create from a catalog template: `name[:version]` (see `sandbox template ls`)
    #[arg(long, conflicts_with_all = ["from_dockerfile", "from_image", "from_preset"])]
    pub template: Option<String>,
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
        SandboxCommands::Template(cmd) => execute_template(cmd).await,
        SandboxCommands::Presets(args) => execute_templates(args),
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

async fn execute_template(cmd: TemplateCommands) -> Result<()> {
    let (transport, config) = sandbox_channel();
    let client = pb::TemplateServiceClient::new(transport, config);
    match cmd {
        TemplateCommands::Build(args) => {
            let request = template_build_request(&args)?;
            let template = client
                .build(request)
                .await
                .with_context(|| format!("failed to build template '{}'", args.name))?
                .into_owned();
            print_template(&template, args.json)
        }
        TemplateCommands::Publish(args) => {
            let template = client
                .publish(pb::PublishTemplateRequest {
                    name: args.name.clone(),
                    version: args.version.clone(),
                    ..Default::default()
                })
                .await
                .with_context(|| format!("failed to publish '{}:{}'", args.name, args.version))?
                .into_owned();
            print_template(&template, args.json)
        }
        TemplateCommands::Get(args) => {
            let template = client
                .get(pb::GetTemplateRequest {
                    reference: args.reference.clone(),
                    ..Default::default()
                })
                .await
                .with_context(|| format!("failed to resolve template '{}'", args.reference))?
                .into_owned();
            print_template(&template, args.json)
        }
        TemplateCommands::List(args) => {
            let templates = drain_pages(|page_token| {
                let client = &client;
                async move {
                    let resp = client
                        .list(pb::ListTemplatesRequest {
                            page_token,
                            ..Default::default()
                        })
                        .await
                        .context("failed to list templates")?
                        .into_owned();
                    Ok((resp.templates, resp.next_page_token))
                }
            })
            .await?;
            if args.json {
                let rows: Vec<_> = templates.iter().map(template_json).collect();
                println!("{}", serde_json::to_string_pretty(&rows)?);
                return Ok(());
            }
            if templates.is_empty() {
                println!("No templates found.");
                return Ok(());
            }
            println!(
                "{:<24} {:<12} {:<8} {:<12} DIGEST",
                "NAME", "VERSION", "WARM", "SIZE"
            );
            for t in &templates {
                let version = if t.version.is_empty() {
                    "(draft)"
                } else {
                    &t.version
                };
                println!(
                    "{:<24} {:<12} {:<8} {:<12} {}",
                    t.name,
                    version,
                    if t.warm_snapshot_id.is_empty() {
                        "-"
                    } else {
                        "yes"
                    },
                    super::top::fmt_bytes(t.size_bytes),
                    t.digest,
                );
            }
            Ok(())
        }
        TemplateCommands::Delete(args) => {
            client
                .delete(pb::DeleteTemplateRequest {
                    reference: args.reference.clone(),
                    ..Default::default()
                })
                .await
                .with_context(|| format!("failed to delete template '{}'", args.reference))?;
            println!("Deleted template {}", args.reference);
            Ok(())
        }
    }
}

/// Resolve `template build` flags into the request: source selection,
/// defaults presence (absent unless a geometry flag was given), labels.
fn template_build_request(args: &TemplateBuildArgs) -> Result<pb::BuildTemplateRequest> {
    let source = if let Some(image) = &args.from_image {
        pb::build_template_request::Source::DockerRef(image.clone())
    } else if let Some(path) = &args.from_dockerfile {
        let contents =
            std::fs::read_to_string(path).with_context(|| format!("failed to read {path}"))?;
        pb::build_template_request::Source::Dockerfile(contents)
    } else if let Some(snapshot_id) = &args.from_snapshot {
        pb::build_template_request::Source::SnapshotId(snapshot_id.clone())
    } else {
        anyhow::bail!(
            "a build source is required: --from-image, --from-dockerfile, or --from-snapshot"
        );
    };
    let defaults = (args.cpus != 0 || args.memory != 0).then(|| pb::TemplateDefaults {
        limits: Some(pb::ResourceLimits {
            vcpus: args.cpus,
            memory_mib: args.memory,
            ..Default::default()
        })
        .into(),
        ..Default::default()
    });
    Ok(pb::BuildTemplateRequest {
        name: args.name.clone(),
        source: Some(source),
        defaults: defaults.into(),
        labels: parse_labels(&args.labels)?.into_iter().collect(),
        prewarm: args.prewarm,
        ..Default::default()
    })
}

/// Drain every continuation page so the human view stays complete. `fetch`
/// receives the page token ("" first) and returns one page plus the next
/// token ("" ends the walk).
async fn drain_pages<T, Fut>(mut fetch: impl FnMut(String) -> Fut) -> Result<Vec<T>>
where
    Fut: std::future::Future<Output = Result<(Vec<T>, String)>>,
{
    let mut items = Vec::new();
    let mut page_token = String::new();
    loop {
        let (mut page, next) = fetch(page_token).await?;
        items.append(&mut page);
        if next.is_empty() {
            break;
        }
        page_token = next;
    }
    Ok(items)
}

/// Hand-mapped JSON view (rpc/AGENTS.md: user-facing JSON never comes from
/// generated shapes).
fn template_json(t: &pb::Template) -> serde_json::Value {
    serde_json::json!({
        "name": t.name,
        "version": t.version,
        "digest": t.digest,
        "warm": !t.warm_snapshot_id.is_empty(),
        "size_bytes": t.size_bytes,
        "labels": t.labels.iter().collect::<std::collections::BTreeMap<_, _>>(),
    })
}

fn print_template(t: &pb::Template, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(&template_json(t))?);
        return Ok(());
    }
    let version = if t.version.is_empty() {
        "(draft)"
    } else {
        &t.version
    };
    println!("Name:    {}", t.name);
    println!("Version: {version}");
    println!("Digest:  {}", t.digest);
    println!(
        "Warm:    {}",
        if t.warm_snapshot_id.is_empty() {
            "no"
        } else {
            "yes"
        }
    );
    println!("Size:    {}", super::top::fmt_bytes(t.size_bytes));
    if !t.labels.is_empty() {
        let labels: std::collections::BTreeMap<_, _> = t.labels.iter().collect();
        println!("Labels:  {labels:?}");
    }
    Ok(())
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

/// Assemble the create request. `limits` is present only when a geometry
/// flag was given: an absent field inherits the template's default limits,
/// while a present one — even all-zero — replaces them wholesale
/// (sandbox.proto contract).
fn create_request(
    args: &CreateArgs,
    template: String,
    labels: HashMap<String, String>,
) -> CreateSandboxRequest {
    CreateSandboxRequest {
        id: args.id.clone().unwrap_or_default(),
        labels: labels.into_iter().collect(),
        template,
        limits: (args.cpus != 0 || args.memory != 0)
            .then(|| ResourceLimits {
                vcpus: args.cpus,
                memory_mib: args.memory,
                ..Default::default()
            })
            .into(),
        ttl_seconds: args.ttl,
        ..Default::default()
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
    } else if let Some(name) = &args.from_preset {
        resolve_template(name).await?
    } else if let Some(reference) = &args.template {
        reference.clone()
    } else {
        String::new()
    };

    let resp: pb::CreateSandboxResponse = client
        .create(create_request(&args, template, labels))
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
        .map_err(|error| crate::error::sandbox_request(error, &args.id, "stopping"))?;

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
        .map_err(|error| crate::error::sandbox_request(error, &args.id, "removal"))?;

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
    let sandboxes = drain_pages(|page_token| {
        let client = &client;
        async move {
            let resp: pb::ListSandboxesResponse = client
                .list(ListSandboxesRequest {
                    state: state.into(),
                    page_token,
                    ..Default::default()
                })
                .await
                .context("Failed to list sandboxes")?
                .into_owned();
            Ok((resp.sandboxes, resp.next_page_token))
        }
    })
    .await?;

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
            id: args.id.clone(),
            ..Default::default()
        })
        .await
        .map_err(|error| crate::error::sandbox_request(error, &args.id, "inspection"))?
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
        .map_err(|error| crate::error::sandbox_request(error, &sandbox_id, "command execution"))?;

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
                sandbox_id: sandbox_id.clone(),
                execution_id: execution_id.clone(),
                timeout_seconds: EXEC_WAIT_TIMEOUT_SECS,
                ..Default::default()
            })
            .await
            .map_err(|error| crate::error::execution_wait(error, &sandbox_id, &execution_id))?
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
    let sandbox_id = args.id.unwrap_or_default();
    let mut stream = client
        .events(SandboxEventsRequest {
            sandbox_id: sandbox_id.clone(),
            kind: kind.into(),
            ..Default::default()
        })
        .await
        .map_err(|error| {
            if sandbox_id.is_empty() {
                anyhow::Error::new(error).context("Failed to subscribe to sandbox events")
            } else {
                crate::error::sandbox_request(error, &sandbox_id, "event subscription")
            }
        })?;

    println!("Listening for sandbox events (Ctrl+C to stop)...");
    while let Some(frame) = stream
        .message::<pb::WatchEventsResponse>()
        .await
        .map_err(|error| {
            if sandbox_id.is_empty() {
                anyhow::Error::new(error).context("Failed to read sandbox event")
            } else {
                crate::error::sandbox_request(error, &sandbox_id, "event streaming")
            }
        })?
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
    let id = args.id;

    let resp: pb::CheckpointResponse = client
        .checkpoint(CheckpointRequest {
            sandbox_id: id.clone(),
            name: args.name,
            ..Default::default()
        })
        .await
        .map_err(|error| crate::error::sandbox_request(error, &id, "checkpointing"))?
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

    let snapshot_id = args.snapshot_id;
    let resp: pb::RestoreResponse = client
        .restore(RestoreRequest {
            id: args.sandbox_id.unwrap_or_default(),
            snapshot_id: snapshot_id.clone(),
            ttl_seconds: args.ttl,
            ..Default::default()
        })
        .await
        .map_err(|error| crate::error::snapshot_request(error, &snapshot_id, "restoration"))?
        .into_owned();

    println!("Sandbox restored");
    println!("  ID: {}", resp.id);
    println!("  IP: {}", resp.ip_address);
    Ok(())
}

async fn execute_list_snapshots(args: ListSnapshotsArgs) -> Result<()> {
    let (transport, config) = sandbox_channel();
    let client = SandboxSnapshotServiceClient::new(transport.clone(), config.clone());

    let sandbox_id = args.sandbox_id;
    let snapshots = drain_pages(|page_token| {
        let client = &client;
        let sandbox_id = &sandbox_id;
        async move {
            let resp: pb::ListSnapshotsResponse = client
                .list_snapshots(ListSnapshotsRequest {
                    sandbox_id: sandbox_id.clone().unwrap_or_default(),
                    page_token,
                    ..Default::default()
                })
                .await
                .map_err(|error| match sandbox_id.as_deref() {
                    Some(id) => crate::error::sandbox_request(error, id, "snapshot listing"),
                    None => anyhow::Error::new(error).context("Failed to list snapshots"),
                })?
                .into_owned();
            Ok((resp.snapshots, resp.next_page_token))
        }
    })
    .await?;

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
        .map_err(|error| crate::error::snapshot_request(error, &args.snapshot_id, "deletion"))?;

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
                    id: id.clone(),
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
                .map_err(|error| {
                    crate::error::sandbox_request(error, &id, "copying a file into it")
                })?;
            println!("Copied {total} bytes to {}", args.dst);
        }
        (CpEndpoint::Sandbox { id, path }, CpEndpoint::Local(dst)) => {
            let mut stream = client
                .read_file(ReadFileRequest {
                    id: id.clone(),
                    path,
                    ..Default::default()
                })
                .await
                .map_err(|error| {
                    crate::error::sandbox_request(error, &id, "copying a file from it")
                })?;

            let mut out = tokio::fs::File::create(&dst)
                .await
                .with_context(|| format!("Failed to create {dst}"))?;
            let mut total = 0usize;
            while let Some(chunk) = stream
                .message::<pb::FileChunk>()
                .await
                .map_err(|error| {
                    crate::error::sandbox_request(error, &id, "copying a file from it")
                })?
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
        .map_err(|error| crate::error::sandbox_request(error, &args.id, "port exposure"))?
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
        .map_err(|error| crate::error::sandbox_request(error, &args.id, "port removal"))?;
    println!("{}:{}/{} unexposed", args.id, args.port, args.protocol);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_args() -> TemplateBuildArgs {
        TemplateBuildArgs {
            name: "web".into(),
            from_image: None,
            from_dockerfile: None,
            from_snapshot: None,
            prewarm: false,
            cpus: 0,
            memory: 0,
            labels: Vec::new(),
            json: false,
        }
    }

    fn create_args() -> CreateArgs {
        CreateArgs {
            id: None,
            from_dockerfile: None,
            from_image: None,
            from_preset: None,
            template: None,
            cpus: 0,
            memory: 0,
            label: Vec::new(),
            ttl: 0,
        }
    }

    #[test]
    fn build_request_maps_each_source_flag() {
        let req = template_build_request(&TemplateBuildArgs {
            from_image: Some("alpine:3.20".into()),
            ..build_args()
        })
        .unwrap();
        match req.source {
            Some(pb::build_template_request::Source::DockerRef(ref image)) => {
                assert_eq!(image, "alpine:3.20");
            }
            _ => panic!("expected a DockerRef source"),
        }
        assert_eq!(req.name, "web");

        let req = template_build_request(&TemplateBuildArgs {
            from_snapshot: Some("snap-1".into()),
            ..build_args()
        })
        .unwrap();
        match req.source {
            Some(pb::build_template_request::Source::SnapshotId(ref id)) => {
                assert_eq!(id, "snap-1");
            }
            _ => panic!("expected a SnapshotId source"),
        }
    }

    #[test]
    fn build_request_reads_the_dockerfile() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Dockerfile");
        std::fs::write(&path, "FROM alpine\n").unwrap();
        let req = template_build_request(&TemplateBuildArgs {
            from_dockerfile: Some(path.to_string_lossy().into_owned()),
            ..build_args()
        })
        .unwrap();
        match req.source {
            Some(pb::build_template_request::Source::Dockerfile(ref contents)) => {
                assert_eq!(contents, "FROM alpine\n");
            }
            _ => panic!("expected a Dockerfile source"),
        }
    }

    #[test]
    fn build_request_requires_a_source() {
        let err = template_build_request(&build_args()).unwrap_err();
        assert!(err.to_string().contains("--from-image"), "{err}");
    }

    #[test]
    fn build_defaults_are_present_only_with_a_geometry_flag() {
        let req = template_build_request(&TemplateBuildArgs {
            from_image: Some("alpine".into()),
            ..build_args()
        })
        .unwrap();
        assert!(req.defaults.as_option().is_none());

        let req = template_build_request(&TemplateBuildArgs {
            from_image: Some("alpine".into()),
            memory: 512,
            ..build_args()
        })
        .unwrap();
        let defaults = req.defaults.as_option().expect("defaults present");
        let limits = defaults.limits.as_option().expect("limits present");
        assert_eq!(limits.vcpus, 0);
        assert_eq!(limits.memory_mib, 512);
    }

    #[test]
    fn create_without_geometry_flags_leaves_limits_absent() {
        let req = create_request(&create_args(), "web:1".into(), HashMap::new());
        assert!(
            req.limits.as_option().is_none(),
            "a present limits field would discard the template's default geometry"
        );
        assert_eq!(req.template, "web:1");
    }

    #[test]
    fn create_with_a_geometry_flag_replaces_limits_wholesale() {
        let req = create_request(
            &CreateArgs {
                cpus: 2,
                ..create_args()
            },
            String::new(),
            HashMap::new(),
        );
        let limits = req.limits.as_option().expect("limits present");
        assert_eq!(limits.vcpus, 2);
        assert_eq!(limits.memory_mib, 0);
    }

    #[tokio::test]
    async fn drain_pages_follows_continuation_tokens() {
        let mut calls = Vec::new();
        let items = drain_pages(|token| {
            calls.push(token.clone());
            let page = match token.as_str() {
                "" => (vec![1, 2], "next".to_string()),
                "next" => (vec![3], String::new()),
                other => panic!("unexpected token {other}"),
            };
            async move { Ok(page) }
        })
        .await
        .unwrap();
        assert_eq!(items, vec![1, 2, 3]);
        assert_eq!(calls, vec!["", "next"]);
    }

    #[tokio::test]
    async fn drain_pages_propagates_a_page_error() {
        let result: Result<Vec<u32>> = drain_pages(|_| async { anyhow::bail!("boom") }).await;
        assert!(result.unwrap_err().to_string().contains("boom"));
    }

    #[test]
    fn template_json_is_the_stable_hand_mapped_shape() {
        let template = pb::Template {
            name: "web".into(),
            version: "1.0".into(),
            digest: "sha256:abc".into(),
            warm_snapshot_id: "snap-1".into(),
            size_bytes: 42,
            labels: std::iter::once(("team".to_string(), "infra".to_string())).collect(),
            ..Default::default()
        };
        assert_eq!(
            template_json(&template),
            serde_json::json!({
                "name": "web",
                "version": "1.0",
                "digest": "sha256:abc",
                "warm": true,
                "size_bytes": 42,
                "labels": {"team": "infra"},
            })
        );
    }
}
