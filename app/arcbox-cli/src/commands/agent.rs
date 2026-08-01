//! Coding-agent sessions inside a sandbox.
//!
//! `abctl claude` builds (or reuses) a sandbox from a built-in template and
//! attaches the terminal to the agent's TUI, so the agent runs with its
//! permission prompts switched off and the microVM is the isolation boundary.
//!
//! `/workspace` starts empty: the agent brings code in itself (`git clone`)
//! and results come back out with `abctl sandbox cp`. Nothing on the host is
//! mounted into the sandbox.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use arcbox_grpc::SandboxServiceClient;
use arcbox_protocol::sandbox_v1::{
    CreateSandboxRequest, InspectSandboxRequest, RemoveSandboxRequest, ResourceLimits, SandboxInfo,
    SandboxState, StartExecutionRequest,
};
use clap::Args;
use tonic::transport::Channel;

use super::sandbox::{attach_machine, current_tty_size, exec_session, sandbox_channel};

/// How long to wait for a freshly created sandbox to become ready.
///
/// Boot itself is about a second; the ceiling covers the guest-side ext4
/// conversion on first use of a new image.
const READY_TIMEOUT: Duration = Duration::from_secs(120);

/// Poll interval while waiting for readiness.
const READY_POLL: Duration = Duration::from_millis(250);

/// Host environment variables always forwarded, regardless of agent.
const PASSTHROUGH_ENV: &[&str] = &["TERM", "LANG"];

/// A coding agent that can be run in a sandbox.
pub struct AgentDef {
    /// Display name, also used as the `arcbox.agent` label value.
    pub name: &'static str,
    /// Default sandbox id, reused across invocations.
    pub sandbox_id: &'static str,
    /// Built-in template providing the image.
    pub template: &'static str,
    /// Executable to run inside the sandbox.
    pub command: &'static str,
    /// Argument that turns off the agent's own permission prompting.
    pub bypass_flag: &'static str,
    /// Host env vars with these prefixes are forwarded into the session.
    pub env_prefixes: &'static [&'static str],
    /// At least one of these must be set, or there is no point starting.
    pub required_env: &'static [&'static str],
    /// Non-root user inside the image.
    pub user: &'static str,
    /// Working directory for the session.
    pub workdir: &'static str,
    /// Environment the session cannot do without.
    ///
    /// Only the image's filesystem is converted into the sandbox rootfs, so
    /// its `ENV` never reaches the process: `vm-agent` runs as PID 1 with the
    /// kernel's environment (`HOME=/`, `TERM=linux`) plus whatever the caller
    /// sends. That makes `PATH` and `HOME` this layer's responsibility —
    /// without `PATH`, `execvp` falls back to `/bin:/usr/bin` and cannot find
    /// an npm-installed CLI in `/usr/local/bin`; without a writable `HOME`,
    /// the agent cannot store its own state.
    pub base_env: &'static [(&'static str, &'static str)],
}

/// Claude Code.
pub const CLAUDE: AgentDef = AgentDef {
    name: "claude",
    sandbox_id: "agent-claude",
    template: "claude",
    command: "claude",
    bypass_flag: "--dangerously-skip-permissions",
    env_prefixes: &["ANTHROPIC_", "CLAUDE_"],
    required_env: &["ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"],
    // The node images ship this uid-1000 user; the template gives it
    // /workspace.
    user: "node",
    workdir: "/workspace",
    base_env: &[
        (
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        ),
        ("HOME", "/home/node"),
    ],
};

#[derive(Args)]
pub struct AgentArgs {
    /// Sandbox ID to use (default: one shared sandbox per agent)
    #[arg(long)]
    pub id: Option<String>,
    /// Number of vCPUs
    #[arg(long, default_value = "2")]
    pub cpus: u32,
    /// Memory in MiB
    #[arg(long, default_value = "2048")]
    pub memory: u64,
    /// Keep the agent's permission prompts instead of skipping them
    #[arg(long)]
    pub no_bypass: bool,
    /// Extra arguments passed through to the agent
    #[arg(trailing_var_arg = true)]
    pub args: Vec<String>,
}

/// What to do with a sandbox before attaching to it.
#[derive(Debug, PartialEq, Eq)]
enum Action {
    /// No sandbox yet.
    Create,
    /// Ready and idle — attach directly.
    Attach,
    /// Booting; wait for it.
    WaitReady,
    /// Dead or half-dead; its `/workspace` is already gone, so start over.
    Recreate,
    /// In use or in a state we should not silently destroy.
    Refuse,
}

/// Decide how to reach a usable sandbox from its current state.
fn plan_action(state: Option<SandboxState>) -> Action {
    match state {
        None => Action::Create,
        Some(SandboxState::Ready) => Action::Attach,
        Some(SandboxState::Starting) => Action::WaitReady,
        // `Stop` tears down the CoW overlay, so a stopped sandbox has lost
        // everything under /workspace and is only a name.
        Some(SandboxState::Stopped | SandboxState::Failed) => Action::Recreate,
        // RUNNING means a workload already holds the sandbox; anything else
        // is a state this build does not know about.
        Some(_) => Action::Refuse,
    }
}

/// Collect the environment to forward into the session.
///
/// Credentials are passed per-session rather than written into the image or
/// the sandbox record, so nothing persists them.
fn collect_env<I>(def: &AgentDef, host_vars: I) -> Result<HashMap<String, String>>
where
    I: IntoIterator<Item = (String, String)>,
{
    let mut env: HashMap<String, String> = def
        .base_env
        .iter()
        .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
        .collect();

    for (key, value) in host_vars {
        let forward = PASSTHROUGH_ENV.contains(&key.as_str())
            || def
                .env_prefixes
                .iter()
                .any(|prefix| key.starts_with(prefix));
        if forward && !value.is_empty() {
            env.insert(key, value);
        }
    }

    if !def.required_env.iter().any(|key| env.contains_key(*key)) {
        bail!(
            "no credentials for {}: set {} in your shell first — it is forwarded \
             into the sandbox for this session only",
            def.name,
            def.required_env.join(" or ")
        );
    }

    Ok(env)
}

/// Run an agent session, creating or reusing its sandbox as needed.
pub async fn execute(def: &AgentDef, args: AgentArgs) -> Result<()> {
    let id = args.id.unwrap_or_else(|| def.sandbox_id.to_string());
    // Fail before any image work if the credentials are not there.
    let env = collect_env(def, std::env::vars())?;

    let channel = sandbox_channel().await?;
    let mut client = SandboxServiceClient::new(channel.clone());

    let existing = inspect(&mut client, &id).await?;
    match plan_action(existing.as_ref().map(SandboxInfo::state)) {
        Action::Attach => {}
        Action::WaitReady => wait_ready(&mut client, &id).await?,
        Action::Refuse => {
            let state = existing.map_or("unknown", |info| super::sandbox::state_name(info.state()));
            bail!(
                "sandbox '{id}' is {state} — a session may already be active. \
                 Use --id <name> for a second one, or remove it with \
                 `abctl sandbox rm {id}`"
            );
        }
        Action::Recreate => {
            remove(&mut client, &id).await?;
            create(&mut client, def, &id, args.cpus, args.memory).await?;
            wait_ready(&mut client, &id).await?;
        }
        Action::Create => {
            create(&mut client, def, &id, args.cpus, args.memory).await?;
            wait_ready(&mut client, &id).await?;
        }
    }

    let mut cmd = vec![def.command.to_string()];
    if !args.no_bypass {
        cmd.push(def.bypass_flag.to_string());
    }
    cmd.extend(args.args);

    let start = StartExecutionRequest {
        sandbox_id: id.clone(),
        cmd,
        env,
        working_dir: def.workdir.to_string(),
        user: def.user.to_string(),
        tty: true,
        tty_size: current_tty_size(true),
        stdin: true,
        ..Default::default()
    };

    let exit_code = exec_session(channel, start).await?;

    eprintln!(
        "\nSandbox '{id}' is still running: reopen with `abctl {}`, copy work out with \
         `abctl sandbox cp {id}:{}/<file> .`, or discard it with `abctl sandbox rm {id}`.\n\
         Removing or stopping the sandbox destroys everything in {}.",
        def.name, def.workdir, def.workdir
    );

    if exit_code != 0 {
        std::process::exit(exit_code);
    }
    Ok(())
}

/// Fetch a sandbox, or `None` when it does not exist.
async fn inspect(
    client: &mut SandboxServiceClient<Channel>,
    id: &str,
) -> Result<Option<SandboxInfo>> {
    let request = attach_machine(tonic::Request::new(InspectSandboxRequest {
        id: id.to_string(),
    }));
    match client.inspect(request).await {
        Ok(response) => Ok(Some(response.into_inner())),
        Err(status) if status.code() == tonic::Code::NotFound => Ok(None),
        Err(status) => Err(status).context("Failed to inspect sandbox")?,
    }
}

/// Remove a sandbox that cannot be reused.
async fn remove(client: &mut SandboxServiceClient<Channel>, id: &str) -> Result<()> {
    let request = attach_machine(tonic::Request::new(RemoveSandboxRequest {
        id: id.to_string(),
        force: true,
    }));
    client
        .remove(request)
        .await
        .context("Failed to remove the previous sandbox")?;
    Ok(())
}

/// Build the agent image if needed and create the sandbox.
async fn create(
    client: &mut SandboxServiceClient<Channel>,
    def: &AgentDef,
    id: &str,
    vcpus: u32,
    memory_mib: u64,
) -> Result<()> {
    let template = super::sandbox::resolve_template(def.template).await?;

    let request = attach_machine(tonic::Request::new(CreateSandboxRequest {
        id: id.to_string(),
        labels: HashMap::from([("arcbox.agent".to_string(), def.name.to_string())]),
        template,
        limits: Some(ResourceLimits { vcpus, memory_mib }),
        // No TTL: expiry would take /workspace with it mid-session.
        ttl_seconds: 0,
        ..Default::default()
    }));
    client
        .create(request)
        .await
        .context("Failed to create the agent sandbox")?;
    Ok(())
}

/// Block until the sandbox reports `ready`.
async fn wait_ready(client: &mut SandboxServiceClient<Channel>, id: &str) -> Result<()> {
    let deadline = tokio::time::Instant::now() + READY_TIMEOUT;
    loop {
        match inspect(client, id).await? {
            Some(info) if info.state() == SandboxState::Ready => return Ok(()),
            Some(info) if info.state() == SandboxState::Failed => {
                let detail = if info.error.is_empty() {
                    "no reason reported".to_string()
                } else {
                    info.error
                };
                bail!("sandbox '{id}' failed to start: {detail}");
            }
            Some(_) => {}
            None => bail!("sandbox '{id}' disappeared while starting"),
        }

        if tokio::time::Instant::now() >= deadline {
            bail!(
                "sandbox '{id}' was not ready within {}s",
                READY_TIMEOUT.as_secs()
            );
        }
        tokio::time::sleep(READY_POLL).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn collect_env_forwards_prefixed_and_passthrough_vars() {
        let env = collect_env(
            &CLAUDE,
            vars(&[
                ("ANTHROPIC_API_KEY", "key"),
                ("CLAUDE_CODE_EXTRA", "1"),
                ("TERM", "xterm-256color"),
                ("AWS_SECRET_ACCESS_KEY", "nope"),
                ("PATH", "/usr/bin"),
            ]),
        )
        .unwrap();

        assert_eq!(env.get("ANTHROPIC_API_KEY").unwrap(), "key");
        assert_eq!(env.get("CLAUDE_CODE_EXTRA").unwrap(), "1");
        assert_eq!(env.get("TERM").unwrap(), "xterm-256color");
        // Without these the session cannot start at all: execvp would miss
        // /usr/local/bin, and HOME would be the unwritable kernel default.
        assert!(env.get("PATH").unwrap().contains("/usr/local/bin"));
        assert_eq!(env.get("HOME").unwrap(), "/home/node");
        // Unrelated host secrets must not leak into the sandbox.
        assert!(!env.contains_key("AWS_SECRET_ACCESS_KEY"));
        // The host's own PATH is a macOS path list and must not win over the
        // sandbox one.
        assert_ne!(env.get("PATH").unwrap(), "/usr/bin");
    }

    #[test]
    fn collect_env_accepts_any_required_key() {
        let env = collect_env(&CLAUDE, vars(&[("ANTHROPIC_AUTH_TOKEN", "token")])).unwrap();
        assert_eq!(env.get("ANTHROPIC_AUTH_TOKEN").unwrap(), "token");
    }

    #[test]
    fn collect_env_requires_credentials() {
        // Nothing set at all.
        let error = collect_env(&CLAUDE, vars(&[("TERM", "xterm")])).unwrap_err();
        assert!(error.to_string().contains("ANTHROPIC_API_KEY"));

        // Set but empty is the same as unset — a common shell footgun.
        let error = collect_env(&CLAUDE, vars(&[("ANTHROPIC_API_KEY", "")])).unwrap_err();
        assert!(error.to_string().contains("no credentials"));
    }

    #[test]
    fn plan_action_maps_every_sandbox_state() {
        assert_eq!(plan_action(None), Action::Create);
        assert_eq!(plan_action(Some(SandboxState::Ready)), Action::Attach);
        assert_eq!(plan_action(Some(SandboxState::Starting)), Action::WaitReady);
        assert_eq!(plan_action(Some(SandboxState::Stopped)), Action::Recreate);
        assert_eq!(plan_action(Some(SandboxState::Failed)), Action::Recreate);
        // A live workload holds the sandbox; never destroy it from under one.
        assert_eq!(plan_action(Some(SandboxState::Running)), Action::Refuse);
        assert_eq!(plan_action(Some(SandboxState::Stopping)), Action::Refuse);
        assert_eq!(plan_action(Some(SandboxState::Unspecified)), Action::Refuse);
    }
}
