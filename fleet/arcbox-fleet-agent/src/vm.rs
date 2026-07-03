//! macOS VM-based execution of darwin runner jobs.
//!
//! Each accepted darwin job boots a disposable macOS guest through the local
//! `arcbox-daemon` (its `MacosService` gRPC on the daemon socket), then runs
//! the Actions runner **baked into the base image** over SSH:
//!
//! 1. copy-on-write clone + boot (`Create`/`Start` — the daemon enforces the
//!    two-guests-per-host Apple license cap, so a `Start` failure is an
//!    admission signal, not a fault),
//! 2. resolve the guest address (`Inspect` reports its DHCP lease),
//! 3. `ssh admin@guest run.sh --jitconfig …` — the session's exit is the
//!    job's completion,
//! 4. `Remove(force)` — destroying the guest is teardown *and* cancellation;
//!    there is no in-guest process management.
//!
//! The guest contract is the ArcBox macOS runner image
//! (`macos-runner-image-builder`): runner preinstalled at
//! [`GUEST_RUNNER_SCRIPT`], SSH login `admin`/`admin` — a deliberate,
//! documented choice for disposable CI guests, which are reachable only from
//! their own host over vmnet NAT. Password auth is why SSH goes through
//! `russh` rather than the OpenSSH binary (which cannot take a password
//! non-interactively).

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use arcbox_grpc::MacosServiceClient;
use arcbox_protocol::v1::{
    CreateMacosMachineRequest, Empty, InspectMacosMachineRequest, MacosImageSummary,
    RemoveMacosMachineRequest, StartMacosMachineRequest,
};
use russh::client::{Config as SshConfig, Handle as SshHandle};
use russh::{ChannelMsg, Disconnect};
use tonic::transport::Channel;
use tracing::{debug, info, warn};

use crate::host;

/// Guest login and runner location — the ArcBox macOS runner image contract
/// (see the module doc).
const GUEST_SSH_USER: &str = "admin";
const GUEST_SSH_PASSWORD: &str = "admin";
const GUEST_RUNNER_SCRIPT: &str = "/Users/admin/actions-runner/run.sh";
const SSH_PORT: u16 = 22;

/// Budget for a freshly started guest to acquire its DHCP lease and answer
/// SSH. First boots take minutes; the DHCP lease appears well before
/// login-dependent services, so one budget spans both waits.
const GUEST_READY_BUDGET: Duration = Duration::from_secs(300);
const READY_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Deterministic per-job guest name, so redeliveries and interrupted
/// startups can always find (and remove) whatever an earlier attempt
/// created — and a crashed agent's leftovers are recognizable at startup.
fn machine_name(job_id: &str) -> String {
    format!("fleet-{job_id}")
}

/// Everything the VM runner needs to execute one job.
pub struct RunSpec<'a> {
    /// Job identifier, used as the guest name suffix.
    pub job_id: &'a str,
    /// Base64-encoded JIT runner config, passed through to `run.sh`.
    pub encoded_jit_config: &'a str,
    /// Base image the guest boots from — the live-settable
    /// `macos_runner_image`, read fresh by the caller for each job.
    pub runner_image: &'a str,
}

/// The stream part of an image reference: `"tahoe-base@2026.07.02"` →
/// `"tahoe-base"`. Installed images are registered under their stream name.
fn stream_name(reference: &str) -> &str {
    reference.split_once('@').map_or(reference, |(s, _)| s)
}

/// Runs darwin jobs in disposable macOS guests via the local arcbox-daemon.
#[derive(Clone)]
pub struct VmRunner {
    client: MacosServiceClient<Channel>,
}

impl VmRunner {
    /// Connect to the daemon socket and prove it can serve VM jobs: its
    /// `MacosService` must answer, and `default_image` must be installed.
    /// Also sweeps `fleet-*` guests left behind by a crashed agent.
    ///
    /// `default_image` is a readiness parameter, not stored: live jobs use
    /// whatever `macos_runner_image` is current at dispatch time
    /// ([`RunSpec::runner_image`]).
    pub async fn new(daemon_socket: &Path, default_image: &str) -> Result<Self> {
        let channel = crate::control::client::connect(daemon_socket).await?;
        let mut client = MacosServiceClient::new(channel);

        // One call proves the daemon is up *and* speaks MacosService (an
        // older daemon without it answers Unimplemented), and provides the
        // installed-image check.
        let images = client
            .image_list(Empty {})
            .await
            .context("daemon does not serve macOS guests (MacosService.ImageList failed)")?
            .into_inner()
            .images;
        if !images.iter().any(|i| i.name == stream_name(default_image)) {
            bail!(
                "macOS runner image '{default_image}' is not installed in the daemon — \
                 run `arcbox-fleet-agent prepare macos-runner-image` (or `arcbox macos \
                 image pull {default_image}`) first"
            );
        }

        let runner = Self { client };
        runner.sweep_leftovers().await;
        info!(image = default_image, "macOS VM backend available");
        Ok(runner)
    }

    /// Force-remove every `fleet-*` guest. Only this agent creates such
    /// names (the control socket is a per-host singleton), so anything
    /// matching is an orphan from a previous process.
    async fn sweep_leftovers(&self) {
        let mut client = self.client.clone();
        let machines = match client.list(Empty {}).await {
            Ok(response) => response.into_inner().machines,
            Err(e) => {
                warn!(error = %e, "listing leftover fleet guests failed");
                return;
            }
        };
        for machine in machines {
            if machine.name.starts_with("fleet-") {
                warn!(name = %machine.name, "removing leftover fleet guest");
                remove_vm(&mut client, &machine.name).await;
            }
        }
    }

    /// Force-remove the guest named for `job_id`, if any — awaited and
    /// idempotent. Remove-before-bind ahead of a create, and the cleanup
    /// when cancellation interrupts [`start`](Self::start) mid-flight.
    pub async fn remove_job_vm(&self, job_id: &str) {
        let mut client = self.client.clone();
        remove_vm(&mut client, &machine_name(job_id)).await;
    }

    /// Pull `reference` through the daemon, returning its progress stream
    /// (terminal event: stage `"done"`). `FleetImageService.Prepare` drives
    /// this to converge `macos_runner_image` onto its target; a pull the
    /// daemon already has registered completes immediately, so
    /// re-preparation is cheap when nothing changed.
    pub async fn pull(
        &self,
        reference: &str,
    ) -> Result<tonic::Streaming<arcbox_protocol::v1::MacosImagePullEvent>> {
        let mut client = self.client.clone();
        let stream = client
            .image_pull(arcbox_protocol::v1::MacosImagePullRequest {
                reference: reference.to_owned(),
                manifest_url: String::new(),
            })
            .await
            .with_context(|| format!("pulling macOS image '{reference}' through the daemon"))?;
        Ok(stream.into_inner())
    }

    /// Provision a guest for `spec` and start the runner in it, returning a
    /// handle to await. Returning `Ok` means the runner command has been
    /// issued over SSH — the caller can then accept the offer. Any failure
    /// up to there is an error so the caller rejects and the platform
    /// re-offers (a `Start` refused by the daemon's two-guest cap lands
    /// here too). On error nothing is left behind; on a dropped future the
    /// caller owns cleanup via [`Self::remove_job_vm`] (the returned
    /// handle's guard covers only post-return panics).
    pub async fn start(&self, spec: RunSpec<'_>) -> Result<RunningVm> {
        // Base64 is shell-quote-safe; anything else never reaches the guest.
        if spec.encoded_jit_config.contains('\'') {
            bail!("encoded JIT config contains a quote — not a base64 payload");
        }
        let command = format!(
            "{GUEST_RUNNER_SCRIPT} --jitconfig '{}'",
            spec.encoded_jit_config
        );
        self.start_with_command(&spec, &command).await
    }

    /// [`start`](Self::start) with the guest command explicit, so the
    /// daemon-backed integration test below can exercise the full
    /// provision→ssh→exec→destroy cycle without a real runner invocation.
    async fn start_with_command(&self, spec: &RunSpec<'_>, command: &str) -> Result<RunningVm> {
        let name = machine_name(spec.job_id);
        let mut client = self.client.clone();

        // The name is deterministic per job, so a redelivery after a crash
        // that left an orphan would otherwise collide on create.
        remove_vm(&mut client, &name).await;

        let image = self.installed_image(spec.runner_image).await?;
        let (cpus, memory_mib) = guest_size(&image, host::cpu_cores(), host::mem_mib());
        client
            .create(CreateMacosMachineRequest {
                name: name.clone(),
                image: image.name.clone(),
                cpus,
                memory_mib,
            })
            .await
            .context("creating macOS guest")?;

        // Everything from here on owns a guest; tear it down on any error.
        let provisioned = async {
            client
                .start(StartMacosMachineRequest { name: name.clone() })
                .await
                .context("starting macOS guest (a two-guest license-cap refusal lands here)")?;

            let deadline = tokio::time::Instant::now() + GUEST_READY_BUDGET;
            let ip = self.await_ip(&name, deadline).await?;
            let ssh = connect_ssh(&ip, deadline).await?;

            let channel = ssh
                .channel_open_session()
                .await
                .context("opening SSH session channel")?;
            channel
                .exec(true, command)
                .await
                .context("starting the runner over SSH")?;
            info!(job_id = spec.job_id, guest = %name, ip, "runner started (vm)");
            Ok(RunningVm {
                client: client.clone(),
                guard: VmGuard::new(client.clone(), name.clone()),
                name: name.clone(),
                ssh,
                channel,
            })
        }
        .await;

        if provisioned.is_err() {
            remove_vm(&mut client, &name).await;
        }
        provisioned
    }

    /// The installed image `reference` resolves to, with its manifest
    /// minimums. Not being installed is a per-job failure (reject), not a
    /// backend fault: the image may have been removed since the probe.
    async fn installed_image(&self, reference: &str) -> Result<MacosImageSummary> {
        let mut client = self.client.clone();
        let images = client
            .image_list(Empty {})
            .await
            .context("listing daemon macOS images")?
            .into_inner()
            .images;
        images
            .into_iter()
            .find(|i| i.name == stream_name(reference))
            .with_context(|| format!("macOS runner image '{reference}' is not installed"))
    }

    /// Poll `Inspect` until the guest reports its DHCP-lease address.
    async fn await_ip(&self, name: &str, deadline: tokio::time::Instant) -> Result<String> {
        let mut client = self.client.clone();
        loop {
            let info = client
                .inspect(InspectMacosMachineRequest {
                    name: name.to_owned(),
                })
                .await
                .context("inspecting macOS guest")?
                .into_inner();
            if !info.ip_address.is_empty() {
                return Ok(info.ip_address);
            }
            if info.state == "stopped" {
                bail!("macOS guest stopped before acquiring an address");
            }
            if tokio::time::Instant::now() >= deadline {
                bail!(
                    "macOS guest did not acquire an address within {}s",
                    GUEST_READY_BUDGET.as_secs()
                );
            }
            tokio::time::sleep(READY_POLL_INTERVAL).await;
        }
    }
}

/// Guest sizing: all host cores (VZ time-shares them), half the host's
/// memory (at most two guests run concurrently), floored to the image
/// manifest's minimums.
fn guest_size(image: &MacosImageSummary, host_cores: u32, host_mem_mib: u64) -> (u32, u64) {
    let cpus = host_cores.max(u32::try_from(image.minimum_cpu_count).unwrap_or(u32::MAX));
    let memory_mib = (host_mem_mib / 2).max(image.minimum_memory_mib);
    (cpus, memory_mib)
}

/// Retry SSH connect+auth until the guest's sshd answers or the deadline
/// passes. A booting guest refuses connections long after it has an
/// address, so failures here are the wait, not errors.
async fn connect_ssh(ip: &str, deadline: tokio::time::Instant) -> Result<SshHandle<SshClient>> {
    let config = Arc::new(SshConfig {
        // Long-idle sessions are normal (a quiet job step); keepalives
        // detect a wedged guest instead of an inactivity timeout killing
        // healthy sessions.
        keepalive_interval: Some(Duration::from_secs(15)),
        ..SshConfig::default()
    });
    loop {
        match try_ssh(Arc::clone(&config), ip).await {
            Ok(handle) => return Ok(handle),
            Err(e) => {
                if tokio::time::Instant::now() >= deadline {
                    return Err(e).context(format!(
                        "guest sshd did not answer within {}s",
                        GUEST_READY_BUDGET.as_secs()
                    ));
                }
                debug!(ip, error = %e, "guest ssh not ready; retrying");
                tokio::time::sleep(READY_POLL_INTERVAL).await;
            }
        }
    }
}

async fn try_ssh(config: Arc<SshConfig>, ip: &str) -> Result<SshHandle<SshClient>> {
    let mut handle = russh::client::connect(config, (ip, SSH_PORT), SshClient)
        .await
        .context("ssh connect")?;
    let auth = handle
        .authenticate_password(GUEST_SSH_USER, GUEST_SSH_PASSWORD)
        .await
        .context("ssh auth")?;
    if !auth.success() {
        bail!("guest rejected the image-contract ssh credentials");
    }
    Ok(handle)
}

/// Accepts any host key: each guest is freshly cloned (its host keys are
/// meaningless), and the connection never leaves this host's vmnet NAT.
struct SshClient;

impl russh::client::Handler for SshClient {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// A guest whose runner has been started. Held by the caller while the job
/// runs: [`wait`](Self::wait) observes the runner's exit, then
/// [`destroy`](Self::destroy) tears the guest down — awaited, so the
/// caller's bookkeeping settles only after the guest is actually gone. The
/// embedded [`VmGuard`] is a panic safety net, not the teardown path.
pub struct RunningVm {
    client: MacosServiceClient<Channel>,
    guard: VmGuard,
    name: String,
    ssh: SshHandle<SshClient>,
    channel: russh::Channel<russh::client::Msg>,
}

impl RunningVm {
    /// Block until the runner command exits and return its exit status, if
    /// the guest reported one before the session closed. No cleanup —
    /// follow with [`destroy`](Self::destroy). The agent reports no outcome
    /// upstream (the GitHub webhook is authoritative); the code is for
    /// logging.
    pub async fn wait(&mut self) -> Option<u32> {
        let mut code = None;
        while let Some(msg) = self.channel.wait().await {
            match msg {
                // Runner output stays in the disposable guest; nothing to
                // collect here.
                ChannelMsg::Data { .. } | ChannelMsg::ExtendedData { .. } => {}
                ChannelMsg::ExitStatus { exit_status } => code = Some(exit_status),
                _ => {}
            }
        }
        code
    }

    /// Destroy the guest, awaited — the completion, cancellation, and
    /// shutdown teardown alike (removing the VM kills the runner and every
    /// process in it). Once this returns the guest is gone, or its removal
    /// failed loudly in the log.
    pub async fn destroy(self) {
        let Self {
            mut client,
            guard,
            name,
            ssh,
            channel,
        } = self;
        guard.defuse();
        drop(channel);
        let _ = ssh.disconnect(Disconnect::ByApplication, "", "en").await;
        remove_vm(&mut client, &name).await;
    }
}

/// Force-remove a guest, awaited and idempotent: "not found" is the normal
/// no-leftover case, anything else is logged — the job itself already
/// concluded, so removal failures must not fail the caller.
async fn remove_vm(client: &mut MacosServiceClient<Channel>, name: &str) {
    let request = RemoveMacosMachineRequest {
        name: name.to_owned(),
        force: true,
    };
    match client.remove(request).await {
        Ok(_) => {}
        Err(status) if status.code() == tonic::Code::NotFound => {}
        // The daemon maps not-found to Internal today; match on message
        // until it grows structured codes.
        Err(status) if status.message().contains("not found") => {}
        Err(status) => warn!(guest = name, error = %status, "failed to remove macOS guest"),
    }
}

/// Removes the guest on drop — the panic safety net. Every deliberate exit
/// ([`RunningVm::destroy`]) defuses the guard and awaits the teardown
/// itself; this drop path only fires when the runner task dies without
/// reaching one. The spawned cleanup is fire-and-forget by necessity (drop
/// cannot await); it must never be the path a correctness guarantee rides
/// on.
struct VmGuard {
    client: MacosServiceClient<Channel>,
    name: String,
    defused: bool,
}

impl VmGuard {
    fn new(client: MacosServiceClient<Channel>, name: String) -> Self {
        Self {
            client,
            name,
            defused: false,
        }
    }

    /// Disarm the guard after normal completion.
    fn defuse(mut self) {
        self.defused = true;
    }
}

impl Drop for VmGuard {
    fn drop(&mut self) {
        if self.defused {
            return;
        }
        let mut client = self.client.clone();
        let name = std::mem::take(&mut self.name);
        tokio::spawn(async move {
            remove_vm(&mut client, &name).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn machine_names_are_deterministic_and_prefixed() {
        assert_eq!(machine_name("rjob_abc"), "fleet-rjob_abc");
    }

    #[test]
    fn stream_name_strips_pinned_version() {
        assert_eq!(stream_name("tahoe-base"), "tahoe-base");
        assert_eq!(stream_name("tahoe-base@2026.07.02"), "tahoe-base");
    }

    /// Full provision→ssh→exec→destroy cycle against a live daemon.
    /// Requires `arcbox-daemon` running with the default image pulled
    /// (`arcbox macos image pull tahoe-base`); run manually:
    /// `cargo test -p arcbox-fleet-agent vm_round_trip -- --ignored`.
    #[tokio::test]
    #[ignore = "needs a live arcbox-daemon with the tahoe-base image installed"]
    async fn vm_round_trip_boots_and_execs_over_ssh() {
        let socket = arcbox_constants::paths::HostLayout::from_env_or_default().grpc_socket;
        let runner = VmRunner::new(&socket, "tahoe-base")
            .await
            .expect("daemon probe");
        let mut running = runner
            .start_with_command(
                &RunSpec {
                    job_id: "itest",
                    encoded_jit_config: "",
                    runner_image: "tahoe-base",
                },
                "/usr/bin/true",
            )
            .await
            .expect("provision guest and exec");
        assert_eq!(running.wait().await, Some(0));
        running.destroy().await;
    }

    #[test]
    fn guest_size_floors_to_image_minimums() {
        let image = MacosImageSummary {
            minimum_cpu_count: 2,
            minimum_memory_mib: 4096,
            ..Default::default()
        };
        // Big host: all cores, half the memory.
        assert_eq!(guest_size(&image, 12, 49152), (12, 24576));
        // Tiny host: the image minimums win.
        assert_eq!(guest_size(&image, 1, 4096), (2, 4096));
    }
}
