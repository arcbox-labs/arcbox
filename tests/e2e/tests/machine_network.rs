//! Machine networking e2e — the first exercise of a Machine's actual
//! network plane (not just readiness/metadata over the vsock agent).
//!
//! A Machine's primary NIC is the same socketpair userspace netstack +
//! TcpBridge as the System VM's: gateway/DNS `10.0.2.1`, guest `10.0.2.x`,
//! egress via in-process host-socket proxying — no privileged helper, no
//! host route, so it runs in the isolated e2e daemon
//! (`virt/arcbox-vmm/src/vmm/darwin.rs`, `app/arcbox-core/src/machine.rs`).
//! The existing `machine.rs` test only asserts an agent-reported IP; it
//! never drives a packet. This drives real traffic from inside the Machine
//! over the `machines.exec` vsock channel (the Machine's `docker exec`).
//!
//! Scenarios (one Machine, one boot):
//! - **M1 egress TCP**: `wget` a host-local origin at the Machine's gateway
//!   — first proof a Machine can reach the network at all.
//! - **M2 DNS**: `nslookup host.docker.internal` / `gateway.docker.internal`
//!   resolve to the gateway via the in-VMM `DnsForwarder`.
//! - **M3 egress volume**: a larger download, byte-exact and bounded.
//! - **M4 metadata**: `inspect` reports gateway `10.0.2.1` and that gateway
//!   as a DNS server.
//! - **M5 SSH contract**: `ssh_info` is still `unimplemented` — pins the
//!   documented gap so a future SSH feature flags this test to grow.
//!
//! Not covered, by architecture (documented in the plan, no active test):
//! Machine↔Machine, Machine→container, Machine→System VM are isolated
//! per-VM netstacks with no cross path today; host→Machine inbound/SSH does
//! not exist.
//!
//! Requires internet (create pulls alpine from the live CDN mirror) and a
//! musl-cross `arcbox-agent`, like `machine.rs`.

use std::sync::Once;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use arcbox_e2e::boot_assets::{resolve_boot_version, stage_dev_boot_assets};
use arcbox_e2e::daemon::{DaemonConfig, DaemonHandle, connect_unix};
use arcbox_e2e::metrics::RunMetrics;
use arcbox_e2e::net_fixtures::spawn_blob_server;
use arcbox_grpc::v1::machine_service_client::MachineServiceClient;
use arcbox_protocol::v1::{
    CreateMachineRequest, InspectMachineRequest, MachineExecRequest, RemoveMachineRequest,
    SshInfoRequest, StartMachineRequest, StopMachineRequest,
};
use tonic::transport::Channel;

static TRACING: Once = Once::new();

const READY_TIMEOUT: Duration = Duration::from_secs(180);
const CREATE_BUDGET: Duration = Duration::from_secs(120);
const START_BUDGET: Duration = Duration::from_secs(120);
const RPC_BUDGET: Duration = Duration::from_secs(30);
/// Budget for an in-Machine network command (download etc.).
const NET_BUDGET: Duration = Duration::from_secs(60);

const MACHINE: &str = "e2e-net-alpine";
/// The gateway/DNS IP a Machine's primary NIC always routes through
/// (`darwin.rs` hardcodes it; `app/arcbox-api/src/grpc/machine.rs` documents
/// it as `NAT_GATEWAY`).
const GATEWAY: &str = "10.0.2.1";
/// M3 download size — enough to span many segments, small enough to stay
/// quick over the loopback-backed egress path.
const VOLUME_BYTES: usize = 16 * 1024 * 1024;

fn init_tracing() {
    TRACING.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
            )
            .try_init();
    });
}

#[test]
#[ignore = "boots a real VZ daemon, pulls a distro image from the live CDN, drives Machine traffic"]
fn machine_network_end_to_end() -> Result<()> {
    init_tracing();

    let root = arcbox_e2e::repo_root();
    if !arcbox_e2e::env_flag("SKIP_BUILD") {
        let shell = xshell::Shell::new()?;
        shell.change_dir(&root);
        xshell::cmd!(shell, "cargo build --release -p arcbox-daemon").run()?;
        xshell::cmd!(
            shell,
            "cargo build --release -p arcbox-agent --target aarch64-unknown-linux-musl"
        )
        .run()?;
    }

    let version = resolve_boot_version(&root)?;
    let data_dir = tempfile::Builder::new()
        .prefix("arcbox-machine-net-")
        .tempdir()?;
    stage_dev_boot_assets(&root, data_dir.path(), &version)?;

    let mut daemon = DaemonHandle::spawn(DaemonConfig {
        binary: root.join("target/release/arcbox-daemon"),
        data_dir: data_dir.path().to_owned(),
        args: vec![],
        env: vec![
            ("ARCBOX_BOOT_ASSET_VERSION".to_owned(), version),
            ("ARCBOX_VM_BACKEND".to_owned(), "vz".to_owned()),
            ("ARCBOX_DNS_PORT".to_owned(), "0".to_owned()),
        ],
    })?;

    let mut metrics = RunMetrics::new("machine_network", Some("vz"));
    let result = scenario(&mut daemon, &mut metrics);
    metrics.passed = result.is_ok();
    if let Err(error) = metrics.write(Some(data_dir.path())) {
        tracing::warn!("writing run metrics failed: {error:#}");
    }
    if result.is_err() || arcbox_e2e::env_flag("KEEP_TEST_DIR") {
        let kept = data_dir.keep();
        tracing::warn!(path = %kept.display(), "preserving test directory");
    }
    result
}

fn scenario(daemon: &mut DaemonHandle, metrics: &mut RunMetrics) -> Result<()> {
    metrics.time("daemon_ready", || daemon.wait_ready_blocking(READY_TIMEOUT))?;
    let socket = daemon.grpc_socket();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building tokio runtime")?;

    runtime.block_on(async {
        let channel = connect_unix(&socket).await?;
        let mut machines = MachineServiceClient::new(channel);

        create_and_start(&mut machines, metrics).await?;

        // Run all network sub-scenarios, aggregating failures so one boot
        // reports the full picture rather than stopping at the first gap.
        let mut failures = Vec::new();
        for (name, result) in [
            ("m1_egress_tcp", m1_egress_tcp(&mut machines).await),
            ("m2_dns", m2_dns(&mut machines).await),
            ("m3_egress_volume", m3_egress_volume(&mut machines).await),
            (
                "m4_network_metadata",
                m4_network_metadata(&mut machines).await,
            ),
            (
                "m5_ssh_unimplemented",
                m5_ssh_unimplemented(&mut machines).await,
            ),
        ] {
            match result {
                Ok(()) => tracing::info!(scenario = name, "passed"),
                Err(error) => {
                    tracing::warn!(scenario = name, "failed: {error:#}");
                    failures.push(format!("{name}: {error:#}"));
                }
            }
        }

        // Teardown regardless of scenario outcome.
        let _ = machines
            .stop(StopMachineRequest {
                id: MACHINE.to_owned(),
                force: true,
            })
            .await;
        let _ = machines
            .remove(RemoveMachineRequest {
                id: MACHINE.to_owned(),
                force: true,
                volumes: true,
            })
            .await;

        if failures.is_empty() {
            Ok(())
        } else {
            bail!(
                "{} of 5 machine-network scenarios failed:\n{}",
                failures.len(),
                failures.join("\n")
            )
        }
    })
}

async fn create_and_start(
    machines: &mut MachineServiceClient<Channel>,
    metrics: &mut RunMetrics,
) -> Result<()> {
    tokio::time::timeout(
        CREATE_BUDGET,
        machines.create(CreateMachineRequest {
            name: MACHINE.to_owned(),
            cpus: 1,
            memory: 1024 * 1024 * 1024,
            disk_size: 2 * 1024 * 1024 * 1024,
            distro: "alpine".to_owned(),
            version: "3.24".to_owned(),
            ..Default::default()
        }),
    )
    .await
    .context("create timed out (CDN pull)")?
    .context("create failed")?;

    tokio::time::timeout(
        START_BUDGET,
        machines.start(StartMachineRequest {
            id: MACHINE.to_owned(),
        }),
    )
    .await
    .context("start timed out")?
    .context("start failed")?;

    metrics.record("machine_started", 1.0);
    Ok(())
}

/// Runs `cmd` inside the Machine over the vsock agent exec channel and
/// returns (stdout, exit_code). The exec channel is independent of the
/// network plane under test — the out-of-band `docker exec` equivalent.
async fn exec_capture(
    machines: &mut MachineServiceClient<Channel>,
    cmd: &[&str],
    budget: Duration,
) -> Result<(String, i32)> {
    let mut stream = tokio::time::timeout(
        budget,
        machines.exec(MachineExecRequest {
            id: MACHINE.to_owned(),
            cmd: cmd.iter().map(|s| (*s).to_owned()).collect(),
            ..Default::default()
        }),
    )
    .await
    .context("exec timed out")?
    .context("exec failed")?
    .into_inner();

    let mut stdout = Vec::new();
    let mut exit = None;
    while let Some(out) = tokio::time::timeout(budget, stream.message())
        .await
        .context("exec output timed out")?
        .context("exec stream error")?
    {
        if out.stream == "stdout" {
            stdout.extend_from_slice(&out.data);
        }
        if out.done {
            exit = Some(out.exit_code);
        }
    }
    Ok((
        String::from_utf8_lossy(&stdout).into_owned(),
        exit.context("exec produced no completion frame")?,
    ))
}

/// M1: the Machine reaches a host-local origin through its gateway — the
/// first proof its network plane carries traffic. `wget … | wc -c` asserts
/// both reachability and a complete (un-truncated) transfer.
async fn m1_egress_tcp(machines: &mut MachineServiceClient<Channel>) -> Result<()> {
    let blob = 256 * 1024;
    let server = spawn_blob_server(blob)?;
    let url = format!("http://{GATEWAY}:{}/blob", server.port());
    let cmd = format!("wget -q -O - '{url}' | wc -c");
    let (out, exit) = exec_capture(machines, &["/bin/sh", "-c", &cmd], NET_BUDGET).await?;
    if exit != 0 {
        bail!("wget exited {exit} (out: {out:?})");
    }
    let got: usize = out.trim().parse().context("parsing wc -c output")?;
    if got != blob {
        bail!("machine received {got} of {blob} bytes from the gateway origin");
    }
    Ok(())
}

/// M2: the Machine's resolver (`10.0.2.1`, from DHCP) answers the
/// gateway-internal names via the in-VMM `DnsForwarder`.
async fn m2_dns(machines: &mut MachineServiceClient<Channel>) -> Result<()> {
    for name in ["host.docker.internal", "gateway.docker.internal"] {
        let (out, exit) = exec_capture(
            machines,
            &["/bin/sh", "-c", &format!("nslookup {name}")],
            RPC_BUDGET,
        )
        .await?;
        // busybox nslookup exits 0 on NXDOMAIN too, so assert on the answer.
        if !out.contains(GATEWAY) {
            bail!("nslookup {name} did not resolve to {GATEWAY} (exit {exit}): {out:?}");
        }
    }
    Ok(())
}

/// M3: a larger download completes, byte-exact and within budget — the
/// Machine egress path sustains volume, not just a token request.
async fn m3_egress_volume(machines: &mut MachineServiceClient<Channel>) -> Result<()> {
    let server = spawn_blob_server(VOLUME_BYTES)?;
    let url = format!("http://{GATEWAY}:{}/blob", server.port());
    let cmd = format!("wget -q -O - '{url}' | wc -c");
    let (out, exit) = exec_capture(machines, &["/bin/sh", "-c", &cmd], NET_BUDGET).await?;
    if exit != 0 {
        bail!("volume wget exited {exit} (out: {out:?})");
    }
    let got: usize = out.trim().parse().context("parsing wc -c output")?;
    if got != VOLUME_BYTES {
        bail!("machine received {got} of {VOLUME_BYTES} bytes");
    }
    Ok(())
}

/// M4: `inspect` reports the gateway and DNS the Machine actually uses —
/// metadata the lifecycle test never checks.
async fn m4_network_metadata(machines: &mut MachineServiceClient<Channel>) -> Result<()> {
    let info = machines
        .inspect(InspectMachineRequest {
            id: MACHINE.to_owned(),
        })
        .await
        .context("inspect failed")?
        .into_inner();
    let net = info.network.context("no network in inspect")?;
    if net.gateway != GATEWAY {
        bail!("inspect gateway is {:?}, expected {GATEWAY}", net.gateway);
    }
    if !net.dns_servers.iter().any(|d| d == GATEWAY) {
        bail!(
            "inspect dns_servers {:?} does not include the gateway {GATEWAY}",
            net.dns_servers
        );
    }
    // The reported IP must be a real, usable IPv4 — but NOT hardcoded to the
    // datapath's 10.0.2.0/24: `select_routable_ip` picks from the agent's
    // enumerated addresses, and on this host it returned 198.18.11.51 (the
    // Surge/Clash fake-IP range) while the datapath IP is 10.0.2.2. That
    // disagreement is worth a look (see the plan's findings) but is
    // host-environment-tangled, so flag it rather than gate on it.
    let addr: std::net::Ipv4Addr = net
        .ip_address
        .parse()
        .with_context(|| format!("machine IP {:?} is not a valid IPv4", net.ip_address))?;
    if addr.is_loopback() || addr.is_unspecified() || addr.is_link_local() {
        bail!("machine reported a non-routable IP {addr}");
    }
    if !net.ip_address.starts_with("10.0.2.") {
        tracing::warn!(
            ip = %net.ip_address,
            "machine's reported IP is outside the datapath 10.0.2.0/24 (gateway 10.0.2.1, \
             guest 10.0.2.2) — select_routable_ip picked a non-datapath address; \
             investigate on a non-fake-IP host"
        );
    }
    Ok(())
}

/// M5: host→Machine SSH is not implemented; pin that contract so a future
/// SSH feature trips this test and prompts real SSH-networking coverage.
async fn m5_ssh_unimplemented(machines: &mut MachineServiceClient<Channel>) -> Result<()> {
    let status = machines
        .ssh_info(SshInfoRequest {
            id: MACHINE.to_owned(),
        })
        .await
        .err()
        .context("ssh_info unexpectedly succeeded — SSH may now exist; add real SSH coverage")?;
    if status.code() != tonic::Code::Unimplemented {
        bail!(
            "ssh_info failed with {:?}, expected Unimplemented",
            status.code()
        );
    }
    Ok(())
}
