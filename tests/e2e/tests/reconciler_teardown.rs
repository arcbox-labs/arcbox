//! Host-networking reconciler e2e — the live validation issue #352 asked for.
//!
//! A container with a published port exits ON ITS OWN and is auto-removed by
//! guest dockerd (`--rm`): no stop/kill/remove ever reaches the host proxy,
//! so the handler-driven teardown never runs. The 30 s reconciler sweep
//! (`app/arcbox-docker/src/host_reconciler.rs`) is the only path that can
//! reclaim the host port-forward listener and DNS/alias registrations — this
//! test proves its real guest query and cadence against a booted VZ System
//! VM, which the unit tests (decision logic only) cannot.

use std::net::TcpStream;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use arcbox_e2e::docker::{docker_output, ensure_image};
use arcbox_e2e::scenario::run_vz_scenario_with_log;

const READY_TIMEOUT: Duration = Duration::from_secs(180);
const NAME: &str = "e2e-reconciler-selfexit";
/// One reconciler interval (30 s) + guest query + generous margin.
const TEARDOWN_DEADLINE: Duration = Duration::from_secs(90);

fn host_port_of(mapped: &str) -> Result<u16> {
    mapped
        .lines()
        .next()
        .and_then(|l| l.rsplit(':').next())
        .and_then(|p| p.trim().parse::<u16>().ok())
        .with_context(|| format!("parsing mapped port from {mapped:?}"))
}

fn connects(port: u16) -> bool {
    TcpStream::connect_timeout(
        &format!("127.0.0.1:{port}").parse().unwrap(),
        Duration::from_millis(500),
    )
    .is_ok()
}

#[test]
#[ignore = "boots a VZ System VM"]
fn reconciler_tears_down_self_exited_container() -> Result<()> {
    run_vz_scenario_with_log(
        "reconciler_teardown",
        "info,arcbox_docker=debug",
        |daemon, data_dir, metrics| {
            metrics.time("daemon_ready", || daemon.wait_ready_blocking(READY_TIMEOUT))?;
            let image =
                std::env::var("ARCBOX_E2E_IMAGE").unwrap_or_else(|_| "alpine:latest".to_owned());
            metrics.time("docker_pull", || ensure_image(data_dir, &image))?;

            // A published port on a container that ends on its own. --rm makes
            // guest dockerd auto-remove it on exit — the exact path that
            // bypasses every host-side teardown handler.
            docker_output(
                data_dir,
                &[
                    "run",
                    "-d",
                    "--rm",
                    "--name",
                    NAME,
                    "-p",
                    "127.0.0.1::80",
                    &image,
                    "sleep",
                    "8",
                ],
                Duration::from_secs(60),
            )
            .context("starting self-exiting published container")?;

            let mapped =
                docker_output(data_dir, &["port", NAME, "80/tcp"], Duration::from_secs(20))
                    .context("docker port")?;
            let port = host_port_of(&mapped)?;

            // While the container lives, the host listener must accept (the
            // inbound relay answers the SYN regardless of what's inside).
            let alive_deadline = Instant::now() + Duration::from_secs(6);
            while !connects(port) {
                if Instant::now() >= alive_deadline {
                    bail!("host listener for 127.0.0.1:{port} never came up");
                }
                std::thread::sleep(Duration::from_millis(200));
            }
            tracing::info!(
                port,
                "published port live; waiting for self-exit + reconciler sweep"
            );

            // The container exits at t≈8 s and dockerd removes it guest-side.
            // The listener must disappear within one reconciler sweep.
            let start = Instant::now();
            let deadline = start + TEARDOWN_DEADLINE;
            while connects(port) {
                if Instant::now() >= deadline {
                    bail!(
                        "host listener for 127.0.0.1:{port} still accepting {}s after \
                         a self-exited --rm container — reconciler teardown did not run",
                        TEARDOWN_DEADLINE.as_secs()
                    );
                }
                std::thread::sleep(Duration::from_millis(500));
            }
            let teardown = start.elapsed();
            metrics.record("teardown_seconds", teardown.as_secs_f64());
            tracing::info!(secs = teardown.as_secs_f64(), "host listener reclaimed");

            // Belt: the daemon log must attribute the teardown to the
            // reconciler (nothing else can see a guest-side removal).
            let log = std::fs::read_to_string(data_dir.join("harness-daemon.log"))
                .context("reading harness daemon log")?;
            if !log.contains("reconciler tearing down host networking") {
                bail!("reconciler teardown log line missing — teardown came from another path?");
            }
            Ok(())
        },
    )
}
