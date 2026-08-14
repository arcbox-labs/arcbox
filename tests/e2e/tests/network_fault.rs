//! Network-fault e2e — Phase 1 of ../company/engineering/arcbox/plans/network-fault-e2e.md.
//!
//! The incident (2026-07-19): a container download hung 23+ minutes on a
//! guest-side TCP flow left `ESTABLISHED` (empty queues) after its upstream
//! leg died, with no RST/FIN reaching the guest. `egress_throughput` only
//! covers the happy path; nothing tested flow *lifetime* across a fault.
//!
//! This drives a real container through the full egress datapath
//! (guest eth0 → classifier → TcpBridge → host socket via the
//! `10.0.2.1`→loopback translation) to a host-local chaos origin that
//! serves a partial body then **resets** its connection, and asserts
//! **bounded failure**: the in-container client must observe the error within
//! a deadline — never hang. `wget` is given no `-T`, so the only thing that
//! can end it is ArcBox propagating the upstream RST to the guest leg.
//!
//! Scope: Phase 1 covers the parallel-safe, in-process fault — a peer RST.
//! The other incident shapes (a silent upstream death where the peer stops
//! answering, an unanswered-SYN connect blackhole) cannot be reproduced
//! in-process: the host kernel keeps ACKing for a merely-idle peer, and a
//! closed local port answers with RST rather than dropping the SYN. Those
//! need actual network-path interruption (firewall/route), which is the
//! plan's exclusive Tier 3, not Tier 1.

use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use arcbox_e2e::docker::{docker_output, ensure_image};
use arcbox_e2e::net_fixtures::{GUEST_GATEWAY_IP, spawn_chaos_origin};
use arcbox_e2e::scenario::run_vz_scenario;

const READY_TIMEOUT: Duration = Duration::from_secs(180);
/// Body bytes the chaos origin sends before injecting the fault: enough that
/// the transfer is genuinely mid-stream (past headers, into the body loop).
const PARTIAL_BODY_BYTES: usize = 64 * 1024;
/// Advertised Content-Length — far larger than the partial body, so the
/// client is still expecting data when the fault hits.
const ADVERTISED_LEN: usize = 256 * 1024 * 1024;
/// The client must observe the failure within this bound. A propagated RST
/// arrives in well under a second; the generous margin absorbs slow CI.
const FAILURE_DEADLINE: Duration = Duration::from_secs(30);
/// Hard ceiling on the docker call — strictly greater than FAILURE_DEADLINE
/// so a hang is caught by the elapsed-time assertion (a clean, specific
/// failure) rather than the docker timeout (an opaque one).
const DOCKER_TIMEOUT: Duration = Duration::from_secs(60);

/// Peer RST mid-transfer must reach the container promptly. A container
/// downloads from a chaos origin that resets the connection after a partial
/// body; `wget` is given no `-T`, so the bound must come from the datapath
/// propagating the RST to the guest leg — the behavior the incident lacked.
#[test]
#[ignore = "boots a VZ System VM through a real daemon; run on the e2e runner"]
fn net_upstream_rst_is_propagated_promptly() -> Result<()> {
    run_vz_scenario("network_fault_rst", |daemon, data_dir, metrics| {
        metrics.time("daemon_ready", || daemon.wait_ready_blocking(READY_TIMEOUT))?;
        let image =
            std::env::var("ARCBOX_E2E_IMAGE").unwrap_or_else(|_| "alpine:latest".to_owned());
        metrics.time("docker_pull", || ensure_image(data_dir, &image))?;

        let port = spawn_chaos_origin(PARTIAL_BODY_BYTES, ADVERTISED_LEN)?;
        let url = format!("http://{GUEST_GATEWAY_IP}:{port}/blob");
        tracing::info!(%url, "chaos origin up");

        let started = Instant::now();
        // No `-T`: the bound must come from the datapath, not wget's own timer.
        let result = docker_output(
            data_dir,
            &["run", "--rm", &image, "wget", "-q", "-O", "/dev/null", &url],
            DOCKER_TIMEOUT,
        );
        let elapsed = started.elapsed();
        metrics.record("client_observed_end", elapsed.as_secs_f64());

        // The download MUST NOT succeed — the origin resets before the body
        // completes.
        if result.is_ok() {
            bail!("download unexpectedly succeeded against a resetting origin");
        }
        tracing::info!(?elapsed, "client returned: {:#}", result.unwrap_err());

        // Bounded-failure property: the client saw the error promptly. A value
        // at or beyond the deadline means the guest leg zombied (the incident)
        // and only the docker timeout unstuck it.
        if elapsed >= FAILURE_DEADLINE {
            bail!(
                "client hung {elapsed:?} (>= {FAILURE_DEADLINE:?}) before observing the upstream \
                 RST — guest leg was not reset (zombie flow regression)"
            );
        }
        Ok(())
    })
}
