//! VirtioFS host↔guest consistency (ABX-296 Layer B).
//!
//! `arcbox-fs` is well covered below the boundary — 65 unit tests across
//! `passthrough`, `dispatcher`, and `cache` exercise the FUSE opcodes, inode
//! refcounting, and negative-cache behavior. What none of them can prove is
//! that a byte written on one side of the share is the same byte on the
//! other: that needs a booted guest.
//!
//! `bench_virtiofs` already measures throughput (and deliberately asserts no
//! ratio — there is no baseline yet). This file is the correctness half:
//! round-trip integrity, permission preservation, and concurrent metadata
//! operations from both sides.
//!
//! **How the share is reached.** The daemon shares its `--data-dir` with the
//! guest under the `arcbox` tag, mounted at `/arcbox`. So host
//! `<data_dir>/<name>` is guest `/arcbox/<name>`, and a container sees it via
//! `-v /arcbox/<name>:/mnt` — the same path `bench_virtiofs` uses.
//!
//! **Assertions run guest-side where possible.** Piping a payload back
//! through `docker_output` would compare against stdout that also carries
//! stderr; instead the guest checks length and boundaries itself and the
//! host asserts on a short verdict. That keeps the check exact without
//! shipping the payload through a shell.

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use arcbox_e2e::docker::{docker_output, ensure_image};
use arcbox_e2e::scenario::run_vz_scenario;

const READY_TIMEOUT: Duration = Duration::from_secs(180);
const DOCKER_TIMEOUT: Duration = Duration::from_secs(60);
/// Share subdirectory used by this scenario, under both `<data_dir>` on the
/// host and `/arcbox` in the guest.
const SHARE_SUBDIR: &str = "fsconsistency";
/// Distinctive head/tail sentinels — a truncated or offset read cannot
/// reproduce both.
const HEAD: &str = "ARCBOX-HEAD-7f3a";
const TAIL: &str = "ARCBOX-TAIL-c19e";
/// Body chunk repeated between the sentinels. Exactly 64 bytes so the guest
/// can rebuild a byte-identical payload with a bounded shell loop.
const FILL_CHUNK: &str = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
/// Repeats of [`FILL_CHUNK`]. The total lands just past 64 KiB, well beyond
/// a page or FUSE buffer boundary, so a read that stops at one shows up as a
/// length mismatch rather than passing.
///
/// The length is *derived* from this rather than fixed: both sides build the
/// payload from the same chunk count, so they cannot drift. Fixing a target
/// length instead and dividing to get the chunk count silently truncates
/// (65536 − 32 is not a multiple of 64) and the two sides disagree by the
/// remainder.
const FILL_CHUNKS: usize = 1024;
/// Metadata objects created per side in the concurrency phase.
const CONCURRENT_EACH: usize = 10;

#[test]
#[ignore = "boots a VZ System VM through a real daemon; run on the e2e runner"]
fn virtiofs_host_guest_consistency() -> Result<()> {
    run_vz_scenario("virtiofs_consistency", |daemon, data_dir, metrics| {
        metrics.time("daemon_ready", || daemon.wait_ready_blocking(READY_TIMEOUT))?;
        let image =
            std::env::var("ARCBOX_E2E_IMAGE").unwrap_or_else(|_| "alpine:latest".to_owned());
        metrics.time("image_pull", || ensure_image(data_dir, &image))?;

        let host_dir = data_dir.join(SHARE_SUBDIR);
        std::fs::create_dir_all(&host_dir)
            .with_context(|| format!("creating {}", host_dir.display()))?;

        metrics.time("host_to_guest", || host_write_guest_read(data_dir, &image))?;
        metrics.time("guest_to_host", || guest_write_host_read(data_dir, &image))?;
        metrics.time("permissions", || permissions_round_trip(data_dir, &image))?;
        metrics.time("concurrent_metadata", || {
            concurrent_metadata(data_dir, &image)
        })?;
        Ok(())
    })
}

/// Guest mount argument for the scenario's share subdirectory.
fn mount_arg() -> String {
    format!("/arcbox/{SHARE_SUBDIR}:/mnt")
}

/// Runs `sh -c <script>` in a throwaway container with the share mounted.
fn guest_sh(data_dir: &Path, image: &str, script: &str) -> Result<String> {
    docker_output(
        data_dir,
        &["run", "--rm", "-v", &mount_arg(), image, "sh", "-c", script],
        DOCKER_TIMEOUT,
    )
}

/// Byte length of [`payload`], derived from the same constants the guest
/// rebuilds it from.
fn payload_len() -> usize {
    HEAD.len() + FILL_CHUNKS * FILL_CHUNK.len() + TAIL.len()
}

/// Sentinel-bracketed payload. Built from whole [`FILL_CHUNK`] repeats so
/// the guest's shell loop produces exactly the same bytes.
fn payload() -> String {
    let mut body = String::with_capacity(payload_len());
    body.push_str(HEAD);
    for _ in 0..FILL_CHUNKS {
        body.push_str(FILL_CHUNK);
    }
    body.push_str(TAIL);
    body
}

/// Guards the host/guest payload contract without needing a VM: the two
/// sides agree only because both are whole-chunk multiples. This is the
/// check that catches a constant edit desynchronising them.
#[test]
fn payload_is_whole_chunks_and_sentinel_bracketed() {
    assert_eq!(FILL_CHUNK.len(), 64, "the guest loop writes 64-byte chunks");
    let body = payload();
    assert_eq!(body.len(), payload_len());
    assert!(body.starts_with(HEAD));
    assert!(body.ends_with(TAIL));
    assert_eq!(
        body.len() - HEAD.len() - TAIL.len(),
        FILL_CHUNKS * FILL_CHUNK.len(),
        "fill must be whole chunks — a remainder would make the guest's \
         reconstruction shorter than the host's expectation"
    );
    assert!(
        body.len() > 64 * 1024,
        "payload must cross a 64 KiB boundary"
    );
}

/// Host writes, guest reads back identical content.
fn host_write_guest_read(data_dir: &Path, image: &str) -> Result<()> {
    let body = payload();
    let path = data_dir.join(SHARE_SUBDIR).join("h2g.bin");
    std::fs::write(&path, &body).with_context(|| format!("writing {}", path.display()))?;

    // Length and both sentinels are checked in the guest; only the verdict
    // crosses back, so stdout framing cannot corrupt the comparison.
    let script = format!(
        "set -e; \
         len=$(wc -c < /mnt/h2g.bin); \
         [ \"$len\" = \"{expected_len}\" ] || {{ echo \"BADLEN:$len\"; exit 1; }}; \
         [ \"$(head -c {head_len} /mnt/h2g.bin)\" = \"{HEAD}\" ] || {{ echo BADHEAD; exit 1; }}; \
         [ \"$(tail -c {tail_len} /mnt/h2g.bin)\" = \"{TAIL}\" ] || {{ echo BADTAIL; exit 1; }}; \
         echo OK",
        expected_len = payload_len(),
        head_len = HEAD.len(),
        tail_len = TAIL.len(),
    );
    let out = guest_sh(data_dir, image, &script)
        .context("guest could not read back the host-written file")?;
    if !out.contains("OK") {
        bail!("guest read mismatch for a host-written file: {out:?}");
    }
    Ok(())
}

/// Guest writes, host reads back identical content.
fn guest_write_host_read(data_dir: &Path, image: &str) -> Result<()> {
    let body = payload();
    // Same constants as `payload()`, so the two constructions cannot drift.
    let script = format!(
        "set -e; \
         printf '%s' '{HEAD}' > /mnt/g2h.bin; \
         i=0; while [ $i -lt {FILL_CHUNKS} ]; do \
         printf '%s' '{FILL_CHUNK}' >> /mnt/g2h.bin; i=$((i+1)); done; \
         printf '%s' '{TAIL}' >> /mnt/g2h.bin; \
         echo OK"
    );
    let out = guest_sh(data_dir, image, &script).context("guest could not write to the share")?;
    if !out.contains("OK") {
        bail!("guest write reported failure: {out:?}");
    }

    let path = data_dir.join(SHARE_SUBDIR).join("g2h.bin");
    let read = std::fs::read_to_string(&path)
        .with_context(|| format!("host reading guest-written {}", path.display()))?;
    if read.len() != body.len() {
        bail!(
            "host saw {} bytes of a guest-written file, expected {}",
            read.len(),
            body.len()
        );
    }
    if read != body {
        bail!("host content differs from what the guest wrote (same length, differing bytes)");
    }
    Ok(())
}

/// Mode bits survive the boundary in both directions.
fn permissions_round_trip(data_dir: &Path, image: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    // Host → guest.
    let host_set = data_dir.join(SHARE_SUBDIR).join("hostmode");
    std::fs::write(&host_set, b"m")?;
    std::fs::set_permissions(&host_set, std::fs::Permissions::from_mode(0o750))
        .with_context(|| format!("chmod {}", host_set.display()))?;
    let seen = guest_sh(data_dir, image, "stat -c %a /mnt/hostmode")
        .context("guest could not stat a host-chmodded file")?;
    if !seen.trim().contains("750") {
        bail!("guest saw mode {seen:?} for a file the host set to 750");
    }

    // Guest → host.
    guest_sh(
        data_dir,
        image,
        "set -e; echo m > /mnt/guestmode; chmod 705 /mnt/guestmode; echo OK",
    )
    .context("guest could not chmod on the share")?;
    let host_view = std::fs::metadata(data_dir.join(SHARE_SUBDIR).join("guestmode"))
        .context("host stat of a guest-chmodded file")?;
    let mode = host_view.permissions().mode() & 0o777;
    if mode != 0o705 {
        bail!("host saw mode {mode:o} for a file the guest set to 705");
    }
    Ok(())
}

/// Concurrent metadata operations from both sides stay coherent.
///
/// Each side owns a disjoint name range, so this measures cross-boundary
/// visibility and cache coherence rather than racing two writers on one
/// target (whose outcome would be legitimately undefined).
fn concurrent_metadata(data_dir: &Path, image: &str) -> Result<()> {
    let dir = data_dir.join(SHARE_SUBDIR).join("concurrent");
    std::fs::create_dir_all(&dir)?;

    // Guest creates its range while the host creates its own.
    let guest = std::thread::scope(|scope| -> Result<String> {
        let handle = scope.spawn(|| {
            guest_sh(
                data_dir,
                image,
                &format!(
                    "set -e; i=0; while [ $i -lt {CONCURRENT_EACH} ]; do \
                     mkdir -p /mnt/concurrent/g$i; i=$((i+1)); done; echo OK"
                ),
            )
        });
        for i in 0..CONCURRENT_EACH {
            std::fs::create_dir_all(dir.join(format!("h{i}")))
                .with_context(|| format!("host mkdir h{i}"))?;
        }
        handle
            .join()
            .map_err(|_| anyhow::anyhow!("guest mkdir thread panicked"))?
    })
    .context("concurrent mkdir phase")?;
    if !guest.contains("OK") {
        bail!("guest mkdir batch reported failure: {guest:?}");
    }

    // Both ranges must be visible from both sides.
    let listing = guest_sh(data_dir, image, "ls /mnt/concurrent | sort | tr '\\n' ' '")
        .context("guest listing after concurrent mkdir")?;
    for i in 0..CONCURRENT_EACH {
        for name in [format!("g{i}"), format!("h{i}")] {
            if !listing.contains(&name) {
                bail!("guest listing is missing {name:?} after concurrent mkdir: {listing:?}");
            }
            if !dir.join(&name).is_dir() {
                bail!("host cannot see {name:?} after concurrent mkdir");
            }
        }
    }

    // Each side removes its own range; the other must observe the removal.
    guest_sh(
        data_dir,
        image,
        &format!(
            "set -e; i=0; while [ $i -lt {CONCURRENT_EACH} ]; do \
             rmdir /mnt/concurrent/g$i; i=$((i+1)); done; echo OK"
        ),
    )
    .context("guest rmdir batch")?;
    for i in 0..CONCURRENT_EACH {
        std::fs::remove_dir(dir.join(format!("h{i}")))
            .with_context(|| format!("host rmdir h{i}"))?;
        if dir.join(format!("g{i}")).exists() {
            bail!("host still sees g{i} after the guest removed it (stale dentry cache)");
        }
    }

    let after = guest_sh(data_dir, image, "ls -A /mnt/concurrent | wc -l")
        .context("guest listing after concurrent rmdir")?;
    if !after.trim().starts_with('0') {
        bail!("guest still sees entries under concurrent/ after both sides cleaned up: {after:?}");
    }
    Ok(())
}
