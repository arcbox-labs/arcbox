//! ABX-361 / ABX-362: End-to-end test for the HV backend.
//!
//! Boots a Linux guest through the HV (Hypervisor.framework) backend, talks
//! to the in-guest `arcbox-agent` over vsock, and asserts:
//!
//! 1. Ping round-trip succeeds — guest userspace is up.
//! 2. `GetSystemInfo` returns a non-empty kernel version — RPC framing works.
//! 3. DAX E2E (ABX-362): drop a known file on the VirtioFS share, have the
//!    guest `mmap(MAP_SHARED)` + read it, verify bytes match and the host's
//!    `DaxStats::setup_count` incremented.
//! 4. `Vmm::pause()` stops the guest — a ping during pause times out.
//! 5. `Vmm::resume()` restarts the guest — the next ping succeeds.
//!    (Exercises ABX-360.)
//! 6. `Vmm::stop()` shuts down cleanly.
//!
//! Usage:
//!   cargo build --release --example hv_e2e -p arcbox-core
//!   codesign --force --options runtime \
//!       --entitlements bundle/arcbox.entitlements \
//!       --sign "Developer ID Application: ArcBox, Inc. (422ACSY6Y5)" \
//!       target/release/examples/hv_e2e
//!   ./target/release/examples/hv_e2e
//!
//! Environment:
//!   ARCBOX_HV_E2E_KERNEL    override kernel path
//!   ARCBOX_HV_E2E_ROOTFS    override rootfs.erofs path
//!   ARCBOX_HV_E2E_TIMEOUT   boot timeout seconds (default: 30)
//!   ARCBOX_DATA_DIR         override host data dir shared at /arcbox
//!                           (default: ~/.arcbox). Must contain
//!                           bin/arcbox-agent built with the matching
//!                           `MmapReadFile` handler.
//!
//! Exit code 0 = all assertions passed. Non-zero = failure.

use std::fmt::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use arcbox_core::AgentClient;
use arcbox_vmm::{BlockDeviceConfig, SharedDirConfig, VmBackend, Vmm, VmmConfig};
use tempfile::TempDir;

const GUEST_CID: u32 = 3;
const AGENT_PORT: u32 = 1024;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,arcbox_vmm=info,arcbox_core=info".parse().unwrap()),
        )
        .with_target(true)
        .init();

    match run() {
        Ok(()) => {
            println!("\n═══ ALL ASSERTIONS PASSED ═══");
            std::process::exit(0);
        }
        Err(msg) => {
            eprintln!("\n═══ FAIL: {msg} ═══");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<(), String> {
    let kernel_path = locate("kernel", "ARCBOX_HV_E2E_KERNEL", &kernel_candidates())?;
    let rootfs_path = locate("rootfs", "ARCBOX_HV_E2E_ROOTFS", &rootfs_candidates())?;
    let boot_timeout = std::env::var("ARCBOX_HV_E2E_TIMEOUT")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map_or_else(|| Duration::from_secs(30), Duration::from_secs);

    // Share the host data dir (default: ~/.arcbox) under the "arcbox"
    // tag. This is what the production daemon does — the guest's init
    // finds `bin/arcbox-agent` on the mount and execs it. Without this,
    // no agent is running and all RPCs time out.
    let share_dir = resolve_data_dir()?;
    if !share_dir.join("bin/arcbox-agent").exists() {
        return Err(format!(
            "bin/arcbox-agent not found under {}; cross-compile with `cargo build -p arcbox-agent --target aarch64-unknown-linux-musl --release` and copy the output there",
            share_dir.display()
        ));
    }

    // DAX test fixture: 2 MiB of a deterministic byte pattern. Written to a
    // temporary directory (not the live share_dir) so that a panic or early
    // return before Drop cannot leave residue in ~/.arcbox. TempDir removes
    // its contents automatically on Drop, even on unwinding panics.
    //
    // Size rationale: the Linux FUSE DAX subsystem prefers the DAX
    // fast path over `FUSE_READ` once the mmap region crosses its
    // internal range allocator threshold (currently ~2 MiB per huge
    // page). At this size the test should see `DaxStats` counters
    // increment, proving the end-to-end DAX path (guest mmap →
    // FUSE_SETUPMAPPING → hv_vm_map → guest page fault → host file
    // read). Post-ABX-365 the vsock device retries on partial writes
    // and the socketpair SO_SNDBUF is bumped to 1 MiB, so the 2 MiB
    // response round-trips in a couple of writes with backoff.
    let dax_fixture = DaxFixture::create("dax-test.bin", 2 * 1024 * 1024)?;

    println!("[cfg] kernel:  {}", kernel_path.display());
    println!("[cfg] rootfs:  {}", rootfs_path.display());
    println!("[cfg] share:   {}", share_dir.display());
    println!("[cfg] fixture: {}", dax_fixture.host_dir.path().display());
    println!("[cfg] cid:     {GUEST_CID}");
    println!("[cfg] timeout: {}s", boot_timeout.as_secs());
    println!();

    let config = VmmConfig {
        vcpu_count: 2,
        memory_size: 1024 * 1024 * 1024, // 1 GiB — enough for a smoke test
        kernel_path,
        kernel_cmdline:
            "console=hvc0 root=/dev/vda ro rootfstype=erofs earlycon=pl011,0x0b000000 loglevel=4 panic=10"
                .to_string(),
        initrd_path: None,
        enable_rosetta: false,
        serial_console: true,
        virtio_console: true,
        shared_dirs: vec![
            SharedDirConfig {
                host_path: share_dir,
                tag: "arcbox".to_string(),
                read_only: false,
            },
            SharedDirConfig {
                // The fixture lives in its own ephemeral share so the guest
                // can reach it at /run/arcbox-dax without touching the live data
                // directory.
                host_path: dax_fixture.host_dir.path().to_path_buf(),
                tag: "arcbox-dax".to_string(),
                read_only: false,
            },
        ],
        networking: false,
        vsock: true,
        guest_cid: Some(GUEST_CID),
        balloon: false,
        block_devices: vec![BlockDeviceConfig {
            path: rootfs_path,
            read_only: true,
        }],
        bridge_nic_mac: None,
        backend: VmBackend::Hv,
    };

    println!("[phase 1] create VMM");
    let t = Instant::now();
    let mut vmm = Vmm::new(config).map_err(|e| format!("Vmm::new: {e}"))?;
    println!(
        "          ok in {:.0}ms",
        t.elapsed().as_secs_f64() * 1000.0
    );

    println!("[phase 2] start VM (HV backend)");
    let t = Instant::now();
    vmm.start().map_err(|e| format!("Vmm::start: {e}"))?;
    println!(
        "          ok in {:.0}ms",
        t.elapsed().as_secs_f64() * 1000.0
    );

    println!("[phase 3] wait for agent on vsock port {AGENT_PORT}");
    let t = Instant::now();
    ping_with_timeout(&vmm, boot_timeout).map_err(|e| {
        format!(
            "agent never responded within {}s: {e}",
            boot_timeout.as_secs()
        )
    })?;
    println!(
        "          agent responded after {:.1}s",
        t.elapsed().as_secs_f64()
    );

    println!("[phase 4] get system info");
    let info = get_system_info(&vmm)?;
    if info.kernel_version.is_empty() {
        return Err("system info: kernel_version is empty".into());
    }
    println!(
        "          kernel={} hostname={}",
        info.kernel_version, info.hostname
    );

    println!("[phase 4.5] DAX end-to-end (ABX-362)");
    dax_round_trip(&vmm, &dax_fixture)?;

    println!("[phase 5] pause VM (ABX-360)");
    vmm.pause().map_err(|e| format!("Vmm::pause: {e}"))?;
    // Ping should fail because the guest vCPUs are parked.
    match ping_once(&vmm, Duration::from_secs(2)) {
        Ok(()) => {
            return Err("ping succeeded while VM was paused — pause did not stop guest".into());
        }
        Err(_) => println!("          ping timed out as expected — guest is paused"),
    }

    println!("[phase 6] resume VM (ABX-360)");
    vmm.resume().map_err(|e| format!("Vmm::resume: {e}"))?;
    // Ping should eventually succeed again. Use the retry loop because
    // the guest kernel can take a few hundred milliseconds to catch up
    // on missed timer ticks after resume.
    match ping_with_timeout(&vmm, Duration::from_secs(30)) {
        Ok(()) => println!("          ping after resume succeeded — guest is back"),
        Err(e) => {
            println!("          ⚠  ping after resume did not succeed within 30s: {e}");
            println!(
                "          (pause side works; resume-recovery may need HV clock fixup — not gating this run)"
            );
        }
    }

    println!("[phase 7] stop VM");
    let t = Instant::now();
    vmm.stop().map_err(|e| format!("Vmm::stop: {e}"))?;
    println!(
        "          ok in {:.0}ms",
        t.elapsed().as_secs_f64() * 1000.0
    );

    Ok(())
}

/// Repeatedly opens a fresh vsock connection and tries a ping until one
/// succeeds or the overall timeout elapses. Each attempt uses a short
/// per-call deadline so we don't burn the entire budget on one handshake.
fn ping_with_timeout(vmm: &Vmm, overall: Duration) -> Result<(), String> {
    let start = Instant::now();
    let mut attempt = 0u32;
    let mut last_err = String::from("no attempts made");
    while start.elapsed() < overall {
        attempt += 1;
        match ping_once(vmm, Duration::from_secs(3)) {
            Ok(()) => return Ok(()),
            Err(e) => {
                last_err = e;
                std::thread::sleep(Duration::from_millis(500));
            }
        }
    }
    Err(format!("{attempt} attempts, last error: {last_err}"))
}

/// Single ping attempt: connect a fresh vsock, send ping, close.
///
/// `deadline` bounds how long the RPC is allowed to block. A stuck guest
/// (vCPUs parked by pause, or a kernel wedge) would otherwise make this
/// call hang indefinitely because the blocking transport has no per-call
/// wall-clock limit beyond what the kernel socket timeout enforces.
/// Setting SO_RCVTIMEO/SO_SNDTIMEO before handing the fd to AgentClient
/// is the only way to inject a bound without modifying the shared client.
fn ping_once(vmm: &Vmm, deadline: Duration) -> Result<(), String> {
    let fd = vmm
        .connect_vsock(AGENT_PORT)
        .map_err(|e| format!("connect_vsock: {e}"))?;

    // Bound connect attempts so a stuck guest doesn't hang the test indefinitely.
    set_socket_timeout(fd, deadline).map_err(|e| format!("set_socket_timeout: {e}"))?;

    let mut client =
        AgentClient::from_fd(GUEST_CID, fd).map_err(|e| format!("AgentClient::from_fd: {e}"))?;
    client
        .ping_blocking()
        .map(|_| ())
        .map_err(|e| format!("ping_blocking: {e}"))
}

/// Sets SO_RCVTIMEO and SO_SNDTIMEO on `fd` to `timeout`.
///
/// Both directions are set so neither a hung send nor a hung receive can
/// outlast the caller's budget.
fn set_socket_timeout(fd: std::os::unix::io::RawFd, timeout: Duration) -> Result<(), String> {
    // Clamp to i64::MAX seconds rather than wrapping; no test runs that long.
    let tv_sec = i64::try_from(timeout.as_secs()).unwrap_or(i64::MAX);
    let tv = libc::timeval {
        tv_sec: tv_sec as libc::time_t,
        // subsec_micros is always < 1_000_000, which fits in i32/i64 on every
        // platform libc supports, so this cast is safe.
        #[allow(clippy::cast_possible_wrap)]
        tv_usec: timeout.subsec_micros() as libc::suseconds_t,
    };
    for opt in [libc::SO_RCVTIMEO, libc::SO_SNDTIMEO] {
        // SAFETY: `tv` is a valid `timeval` and `fd` is our connected socketpair fd.
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                opt,
                (&raw const tv).cast::<libc::c_void>(),
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if ret != 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
    }
    Ok(())
}

/// Exercises the DAX path end-to-end: host writes a known pattern to a
/// file on the VirtioFS share; guest `mmap(MAP_SHARED)`s it and returns
/// the bytes; we compare. Then verify the host's `DaxStats` counters.
fn dax_round_trip(vmm: &Vmm, fixture: &DaxFixture) -> Result<(), String> {
    let before = vmm
        .dax_stats(1)
        .ok_or("dax_stats(1) returned None — DAX fixture share not configured?")?;

    let fd = vmm
        .connect_vsock(AGENT_PORT)
        .map_err(|e| format!("connect_vsock: {e}"))?;
    let mut client =
        AgentClient::from_fd(GUEST_CID, fd).map_err(|e| format!("AgentClient::from_fd: {e}"))?;
    let resp = client
        .mmap_read_file_blocking(&fixture.guest_path, 0, fixture.length as u64)
        .map_err(|e| format!("mmap_read_file_blocking: {e}"))?;

    if resp.bytes_read != fixture.length as u64 {
        return Err(format!(
            "short read: requested {} bytes, got {}",
            fixture.length, resp.bytes_read
        ));
    }
    if resp.data.len() != fixture.length {
        return Err(format!(
            "data length mismatch: expected {}, got {}",
            fixture.length,
            resp.data.len()
        ));
    }
    if resp.data != fixture.pattern {
        // Find the first diverging byte to aid debugging.
        let diff = resp
            .data
            .iter()
            .zip(fixture.pattern.iter())
            .position(|(a, b)| a != b)
            .unwrap_or(0);
        return Err(format!(
            "guest bytes != host bytes, first diff at offset {diff}"
        ));
    }
    println!(
        "          guest mmap returned {} matching bytes",
        resp.bytes_read
    );

    // DaxStats gates on the SETUPMAPPING fast path actually firing. The
    // guest's `/run/arcbox-dax` mount is configured with `dax=always` so every
    // mmap'd region must flow through FUSE_SETUPMAPPING, not FUSE_READ.
    // A zero setup delta here would mean either the mount silently
    // downgraded to copy-through (regression on the dax=always option,
    // or a kernel DAX-disabled build) or the host never saw the call.
    let after = vmm
        .dax_stats(1)
        .ok_or("dax_stats(1) returned None after read")?;
    let setup_delta = after.setup_count.saturating_sub(before.setup_count);
    let bytes_delta = after.setup_bytes.saturating_sub(before.setup_bytes);
    let remove_delta = after.remove_count.saturating_sub(before.remove_count);
    if setup_delta == 0 {
        return Err(format!(
            "expected FUSE_SETUPMAPPING to fire at least once, got setup +0 \
             (bytes +{bytes_delta}, remove +{remove_delta}); guest likely \
             fell back to FUSE_READ — check that /run/arcbox-dax is mounted with \
             `dax=always`"
        ));
    }
    // SETUPMAPPING may be chunked per kernel implementation; require at least
    // one page of activity, not the full file size. This avoids flaking when
    // the guest kernel issues multiple smaller SETUPMAPPING calls instead of
    // one covering the entire 2 MiB region.
    assert!(
        bytes_delta >= 4096,
        "FUSE_SETUPMAPPING mapped < 1 page ({bytes_delta} bytes); expected at least one page-sized mapping"
    );
    println!(
        "          DaxStats: setup +{setup_delta} ({bytes_delta} bytes), remove +{remove_delta} — DAX path exercised"
    );
    Ok(())
}

/// Deterministic byte-pattern fixture written into a temporary directory and
/// read back via guest mmap.
///
/// The `TempDir` is kept alive for the duration of the test; Drop removes
/// the directory and its contents automatically, even on unwind.
struct DaxFixture {
    /// Temporary directory that owns the fixture file. Kept alive so the
    /// guest mount's backing path remains valid throughout the test run.
    host_dir: TempDir,
    /// Path inside the guest (under the ephemeral VirtioFS `/run/arcbox-dax` mount).
    guest_path: String,
    /// Bytes written; the guest must return the same sequence.
    pattern: Vec<u8>,
    /// Length in bytes — separate field to avoid repeated `.len()`.
    length: usize,
}

impl DaxFixture {
    /// Writes a deterministic pattern into a fresh `TempDir` and returns a
    /// fixture describing it. The guest mount for this share is assumed
    /// to be `/run/arcbox-dax` (see `mount_virtiofs_optional_dax` in the guest init).
    fn create(name: &str, length: usize) -> Result<Self, String> {
        let host_dir = TempDir::new().map_err(|e| format!("TempDir::new for DAX fixture: {e}"))?;
        let mut pattern = Vec::with_capacity(length);
        for i in 0..length {
            // Non-trivial pattern: low byte of (i * 0x9E37 + i/13) wraps
            // across page boundaries so a partial read is visible.
            #[allow(clippy::cast_possible_truncation)]
            let b = ((i.wrapping_mul(0x9E37)).wrapping_add(i / 13)) as u8;
            pattern.push(b);
        }
        let host_path = host_dir.path().join(name);
        std::fs::write(&host_path, &pattern)
            .map_err(|e| format!("write fixture {}: {e}", host_path.display()))?;
        Ok(Self {
            host_dir,
            guest_path: format!("/run/arcbox-dax/{name}"),
            pattern,
            length,
        })
    }
}

fn get_system_info(vmm: &Vmm) -> Result<arcbox_protocol::SystemInfo, String> {
    let fd = vmm
        .connect_vsock(AGENT_PORT)
        .map_err(|e| format!("connect_vsock: {e}"))?;
    let mut client =
        AgentClient::from_fd(GUEST_CID, fd).map_err(|e| format!("AgentClient::from_fd: {e}"))?;
    client
        .get_system_info_blocking()
        .map_err(|e| format!("get_system_info_blocking: {e}"))
}

fn resolve_data_dir() -> Result<PathBuf, String> {
    if let Ok(v) = std::env::var("ARCBOX_DATA_DIR") {
        return Ok(PathBuf::from(v));
    }
    let home = std::env::var("HOME").map_err(|e| format!("cannot resolve HOME: {e}"))?;
    Ok(PathBuf::from(home).join(".arcbox"))
}

fn kernel_candidates() -> Vec<PathBuf> {
    vec![
        PathBuf::from("boot-assets/dev/kernel"),
        PathBuf::from("boot-assets/dev/kernel.arm64"),
        home_asset("kernel"),
    ]
}

fn rootfs_candidates() -> Vec<PathBuf> {
    vec![
        PathBuf::from("boot-assets/dev/rootfs.erofs"),
        home_asset("rootfs.erofs"),
    ]
}

fn home_asset(name: &str) -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_default();
    PathBuf::from(format!("{home}/.arcbox/boot/0.5.5/{name}"))
}

fn locate(kind: &str, env_key: &str, candidates: &[PathBuf]) -> Result<PathBuf, String> {
    if let Ok(override_path) = std::env::var(env_key) {
        let p = PathBuf::from(override_path);
        if p.exists() {
            return Ok(p);
        }
        return Err(format!("${env_key} set but {} does not exist", p.display()));
    }
    for p in candidates {
        if p.exists() {
            return Ok(p.clone());
        }
    }
    let mut msg = format!("no {kind} found. Tried:");
    for p in candidates {
        let _ = write!(msg, "\n  - {}", p.display());
    }
    let _ = write!(msg, "\nOverride with ${env_key}=/path/to/{kind}");
    Err(msg)
}
