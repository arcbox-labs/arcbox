//! ABX cold-boot repro: a single cold boot of the HV backend to agent
//! readiness, then exit. Designed to be looped by an external driver
//! (`scripts/hv-coldboot-repro.sh`) because Hypervisor.framework allows only
//! one `hv_vm_create` per process — every cold boot must be a fresh process.
//!
//! It mirrors `hv_e2e` phases 1-3 + 7 (create -> start -> ping-to-ready ->
//! stop) and nothing else, so the only thing it measures is "did the guest
//! agent become reachable over vsock within the timeout". A cold-boot wedge
//! (e.g. a lost blk completion notification) shows up as `RESULT: HANG`.
//!
//! Output contract (parsed by the driver):
//!   `RESULT: PASS <boot_ms> <ready_ms>`   exit 0
//!   `RESULT: HANG <waited_ms>`            exit 2
//!   `RESULT: ERROR <stage> <msg>`         exit 1
//!
//! Env:
//!   ARCBOX_HV_E2E_KERNEL / ARCBOX_HV_E2E_ROOTFS  override asset paths
//!   ARCBOX_REPRO_ASSET_VERSION                   default boot asset dir under
//!                                                ~/.arcbox/boot (default 0.6.1)
//!   ARCBOX_HV_E2E_TIMEOUT                         ready timeout secs (default 30)
//!   ARCBOX_DATA_DIR                               host dir shared at /arcbox
//!                                                (default ~/.arcbox; needs
//!                                                bin/arcbox-agent)

use std::path::PathBuf;
use std::time::{Duration, Instant};

use arcbox_core::AgentClient;
use arcbox_vmm::{BlockDeviceConfig, SharedDirConfig, VmBackend, Vmm, VmmConfig};

const GUEST_CID: u32 = 3;
const AGENT_PORT: u32 = 1024;

fn main() {
    // Quiet by default; the driver wants a clean RESULT line. Opt into guest
    // and device tracing via RUST_LOG when investigating a specific hang.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "warn".parse().unwrap()),
        )
        .with_target(true)
        .init();

    match run() {
        Ok(Outcome {
            boot_ms,
            ready_ms,
            runtime_ms,
            runtime_status,
        }) => {
            println!("RESULT: PASS {boot_ms} {ready_ms} {runtime_ms} {runtime_status}");
            std::process::exit(0);
        }
        Err(Failure::Hang { stage, waited_ms }) => {
            println!("RESULT: HANG {stage} {waited_ms}");
            std::process::exit(2);
        }
        Err(Failure::Error { stage, msg }) => {
            println!("RESULT: ERROR {stage} {msg}");
            std::process::exit(1);
        }
    }
}

struct Outcome {
    boot_ms: u128,
    ready_ms: u128,
    /// `ensure_runtime` round-trip in ms, or `-1` if the runtime stage was
    /// disabled (ARCBOX_REPRO_RUNTIME=0).
    runtime_ms: i128,
    /// `ensure_runtime` status string ("started"/"reused") or "skipped".
    runtime_status: String,
}

enum Failure {
    Hang {
        stage: &'static str,
        waited_ms: u128,
    },
    Error {
        stage: &'static str,
        msg: String,
    },
}

fn err(stage: &'static str) -> impl Fn(String) -> Failure {
    move |msg| Failure::Error { stage, msg }
}

fn run() -> Result<Outcome, Failure> {
    let kernel_path = locate("ARCBOX_HV_E2E_KERNEL", "kernel").map_err(err("locate"))?;
    let rootfs_path = locate("ARCBOX_HV_E2E_ROOTFS", "rootfs.erofs").map_err(err("locate"))?;
    let boot_timeout = std::env::var("ARCBOX_HV_E2E_TIMEOUT")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .map_or_else(|| Duration::from_secs(30), Duration::from_secs);

    let share_dir = resolve_data_dir().map_err(err("share"))?;
    if !share_dir.join("bin/arcbox-agent").exists() {
        return Err(Failure::Error {
            stage: "share",
            msg: format!("bin/arcbox-agent not found under {}", share_dir.display()),
        });
    }

    let config = VmmConfig {
        vcpu_count: 2,
        memory_size: 1024 * 1024 * 1024,
        kernel_path,
        kernel_cmdline:
            "console=hvc0 root=/dev/vda ro rootfstype=erofs earlycon=pl011,0x0b000000 loglevel=4 panic=10"
                .to_string(),
        initrd_path: None,
        enable_rosetta: false,
        serial_console: true,
        virtio_console: true,
        shared_dirs: vec![SharedDirConfig {
            host_path: share_dir,
            tag: "arcbox".to_string(),
            read_only: false,
        }],
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
        debug_console_socket: None,
    };

    let mut vmm = Vmm::new(config).map_err(|e| Failure::Error {
        stage: "new",
        msg: e.to_string(),
    })?;

    let t_boot = Instant::now();
    vmm.start().map_err(|e| Failure::Error {
        stage: "start",
        msg: e.to_string(),
    })?;
    let boot_ms = t_boot.elapsed().as_millis();

    let t_ready = Instant::now();
    let ready = ping_with_timeout(&vmm, boot_timeout);
    let ready_ms = t_ready.elapsed().as_millis();

    if ready.is_err() {
        let _ = vmm.stop();
        return Err(Failure::Hang {
            stage: "agent",
            waited_ms: ready_ms,
        });
    }

    // Runtime stage: drive the "Starting Docker engine" path via
    // `ensure_runtime`. A lost blk completion during the runtime's heavy disk
    // I/O would wedge the agent's call -> RPC times out -> HANG runtime.
    // Disable with ARCBOX_REPRO_RUNTIME=0 to measure agent-ready only.
    let run_runtime = std::env::var("ARCBOX_REPRO_RUNTIME").map_or(true, |v| v != "0");
    let (runtime_ms, runtime_status) = if run_runtime {
        let runtime_timeout = std::env::var("ARCBOX_REPRO_RUNTIME_TIMEOUT")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .map_or_else(|| Duration::from_secs(60), Duration::from_secs);
        let t_rt = Instant::now();
        match ensure_runtime(&vmm, runtime_timeout) {
            Ok(status) => (
                i128::try_from(t_rt.elapsed().as_millis()).unwrap_or(i128::MAX),
                status,
            ),
            Err(RuntimeFail::Hang) => {
                let waited = t_rt.elapsed().as_millis();
                let _ = vmm.stop();
                return Err(Failure::Hang {
                    stage: "runtime",
                    waited_ms: waited,
                });
            }
            Err(RuntimeFail::NotReady(status)) => {
                let _ = vmm.stop();
                return Err(Failure::Error {
                    stage: "runtime",
                    msg: format!("not_ready(status={status})"),
                });
            }
        }
    } else {
        (-1, "skipped".to_string())
    };

    let _ = vmm.stop();
    Ok(Outcome {
        boot_ms,
        ready_ms,
        runtime_ms,
        runtime_status,
    })
}

enum RuntimeFail {
    /// The ensure_runtime RPC did not return within the deadline — the wedge
    /// we are hunting (agent blocked waiting for dockerd's stuck disk I/O).
    Hang,
    /// The RPC returned but the runtime is not ready (e.g. dockerd binary
    /// missing in this minimal share) — an environment issue, not a wedge.
    NotReady(String),
}

/// Drives the runtime to readiness. `ensure_runtime` on the agent is
/// non-blocking — it kicks off containerd+dockerd and returns `status=starting`
/// immediately — so we poll until `ready`, the runtime reports `failed`, or the
/// overall deadline elapses. A deadline with the runtime stuck mid-startup is
/// the wedge signal (`Hang`); a clean `failed` is an environment issue
/// (`NotReady`).
fn ensure_runtime(vmm: &Vmm, overall: Duration) -> Result<String, RuntimeFail> {
    let start = Instant::now();
    let mut last_status = String::from("none");
    while start.elapsed() < overall {
        match ensure_runtime_once(vmm, Duration::from_secs(10)) {
            Ok((true, status)) => {
                return Ok(if status.is_empty() {
                    "started".into()
                } else {
                    status
                });
            }
            Ok((false, status)) => {
                if status == "failed" {
                    return Err(RuntimeFail::NotReady("failed".into()));
                }
                last_status = status;
                std::thread::sleep(Duration::from_secs(1));
            }
            // Transient RPC error during startup churn — retry until the
            // deadline rather than declaring a wedge prematurely.
            Err(_) => std::thread::sleep(Duration::from_secs(1)),
        }
    }
    eprintln!("[runtime] deadline reached, last status = {last_status}");
    Err(RuntimeFail::Hang)
}

/// One `ensure_runtime(true)` call over a fresh vsock; returns `(ready, status)`.
fn ensure_runtime_once(vmm: &Vmm, deadline: Duration) -> Result<(bool, String), String> {
    let fd = vmm
        .connect_vsock(AGENT_PORT)
        .map_err(|e| format!("connect_vsock: {e}"))?;
    set_socket_timeout(fd, deadline).map_err(|e| format!("set_socket_timeout: {e}"))?;
    let mut client =
        AgentClient::from_fd_blocking(GUEST_CID, fd).map_err(|e| format!("AgentClient::from_fd_blocking: {e}"))?;
    let resp = client
        .ensure_runtime_blocking(true)
        .map_err(|e| format!("ensure_runtime: {e}"))?;
    Ok((resp.ready, resp.status))
}

fn ping_with_timeout(vmm: &Vmm, overall: Duration) -> Result<(), String> {
    let start = Instant::now();
    let mut last_err = String::from("no attempts made");
    while start.elapsed() < overall {
        match ping_once(vmm, Duration::from_secs(3)) {
            Ok(()) => return Ok(()),
            Err(e) => {
                last_err = e;
                std::thread::sleep(Duration::from_millis(500));
            }
        }
    }
    Err(last_err)
}

fn ping_once(vmm: &Vmm, deadline: Duration) -> Result<(), String> {
    let fd = vmm
        .connect_vsock(AGENT_PORT)
        .map_err(|e| format!("connect_vsock: {e}"))?;
    set_socket_timeout(fd, deadline).map_err(|e| format!("set_socket_timeout: {e}"))?;
    let mut client =
        AgentClient::from_fd_blocking(GUEST_CID, fd).map_err(|e| format!("AgentClient::from_fd_blocking: {e}"))?;
    client
        .ping_blocking()
        .map(|_| ())
        .map_err(|e| format!("ping_blocking: {e}"))
}

fn set_socket_timeout(fd: std::os::unix::io::RawFd, timeout: Duration) -> Result<(), String> {
    let tv_sec = i64::try_from(timeout.as_secs()).unwrap_or(i64::MAX);
    let tv = libc::timeval {
        tv_sec: tv_sec as libc::time_t,
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

fn resolve_data_dir() -> Result<PathBuf, String> {
    if let Ok(v) = std::env::var("ARCBOX_DATA_DIR") {
        return Ok(PathBuf::from(v));
    }
    let home = std::env::var("HOME").map_err(|e| format!("cannot resolve HOME: {e}"))?;
    Ok(PathBuf::from(home).join(".arcbox"))
}

/// Resolves an asset path: `$env_key` if set, else
/// `~/.arcbox/boot/<version>/<name>` (version from `ARCBOX_REPRO_ASSET_VERSION`,
/// default 0.6.1).
fn locate(env_key: &str, name: &str) -> Result<PathBuf, String> {
    if let Ok(p) = std::env::var(env_key) {
        let p = PathBuf::from(p);
        if p.exists() {
            return Ok(p);
        }
        return Err(format!("${env_key} set but {} does not exist", p.display()));
    }
    let version =
        std::env::var("ARCBOX_REPRO_ASSET_VERSION").unwrap_or_else(|_| "0.6.1".to_string());
    let home = std::env::var("HOME").map_err(|e| format!("cannot resolve HOME: {e}"))?;
    let p = PathBuf::from(home)
        .join(".arcbox/boot")
        .join(&version)
        .join(name);
    if p.exists() {
        Ok(p)
    } else {
        Err(format!(
            "{} not found (set ${env_key} or ARCBOX_REPRO_ASSET_VERSION)",
            p.display()
        ))
    }
}
