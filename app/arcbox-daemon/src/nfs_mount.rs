//! Host-side NFSv4 mount of the guest docker data export at `~/ArcBox`.
//!
//! The guest agent exports `/var/lib/docker` read-only over NFSv4, which serves
//! everything on the single well-known port 2049 (no MOUNT protocol). This
//! module runs one localhost TCP proxy and bridges it to the guest over vsock:
//!
//! ```text
//! mount_nfs -o vers=4,port=<nfsd> 127.0.0.1:/ ~/ArcBox
//!   └─ 127.0.0.1:<nfsd> → vsock NFS_NFSD_RELAY_PORT → guest 127.0.0.1:2049
//! ```
//!
//! Readiness needs no separate probe: the reconcile simply retries `mount_nfs`
//! until the guest server answers, so the mount is its own liveness check and
//! the path works identically on the HV and VZ backends.

use std::os::fd::{FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use arcbox_constants::ports::NFS_NFSD_RELAY_PORT;
use arcbox_core::{DEFAULT_MACHINE_NAME, Runtime, VmLifecycleState};
use arcbox_transport::vsock::{VsockShutdown, VsockStream};
use tokio::io::copy_bidirectional;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::context::DaemonContext;

const MOUNT_TIMEOUT: Duration = Duration::from_secs(30);
const MOUNT_RETRY_INTERVAL: Duration = Duration::from_millis(500);
/// Shutdown may make two attempts; their 10s total is part of launchd's
/// 45s budget.
const UNMOUNT_TIMEOUT: Duration = Duration::from_secs(5);
/// Pause before retrying a failed incarnation, so a guest that is up but not
/// yet able to serve the export is retried without spinning.
const RETRY_BACKOFF: Duration = Duration::from_secs(30);

/// Path this daemon successfully mounted, set once by the reconcile task.
/// [`cleanup`] only unmounts what this process created — a daemon that never
/// completed its mount must not unmount whatever else sits at `~/ArcBox`.
static MOUNTED_PATH: OnceLock<PathBuf> = OnceLock::new();

/// Spawns the background task that mounts the guest export at `~/ArcBox`.
pub fn spawn(ctx: &DaemonContext, runtime: &Arc<Runtime>) {
    if !ctx.mount_nfs {
        return;
    }

    // Same gate as the HostsAlias self-setup task in `recovery`: only a
    // canonical-data-dir daemon has that task racing this reconcile, so only
    // it should wait for the alias before the first mount attempt.
    let expect_hosts_alias = ctx.layout.data_dir
        == arcbox_constants::paths::HostLayout::resolve_for_profile_from_env(ctx.profile, None)
            .data_dir;

    let runtime = Arc::clone(runtime);
    let shutdown = ctx.shutdown.clone();
    tokio::spawn(async move {
        if let Err(e) = reconcile(runtime, shutdown, expect_hosts_alias).await {
            warn!(error = %e, "failed to establish host NFS mount at ~/ArcBox");
        }
    });
}

/// Unmounts `~/ArcBox` on shutdown, but only the mount this daemon created.
pub async fn cleanup(ctx: &DaemonContext) {
    if !ctx.mount_nfs {
        return;
    }

    // Never mounted (startup raced shutdown, or the mount failed): whatever
    // sits at the path is not ours to touch.
    let Some(mount_path) = MOUNTED_PATH.get() else {
        return;
    };

    // Re-check the shape in case the user replaced the mount since.
    match current_mount_info(mount_path) {
        Some(info) if is_arcbox_nfs_mount(&info) => match unmount(mount_path).await {
            Ok(()) => info!(path = %mount_path.display(), "unmounted ~/ArcBox host NFS mount"),
            Err(e) => warn!(path = %mount_path.display(), error = %e, "failed to unmount ~/ArcBox"),
        },
        _ => {}
    }
}

async fn reconcile(
    runtime: Arc<Runtime>,
    shutdown: CancellationToken,
    expect_hosts_alias: bool,
) -> Result<()> {
    let Some(mount_path) = resolve_mount_path() else {
        bail!("could not determine home directory for ~/ArcBox mount");
    };

    // One localhost TCP proxy to the guest nfsd, bridged over vsock. It outlives
    // VM restarts: each connection dials `connect_vsock_port` against whatever
    // guest is current, so the same local port keeps working across reboots.
    let nfsd_port = spawn_proxy(&runtime, &shutdown, NFS_NFSD_RELAY_PORT).await?;

    // Re-establish the export for every VM incarnation. The agent no longer
    // starts nfsd on its own, so each guest — the first boot and every restart
    // (backend switch, crash recovery) — has no NFS server until we ask; a
    // `--no-mount-nfs` daemon never reaches here, so its guests run none.
    //
    // The trigger is the lifecycle *ready* edge, never the restart generation:
    // that counter is bumped when the VM stops, so acting on it would send the
    // request into the gap where no guest exists and burn the retry budget on a
    // VM that is still booting — or, after a plain `arcbox stop`, on one that is
    // not coming back until the next on-demand start.
    let mut state = runtime.subscribe_system_vm_state();
    let mut first = true;

    while wait_for_state(&mut state, &shutdown, VmLifecycleState::is_ready).await {
        // The one fatal condition: the mount point holds a mount this daemon
        // did not create, and no retry or VM restart can free it.
        let occupancy = classify_mount_point(&mount_path)?;

        // The hosts alias only needs waiting for on the very first mount.
        if first && expect_hosts_alias {
            wait_for_hosts_alias(&shutdown).await;
        }
        first = false;

        // A failed attempt must not end the supervisor: the next ready VM — or
        // this one after a backoff — gets another chance. Losing the loop would
        // leave every later incarnation with no nfsd at all.
        if let Err(e) = establish(&runtime, occupancy, &mount_path, nfsd_port, &shutdown).await {
            if shutdown.is_cancelled() {
                break;
            }
            warn!(error = %e, "could not establish the ~/ArcBox export; retrying");
            if !sleep_unless_shutdown(RETRY_BACKOFF, &shutdown).await {
                break;
            }
            continue;
        }

        // Hold until this incarnation goes away, then loop to rebuild the
        // export on the next guest and remount over the now-stale mount.
        if !wait_for_state(&mut state, &shutdown, |s| !s.is_ready()).await {
            break;
        }
        info!("system VM stopped; the ~/ArcBox export will be rebuilt when it returns");
    }
    Ok(())
}

/// Brings the guest export up and mounts it — the per-incarnation work.
///
/// Everything here is retryable, including reclaiming our own stale mount: the
/// previous incarnation's mount can take a moment to release once its guest is
/// gone, and a failed `umount` must not be terminal.
async fn establish(
    runtime: &Arc<Runtime>,
    occupancy: MountPoint,
    mount_path: &Path,
    nfsd_port: u16,
    shutdown: &CancellationToken,
) -> Result<()> {
    if occupancy == MountPoint::Stale {
        info!(path = %mount_path.display(), "replacing stale ~/ArcBox NFS mount");
        unmount(mount_path).await?;
    }
    std::fs::create_dir_all(mount_path)?;

    // The request must actually land — a pre-delivery failure (agent still
    // coming up, connect/send error) leaves the guest with no nfsd and the
    // mount below could only retry forever, so retry until the agent confirms.
    ensure_guest_export(runtime, shutdown).await?;
    mount_with_retry(mount_path, nfsd_port, shutdown).await
}

/// Waits until the System VM's lifecycle state satisfies `pred`.
///
/// Returns `false` when the daemon shut down or the lifecycle manager was
/// dropped first — in both cases there is nothing left to reconcile.
async fn wait_for_state(
    state: &mut watch::Receiver<VmLifecycleState>,
    shutdown: &CancellationToken,
    pred: fn(&VmLifecycleState) -> bool,
) -> bool {
    loop {
        if shutdown.is_cancelled() {
            return false;
        }
        if pred(&state.borrow_and_update()) {
            return true;
        }
        tokio::select! {
            biased;
            () = shutdown.cancelled() => return false,
            changed = state.changed() => {
                if changed.is_err() {
                    return false;
                }
            }
        }
    }
}

/// Sleeps for `duration`, returning `false` if the daemon shut down instead.
async fn sleep_unless_shutdown(duration: Duration, shutdown: &CancellationToken) -> bool {
    tokio::select! {
        biased;
        () = shutdown.cancelled() => false,
        () = tokio::time::sleep(duration) => true,
    }
}

/// Asks the guest agent to bring up the export, retrying until it confirms,
/// the deadline passes, or shutdown.
///
/// A pre-delivery failure must be retried, not swallowed: the agent no longer
/// starts nfsd on its own, so if the request never lands the guest has no
/// server and `mount_with_retry` can only fail.
///
/// The caller only sends once the VM is ready, so the agent is up — but the
/// handler takes the runtime-start lock, which the in-flight dockerd start
/// holds for far longer (its own budget is 150s), and neither transport
/// self-limits usefully across that: the HV blocking RPC deadline (5s) is much
/// shorter, and the VZ async path has no read deadline at all, so an unbounded
/// attempt could hang the reconcile until — or past — a wedged runtime start.
/// Bounding each attempt and racing shutdown makes both backends retry across
/// that window, and the handler is idempotent so a retry after the export is
/// already up just confirms it.
async fn ensure_guest_export(runtime: &Arc<Runtime>, shutdown: &CancellationToken) -> Result<()> {
    const ENSURE_TIMEOUT: Duration = Duration::from_secs(120);
    const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(15);
    const RETRY_INTERVAL: Duration = Duration::from_secs(1);

    let deadline = tokio::time::Instant::now() + ENSURE_TIMEOUT;
    loop {
        let attempt = tokio::select! {
            biased;
            () = shutdown.cancelled() => {
                bail!("daemon shutdown before the guest NFS export was established");
            }
            result = tokio::time::timeout(ATTEMPT_TIMEOUT, send_ensure_export(runtime)) => result,
        };
        match attempt {
            Ok(Ok(notes)) => {
                debug!(notes = ?notes, "guest nfs export ensured");
                return Ok(());
            }
            outcome if tokio::time::Instant::now() >= deadline => {
                return match outcome {
                    Ok(Err(e)) => Err(e).context("guest did not establish the NFS export in time"),
                    _ => Err(anyhow::anyhow!(
                        "guest did not establish the NFS export within {ENSURE_TIMEOUT:?}"
                    )),
                };
            }
            Ok(Err(e)) => debug!(error = %e, "ensure guest nfs export attempt failed, retrying"),
            Err(_) => debug!("ensure guest nfs export attempt timed out, retrying"),
        }
        tokio::select! {
            biased;
            () = shutdown.cancelled() => {
                bail!("daemon shutdown before the guest NFS export was established");
            }
            () = tokio::time::sleep(RETRY_INTERVAL) => {}
        }
    }
}

/// One `EnsureNfsExport` round-trip to the guest agent.
///
/// `connect_agent` is a blocking hypervisor call on both backends; on HV the
/// whole agent transport is blocking, on VZ only the connect is. Mirrors the
/// `sync_guest_clock` backend dispatch in `arcbox-core`.
async fn send_ensure_export(runtime: &Arc<Runtime>) -> Result<Vec<String>> {
    let machine = DEFAULT_MACHINE_NAME.to_string();
    let rt = Arc::clone(runtime);
    let mut agent = tokio::task::spawn_blocking(move || rt.get_agent(&machine)).await??;
    let resp = if agent.is_blocking() {
        tokio::task::spawn_blocking(move || agent.ensure_nfs_export_blocking()).await??
    } else {
        agent.ensure_nfs_export().await?
    };
    Ok(resp.notes)
}

/// Bounded wait for the `ArcBox` hosts alias the concurrent self-setup task
/// installs on canonical daemons.
///
/// The retry loop exits on its first successful mount, so without this a
/// fresh install whose guest export comes up before the helper finishes
/// would stick with the `127.0.0.1:/` source until the next daemon restart.
/// Bounded: a helperless setup (CLI-only install where self-setup is
/// skipped) proceeds after the window and simply mounts by loopback.
async fn wait_for_hosts_alias(shutdown: &CancellationToken) {
    const ALIAS_WAIT: Duration = Duration::from_secs(10);

    let deadline = tokio::time::Instant::now() + ALIAS_WAIT;
    while !hosts_alias_installed() && !shutdown.is_cancelled() {
        if tokio::time::Instant::now() >= deadline {
            debug!("hosts alias did not appear; mounting by loopback");
            return;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// Binds a localhost TCP proxy that relays each connection to `vsock_port` on
/// the guest, and returns the local port it is listening on.
async fn spawn_proxy(
    runtime: &Arc<Runtime>,
    shutdown: &CancellationToken,
    vsock_port: u32,
) -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let local_port = listener.local_addr()?.port();
    debug!(local_port, vsock_port, "NFS proxy listening");

    let runtime = Arc::clone(runtime);
    let shutdown = shutdown.clone();
    tokio::spawn(run_proxy(listener, runtime, shutdown, vsock_port));
    Ok(local_port)
}

async fn run_proxy(
    listener: TcpListener,
    runtime: Arc<Runtime>,
    shutdown: CancellationToken,
    vsock_port: u32,
) {
    loop {
        let stream = tokio::select! {
            biased;
            () = shutdown.cancelled() => return,
            result = listener.accept() => match result {
                Ok((stream, _)) => stream,
                Err(e) => {
                    warn!(vsock_port, error = %e, "NFS proxy accept failed");
                    continue;
                }
            }
        };

        let runtime = Arc::clone(&runtime);
        tokio::spawn(async move {
            if let Err(e) = relay_connection(stream, runtime, vsock_port).await {
                debug!(vsock_port, error = %e, "NFS proxy relay failed");
            }
        });
    }
}

async fn relay_connection(
    mut tcp: tokio::net::TcpStream,
    runtime: Arc<Runtime>,
    vsock_port: u32,
) -> Result<()> {
    // connect_vsock_port is a blocking hypervisor call on both backends.
    let fd = tokio::task::spawn_blocking(move || {
        runtime.connect_vsock_port(DEFAULT_MACHINE_NAME, vsock_port)
    })
    .await??;

    // SAFETY: `fd` is a valid, newly-opened vsock fd handed over by the
    // hypervisor layer; ownership transfers to the OwnedFd here.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut vsock = VsockStream::from_fd_with_shutdown(owned, VsockShutdown::CloseOnDropOnly)?;

    copy_bidirectional(&mut tcp, &mut vsock).await?;
    Ok(())
}

/// Retries `mount_nfs` until it succeeds, the deadline passes, or shutdown.
///
/// The guest export comes up shortly after dockerd; while it is not yet
/// answering, `mount_nfs` fails fast (the guest relay resets the connection),
/// so retrying is the readiness signal.
async fn mount_with_retry(
    mount_path: &Path,
    nfsd_port: u16,
    shutdown: &CancellationToken,
) -> Result<()> {
    let opts = render_mount_opts(nfsd_port);
    let deadline = tokio::time::Instant::now() + MOUNT_TIMEOUT;

    loop {
        if shutdown.is_cancelled() {
            bail!("daemon shutdown before ~/ArcBox mount completed");
        }

        // Re-evaluated each attempt: on a fresh install the self-setup task
        // writes the hosts alias concurrently with this retry loop, and the
        // mount should pick the friendly source up as soon as it lands.
        let source = mount_source();

        match run_mount(&opts, &source, mount_path).await {
            Ok(()) => {
                let _ = MOUNTED_PATH.set(mount_path.to_path_buf());
                info!(
                    path = %mount_path.display(),
                    nfsd_port,
                    "mounted guest docker data at ~/ArcBox (NFSv4, read-only)"
                );
                return Ok(());
            }
            Err(e) if tokio::time::Instant::now() >= deadline => {
                bail!("mount_nfs did not succeed within {MOUNT_TIMEOUT:?}: {e}");
            }
            Err(e) => debug!(error = %e, "mount_nfs attempt failed, retrying"),
        }

        tokio::time::sleep(MOUNT_RETRY_INTERVAL).await;
    }
}

async fn run_mount(opts: &str, source: &str, mount_path: &Path) -> Result<(), String> {
    let opts = opts.to_string();
    let source = source.to_string();
    let mount_path = mount_path.to_path_buf();

    tokio::task::spawn_blocking(move || {
        let output = Command::new("/sbin/mount_nfs")
            .arg("-o")
            .arg(&opts)
            .arg(&source)
            .arg(&mount_path)
            .output()
            .map_err(|e| format!("failed to execute mount_nfs: {e}"))?;

        if output.status.success() {
            Ok(())
        } else {
            Err(format!(
                "mount_nfs exited with {}: {}",
                output.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&output.stderr).trim()
            ))
        }
    })
    .await
    .map_err(|e| format!("mount_nfs task panicked: {e}"))?
}

/// The `host:/path` source string for `mount_nfs`. The export carries
/// `fsid=0`, so it is the NFSv4 pseudo-root at `/`.
///
/// Finder's Locations sidebar displays a network mount by its source host
/// name, so when the helper-managed `/etc/hosts` alias is present the
/// source is `ArcBox:/` (an "ArcBox" location) rather than "127.0.0.1".
/// The check reads `/etc/hosts` directly — never DNS — so a missing alias
/// costs nothing and a user's own unrelated `ArcBox` entry is not trusted.
fn mount_source() -> String {
    mount_source_for(hosts_alias_installed())
}

/// True when `/etc/hosts` carries the helper-managed alias line right now.
fn hosts_alias_installed() -> bool {
    std::fs::read_to_string("/etc/hosts")
        .is_ok_and(|content| arcbox_helper::hosts_alias_installed(&content))
}

fn mount_source_for(alias_installed: bool) -> String {
    if alias_installed {
        format!("{}:/", arcbox_helper::HOSTS_ALIAS_NAME)
    } else {
        "127.0.0.1:/".to_string()
    }
}

/// Read-only NFSv4 mount options with the nfsd port pinned.
///
/// - `deadtimeout=60`: a vanished VM makes the mount fail I/O after 60s instead
///   of hanging Finder forever (macOS rejects `soft` with `vers=4`).
/// - `rdirplus`: fetch attributes with directory entries — fewer round trips.
/// - `actimeo=10`: modest attribute cache for a browse mount.
/// - `noowners`: display-only owner mapping (ABX-427). The guest's uids are
///   meaningless on the host, so the export otherwise lists as `root` and bare
///   numbers. This is `MNT_IGNORE_OWNERSHIP` — Finder's "Ignore ownership on
///   this volume" — under which every object reports uid 99, which the VFS
///   renders as the *current* user. Presentational only, and safe precisely
///   because it is: the server stays the sole authority (`ro` export,
///   `all_squash,anonuid=0`, so it already evaluates ACCESS as root), and the
///   mount is `ro` besides. The local check it drops was only ever able to
///   refuse reads the server would have granted.
fn render_mount_opts(nfsd_port: u16) -> String {
    format!("ro,noowners,vers=4,rdirplus,actimeo=10,deadtimeout=60,port={nfsd_port}")
}

/// Host mount point: `$ARCBOX_HOST_MOUNT_DIR` when set (so a test daemon stays
/// off the shared `~/ArcBox`), otherwise `~/ArcBox`.
fn resolve_mount_path() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("ARCBOX_HOST_MOUNT_DIR") {
        return Some(PathBuf::from(dir));
    }
    dirs::home_dir().map(|home| resolve_mount_path_from_home(&home))
}

fn resolve_mount_path_from_home(home: &Path) -> PathBuf {
    home.join("ArcBox")
}

/// What currently holds the mount point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MountPoint {
    /// Nothing mounted there — free to use.
    Free,
    /// A mount matching our exact shape, left over from a previous daemon or a
    /// previous incarnation whose guest is gone. Dead weight; reclaimable.
    Stale,
}

/// Classifies the mount point, erroring when it is held by a mount this daemon
/// did not create.
///
/// Anything that is not our own shape — including a foreign NFS mount — is
/// someone else's, and no retry or VM restart can free it, so it is the one
/// condition that ends the reconcile.
fn classify_mount_point(mount_path: &Path) -> Result<MountPoint> {
    match current_mount_info(mount_path) {
        None => Ok(MountPoint::Free),
        Some(info) if is_arcbox_nfs_mount(&info) => Ok(MountPoint::Stale),
        Some(info) => bail!(
            "~/ArcBox path {} already occupied by {} ({})",
            mount_path.display(),
            info.source,
            info.fstype
        ),
    }
}

/// True when the mount at the path has exactly the shape this daemon creates:
/// NFS from the v4 pseudo-root of the localhost proxy, under either source
/// spelling (the loopback literal, or the `ArcBox` hosts alias) — a stale
/// mount must be reclaimable regardless of which name it was created with.
fn is_arcbox_nfs_mount(info: &MountInfo) -> bool {
    info.fstype == "nfs"
        && (info.source == mount_source_for(false) || info.source == mount_source_for(true))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MountInfo {
    source: String,
    fstype: String,
}

fn current_mount_info(path: &Path) -> Option<MountInfo> {
    let output = Command::new("/sbin/mount").output().ok()?;
    if !output.status.success() {
        return None;
    }

    let target = path.to_string_lossy();
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| match parse_mount_line(line) {
            Some((mountpoint, info)) if mountpoint == target => Some(info),
            _ => None,
        })
}

/// Parses one `/sbin/mount` line: `SOURCE on MOUNTPOINT (fstype, opts…)`.
fn parse_mount_line(line: &str) -> Option<(&str, MountInfo)> {
    let (source, rest) = line.split_once(" on ")?;
    let (mountpoint, suffix) = rest.split_once(" (")?;
    let fstype = suffix
        .split([',', ')'])
        .next()
        .unwrap_or_default()
        .trim()
        .to_string();

    Some((
        mountpoint,
        MountInfo {
            source: source.to_string(),
            fstype,
        },
    ))
}

async fn unmount(path: &Path) -> Result<()> {
    let mut command = tokio::process::Command::new("/sbin/umount");
    command.arg(path).kill_on_drop(true);
    let status = tokio::time::timeout(UNMOUNT_TIMEOUT, command.status())
        .await
        .context("umount timed out")??;
    if status.success() {
        Ok(())
    } else {
        bail!("umount exited with {}", status.code().unwrap_or(-1))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MountInfo, VmLifecycleState, is_arcbox_nfs_mount, mount_source_for, parse_mount_line,
        render_mount_opts, resolve_mount_path_from_home, wait_for_state,
    };
    use std::path::{Path, PathBuf};
    use tokio::sync::watch;
    use tokio_util::sync::CancellationToken;

    #[test]
    fn only_our_exact_mount_shape_is_reclaimed() {
        // Both source spellings are ours — loopback (no hosts alias) and
        // the branded alias name.
        for source in ["127.0.0.1:/", "ArcBox:/"] {
            let ours = MountInfo {
                source: source.to_string(),
                fstype: "nfs".to_string(),
            };
            assert!(is_arcbox_nfs_mount(&ours), "{source} should be reclaimed");
        }

        // A user's own NFS mount at ~/ArcBox must never be unmounted.
        let foreign_nfs = MountInfo {
            source: "fileserver:/export/home".to_string(),
            fstype: "nfs".to_string(),
        };
        assert!(!is_arcbox_nfs_mount(&foreign_nfs));

        let smb = MountInfo {
            source: "//user@server/share".to_string(),
            fstype: "smbfs".to_string(),
        };
        assert!(!is_arcbox_nfs_mount(&smb));
    }

    #[test]
    fn mount_path_is_arcbox_under_home() {
        assert_eq!(
            resolve_mount_path_from_home(Path::new("/Users/tester")),
            PathBuf::from("/Users/tester/ArcBox")
        );
    }

    #[test]
    fn mount_opts_are_readonly_v4_with_nfsd_port_pinned() {
        let opts = render_mount_opts(51000);
        assert!(opts.contains("vers=4"));
        assert!(opts.contains("ro,"));
        assert!(opts.contains("port=51000"));
        // Must never request write access to a read-only export.
        assert!(!opts.contains("rw"));
        // Guest uids mean nothing on the host; show the browsing user instead.
        assert!(opts.contains("noowners"));
    }

    #[test]
    fn mount_source_is_the_v4_pseudo_root_under_both_names() {
        assert_eq!(mount_source_for(false), "127.0.0.1:/");
        assert_eq!(mount_source_for(true), "ArcBox:/");
    }

    /// The whole point of watching lifecycle state instead of the restart
    /// generation: the export must be (re)built when a guest arrives, not when
    /// one leaves. `Stopped` is where the generation counter fires — waiting
    /// there would send the request into the gap with no guest in it.
    #[tokio::test]
    async fn ready_wait_resumes_on_the_arrival_edge_not_the_departure() {
        let (tx, mut rx) = watch::channel(VmLifecycleState::Running);
        let shutdown = CancellationToken::new();

        // A running VM satisfies the predicate immediately.
        assert!(wait_for_state(&mut rx, &shutdown, VmLifecycleState::is_ready).await);

        // Departure: intermediate states must not be mistaken for arrival.
        for state in [VmLifecycleState::Stopping, VmLifecycleState::Stopped] {
            tx.send_replace(state);
            assert!(wait_for_state(&mut rx, &shutdown, |s| !s.is_ready()).await);
        }

        // A restart passes through Starting, which is not yet usable; only
        // Running releases the waiter.
        tx.send_replace(VmLifecycleState::Starting);
        let waiter = tokio::spawn({
            let shutdown = shutdown.clone();
            let mut rx = rx.clone();
            async move { wait_for_state(&mut rx, &shutdown, VmLifecycleState::is_ready).await }
        });
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished(), "Starting is not an arrival");

        tx.send_replace(VmLifecycleState::Running);
        assert!(waiter.await.expect("waiter panicked"));
    }

    #[tokio::test]
    async fn ready_wait_gives_up_on_shutdown_and_on_a_dropped_lifecycle() {
        let (tx, mut rx) = watch::channel(VmLifecycleState::Stopped);
        let shutdown = CancellationToken::new();
        shutdown.cancel();
        assert!(!wait_for_state(&mut rx, &shutdown, VmLifecycleState::is_ready).await);

        drop(tx);
        let shutdown = CancellationToken::new();
        assert!(!wait_for_state(&mut rx, &shutdown, VmLifecycleState::is_ready).await);
    }

    #[test]
    fn parse_mount_line_extracts_source_and_fstype() {
        let line =
            "127.0.0.1:/run/arcbox/nfs-export/docker on /Users/t/ArcBox (nfs, nodev, read-only)";
        let (mountpoint, info) = parse_mount_line(line).expect("line should parse");
        assert_eq!(mountpoint, "/Users/t/ArcBox");
        assert_eq!(
            info,
            MountInfo {
                source: "127.0.0.1:/run/arcbox/nfs-export/docker".to_string(),
                fstype: "nfs".to_string(),
            }
        );
    }
}
