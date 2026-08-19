//! What the boot flow needs that is not the boot itself: the readiness probe
//! a template's create is gated on, and the rootfs staging a restore shares
//! with it. The flow bodies live in `crate::lifecycle::tasks::boot`, and the
//! actor is what runs them.

use super::*;
use arcbox_snapshot::SnapshotError;

/// Default probe deadline when the template leaves `timeout_seconds` at 0
/// (matches the WaitForPort daemon default).
const READY_PROBE_DEFAULT_TIMEOUT_SECS: u64 = 30;
/// Delay between command-probe attempts.
const READY_PROBE_RETRY_MS: u64 = 500;

/// Run a template's readiness probe against the booted guest (CORE-107).
///
/// Port form: the vm-agent's listen-table watcher — never a connect probe,
/// which would perturb the workload. Command form: a one-shot exec retried
/// until it exits 0 or the deadline elapses.
pub async fn run_ready_probe(
    probe: &crate::template_catalog::ReadyProbeSpec,
    agent: &dyn GuestAgent,
) -> Result<()> {
    use crate::template_catalog::ReadyProbeSpec;
    let effective = |timeout_seconds: u32| {
        std::time::Duration::from_secs(if timeout_seconds == 0 {
            READY_PROBE_DEFAULT_TIMEOUT_SECS
        } else {
            u64::from(timeout_seconds)
        })
    };
    match probe {
        ReadyProbeSpec::Port {
            port,
            timeout_seconds,
        } => match agent
            .wait_for_port(*port, effective(*timeout_seconds))
            .await?
        {
            PortWait::Listening => Ok(()),
            PortWait::Deadline => Err(ComputerError::DeadlineExceeded(format!(
                "no listener on port {port} within the ready-probe deadline"
            ))),
        },
        ReadyProbeSpec::Command {
            cmd,
            timeout_seconds,
        } => {
            let deadline = tokio::time::Instant::now() + effective(*timeout_seconds);
            let mut last_status: Option<String> = None;
            loop {
                // Each attempt is bounded twice over: the host-side timeout
                // caps the await even if the exec stream stalls, and the
                // remaining budget rides StartCommand.timeout_seconds so the
                // guest kills a never-exiting probe process instead of
                // leaking it. Without both, `timeout_seconds` would not be
                // an upper bound at all — a non-exiting probe command parked
                // this await forever.
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    return Err(ComputerError::DeadlineExceeded(format!(
                        "ready-probe command did not exit 0 within the deadline ({})",
                        last_status.as_deref().unwrap_or("no attempt completed")
                    )));
                }
                // The guest kill timer has whole-second granularity; the
                // host timeout enforces the exact remaining budget.
                let budget_secs = u32::try_from(remaining.as_secs().max(1)).unwrap_or(u32::MAX);
                match tokio::time::timeout(remaining, run_probe_command(cmd, agent, budget_secs))
                    .await
                {
                    Ok(Ok(ExitStatus::Code(0))) => return Ok(()),
                    Ok(Ok(status)) => last_status = Some(format!("last exit: {status:?}")),
                    Ok(Err(error)) => last_status = Some(format!("last error: {error}")),
                    Err(_) => {
                        return Err(ComputerError::DeadlineExceeded(format!(
                            "ready-probe command did not exit within the deadline ({})",
                            last_status.as_deref().unwrap_or("no attempt completed")
                        )));
                    }
                }
                if tokio::time::Instant::now() >= deadline {
                    return Err(ComputerError::DeadlineExceeded(format!(
                        "ready-probe command did not exit 0 within the deadline ({})",
                        last_status.as_deref().unwrap_or("no attempt completed")
                    )));
                }
                let nap = std::time::Duration::from_millis(READY_PROBE_RETRY_MS)
                    .min(deadline.saturating_duration_since(tokio::time::Instant::now()));
                tokio::time::sleep(nap).await;
            }
        }
    }
}

/// One probe attempt: run the command and wait for its exit status.
async fn run_probe_command(
    cmd: &[String],
    agent: &dyn GuestAgent,
    timeout_seconds: u32,
) -> Result<ExitStatus> {
    let start = StartCommand {
        cmd: cmd.to_vec(),
        env: HashMap::new(),
        working_dir: String::new(),
        user: String::new(),
        tty: false,
        tty_width: 80,
        tty_height: 24,
        timeout_seconds,
    };
    let (_input, mut output) = agent.exec(start).await?;
    while let Some(chunk) = output.recv().await {
        if let OutputChunk::Exit(status) = chunk? {
            return Ok(status);
        }
    }
    Err(ComputerError::Vsock(
        "probe command stream ended without an exit status".into(),
    ))
}

/// A failed restore-staging step, carrying whichever CoW resources were
/// acquired before the failure so the caller can roll them back.
pub struct StageError {
    pub error: ComputerError,
    pub cow_handle: Option<CowHandle>,
}

/// The root disk as the VM will see it, and the overlay behind it.
pub struct StagedRootfs {
    /// Where the disk is now — the path the spec must name for it.
    pub path: PathBuf,
    /// The copy-on-write overlay the disk is a view of, when that path was
    /// taken; `None` after the full-copy fallback.
    pub cow_handle: Option<CowHandle>,
}

/// Stage `rootfs` as the computer's root disk: a copy-on-write device when
/// device-mapper gives one, a private copy of the template otherwise.
///
/// The decision is the runtime's and cannot be left to the driver: it is
/// made from whether `setup` produced a device *and* whether the driver
/// could bring that device into the VM's area, and the fallback has to
/// tear the overlay down and re-journal before it copies. Everything else
/// about where the disk goes — the name it lands under, whether a
/// confinement exists at all — belongs to [`Staging`] and is not decided
/// here.
///
/// `owner_id` keys the dm/CoW resource names (the computer id, or a pool
/// slot id for pre-warmed slots). `journal` persists the caller's crash
/// record whenever CoW resources appear or disappear, so reconciliation
/// can always identify them.
pub async fn stage_rootfs_cow_or_copy(
    cow_manager: &CowManager,
    staging: &dyn Staging,
    owner_id: &str,
    rootfs: &str,
    journal: &(dyn Fn(Option<&CowHandle>) -> Result<()> + Sync),
) -> std::result::Result<StagedRootfs, StageError> {
    let fail =
        |error: ComputerError, cow_handle: Option<CowHandle>| StageError { error, cow_handle };
    let copy = async || {
        staging
            .stage_disk(ROOTFS_DISK_ID, DiskSource::Image(Path::new(rootfs)))
            .await
            .map_err(ComputerError::from)
    };
    match cow_manager.setup(owner_id, rootfs).await {
        Ok(handle) => {
            if let Err(error) = journal(Some(&handle)) {
                return Err(fail(error, Some(handle)));
            }
            match staging
                .stage_disk(
                    ROOTFS_DISK_ID,
                    DiskSource::Device(Path::new(&handle.dm_device)),
                )
                .await
            {
                Ok(path) => Ok(StagedRootfs {
                    path,
                    cow_handle: Some(handle),
                }),
                Err(e) => {
                    debug!(
                        owner_id,
                        error = %e,
                        "the overlay could not be brought into the vm's area, falling back to a rootfs copy"
                    );
                    if let Err(error) = cow_manager.teardown_checked(&handle).await {
                        return Err(fail(error.into(), Some(handle)));
                    }
                    journal(None).map_err(|error| fail(error, None))?;
                    Ok(StagedRootfs {
                        path: copy().await.map_err(|error| fail(error, None))?,
                        cow_handle: None,
                    })
                }
            }
        }
        Err(e) if matches!(e, SnapshotError::Unavailable(_)) => Err(fail(e.into(), None)),
        Err(e) => {
            debug!(
                owner_id,
                error = %e,
                "dm-snapshot unavailable, staging a copy of the rootfs"
            );
            Ok(StagedRootfs {
                path: copy().await.map_err(|error| fail(error, None))?,
                cow_handle: None,
            })
        }
    }
}

/// Create a stable `{vm_dir}/rootfs.link` symlink pointing at the dm-snapshot
/// device.  Returns the symlink path as a string for Firecracker to use as the
/// rootfs.  The vmstate records this path verbatim, so on restore we can
/// retarget the symlink at a freshly-created dm-snapshot without FC noticing.
///
/// Removes any stale symlink first so a previous crash doesn't cause EEXIST.
pub fn create_rootfs_symlink(vm_dir: &Path, dm_device: &str) -> Result<String> {
    let link_path = vm_dir.join("rootfs.link");
    let _ = std::fs::remove_file(&link_path);
    std::os::unix::fs::symlink(dm_device, &link_path).map_err(ComputerError::Io)?;
    link_path
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| ComputerError::Config(format!("non-UTF-8 path: {}", link_path.display())))
}
