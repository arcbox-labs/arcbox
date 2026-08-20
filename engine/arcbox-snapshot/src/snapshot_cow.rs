//! Block-level copy-on-write for sandbox rootfs via dm-snapshot.
//!
//! Instead of copying the full rootfs ext4 image for every sandbox,
//! `CowManager` creates a dm-snapshot backed by a sparse COW file.
//! The template image is shared read-only across all sandboxes that
//! use the same rootfs; only written blocks consume disk space.
//!
//! Requires `CONFIG_DM_SNAPSHOT=y` in the kernel, a `dmsetup` binary at one
//! of [`CowOptions::dmsetup_candidates`], and loop-device tooling supplied
//! through the [`BlockTools`] seam ([`BusyboxBlockTools`] is the reference:
//! the System VM's busybox applets; [`UtilLinuxBlockTools`] is the stock
//! distro's `/sbin` userland). `PATH` is never searched — neither the
//! guest nor a node agent has a meaningful one, so both implementations
//! take absolute paths.

use std::collections::HashMap;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
#[cfg(any(test, feature = "test-probe"))]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::Mutex as AsyncMutex;
use tracing::{debug, info, warn};

use crate::error::{Result, SnapshotError};

mod block_tools;
mod persistence;

pub use block_tools::{
    BlockTools, BusyboxBlockTools, UtilLinuxBlockTools, device_major_minor, mknod_blkdev,
};
use persistence::{
    SetupOrphan, clear_owner_marker, loop_backs_path, loop_devices_for_backing_sync,
    remove_file_durable,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Reference search list for the `dmsetup` binary.  The first existing,
/// working entry wins.  `/usr/sbin/dmsetup` covers usrmerged distros,
/// `/sbin/dmsetup` stock Debian/Alpine.  A composer with a bundled copy
/// (the System VM ships one under `/arcbox/bin`) lists it first through
/// [`CowOptions::dmsetup_candidates`].
const DMSETUP_CANDIDATES: &[&str] = &["/usr/sbin/dmsetup", "/sbin/dmsetup"];

/// dm-snapshot chunk size in 512-byte sectors (4096 bytes = 8 sectors).
const SNAPSHOT_CHUNK_SECTORS: u64 = 8;

/// Device-mapper name prefix for sandbox snapshots.
///
/// Public with [`COW_FILE_PREFIX`] and [`COW_FILE_SUFFIX`] because the
/// convention has an inverse: [`CowManager::reconcile_stale`] reads an
/// owner back out of a name on the host, and a composer holding a durable
/// record it cannot otherwise interpret does the same to decide what that
/// record still names. One definition, so the two directions cannot drift.
pub const DM_NAME_PREFIX: &str = "arcbox-snap-";

/// File-name prefix of a sandbox's copy-on-write overlay, under `cow_dir`.
pub const COW_FILE_PREFIX: &str = "arcbox-cow-";

/// File-name suffix of a sandbox's copy-on-write overlay. Optional when
/// reading one back: `reconcile_stale` accepts a name without it.
pub const COW_FILE_SUFFIX: &str = ".img";

/// Maximum length of a device-mapper name (DM_NAME_LEN - 1, from linux/dm-ioctl.h).
const DM_NAME_MAX_LEN: usize = 127;

/// Subdirectory of `cow_dir` holding template-loop marker files for
/// crash recovery.  Each file is named after the loop's basename (e.g.
/// `loop0`) and contains the absolute path of the backing template; on
/// startup we use these to identify *our* attached read-only loops
/// rather than every read-only loop on the system.
const TEMPLATE_LOOP_DIR: &str = ".template-loops";
const TEMPLATE_PENDING_PREFIX: &str = "pending-";
const TEMPLATE_MARKER_TEMP_PREFIX: &str = ".tmp-";

/// Whether device-mapper holds a device by this name.
///
/// Asked of the kernel rather than of `/dev/mapper`, because that directory
/// is only as good as the udev rules that populate it: a teardown reading a
/// missing symlink as a missing device skips the removal and reports success,
/// leaving the device and everything under it attached for good.
fn dm_present(dm_name: &str) -> bool {
    Path::new(&format!("/dev/mapper/{dm_name}")).exists() || devtmpfs_dm_node(dm_name).is_some()
}

/// The kernel's own node for `dm_name`, found by matching `dm/name` in sysfs.
fn devtmpfs_dm_node(dm_name: &str) -> Option<String> {
    std::fs::read_dir("/sys/block")
        .ok()?
        .flatten()
        .find_map(|entry| -> Option<String> {
            let name = entry.file_name();
            let device = name.to_str().filter(|name| name.starts_with("dm-"))?;
            let mapped = std::fs::read_to_string(entry.path().join("dm/name")).ok()?;
            (mapped.trim() == dm_name).then(|| format!("/dev/{device}"))
        })
}

/// Validate that `sandbox_id` can be used as the suffix of a dm-name.
///
/// Device-mapper allows `[A-Za-z0-9_+.-]` (see kernel `validate_name`).
/// Sandboxes are most commonly UUIDs, which already pass; this rejects
/// caller-supplied IDs containing whitespace, `/`, `:`, etc., before
/// `dmsetup create` errors out with a confusing message.
fn validate_dm_name_suffix(sandbox_id: &str) -> Result<()> {
    if sandbox_id.is_empty() {
        return Err(SnapshotError::DeviceMapper("empty sandbox id".into()));
    }
    if DM_NAME_PREFIX.len() + sandbox_id.len() > DM_NAME_MAX_LEN {
        return Err(SnapshotError::DeviceMapper(format!(
            "sandbox id too long for dm-name (max {} chars after prefix)",
            DM_NAME_MAX_LEN - DM_NAME_PREFIX.len()
        )));
    }
    if let Some(bad) = sandbox_id
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '+' | '.' | '-')))
    {
        return Err(SnapshotError::DeviceMapper(format!(
            "sandbox id contains character {bad:?} not allowed in dm-name"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Tracks a read-only loop device for a template rootfs image.
struct TemplateEntry {
    /// Loop device path, e.g. `/dev/loop0`.
    loop_device: String,
    /// Template size in 512-byte sectors.
    sectors: u64,
    /// Number of active sandboxes using this template.
    refcount: usize,
}

/// Per-sandbox CoW state.  Stored in `SandboxInstance` for cleanup.
///
/// Intentionally `!Clone`: every handle owns a refcount on its template,
/// and a stray clone would double-decrement on teardown.
#[derive(Debug)]
pub struct CowHandle {
    /// dm device name, e.g. `arcbox-snap-<sandbox_id>`.
    pub dm_name: String,
    /// Absolute device path, e.g. `/dev/mapper/arcbox-snap-<sandbox_id>`.
    pub dm_device: String,
    /// Loop device backing the sparse COW file.
    pub cow_loop: String,
    /// Path to the sparse COW file on disk.
    pub cow_file: PathBuf,
    /// Original template rootfs path (used to release the template refcount).
    pub template_path: PathBuf,
}

#[cfg(any(test, feature = "test-probe"))]
#[derive(Default)]
pub struct CowTestProbe {
    setups: AtomicUsize,
    teardowns: Mutex<Vec<String>>,
}

#[cfg(any(test, feature = "test-probe"))]
impl CowTestProbe {
    fn setup(&self, sandbox_id: &str, rootfs_path: &str, cow_dir: &Path) -> CowHandle {
        self.setups.fetch_add(1, Ordering::SeqCst);
        let dm_name = format!("{DM_NAME_PREFIX}{sandbox_id}");
        CowHandle {
            dm_device: format!("/dev/mapper/{dm_name}"),
            cow_loop: format!("/dev/loop-test-{sandbox_id}"),
            cow_file: cow_dir.join(format!("{COW_FILE_PREFIX}{sandbox_id}{COW_FILE_SUFFIX}")),
            template_path: PathBuf::from(rootfs_path),
            dm_name,
        }
    }

    fn teardown(&self, handle: &CowHandle) {
        self.teardowns.lock().unwrap().push(handle.dm_name.clone());
    }

    pub fn setup_count(&self) -> usize {
        self.setups.load(Ordering::SeqCst)
    }

    pub fn teardown_count(&self) -> usize {
        self.teardowns.lock().unwrap().len()
    }
}

/// What a [`CowManager`] needs from its environment.
///
/// [`CowOptions::new`] fills in the reference environment — the System
/// VM's userland — so today's callers pass a data directory and nothing
/// else; a composer on a different userland overrides the fields it owns.
pub struct CowOptions {
    /// Data directory; COW files live under `{data_dir}/cow/`.
    pub data_dir: PathBuf,
    /// Loop-device and block-size operations.
    pub block_tools: Arc<dyn BlockTools>,
    /// Where to look for `dmsetup`. The first entry that exists and answers
    /// `dmsetup version` is used; none usable degrades the manager to
    /// copy-mode fallback (every setup fails with an actionable error).
    pub dmsetup_candidates: Vec<PathBuf>,
}

impl CowOptions {
    /// The reference environment: busybox at [`BusyboxBlockTools::DEFAULT_PATH`]
    /// and the stock-distro `dmsetup` search list.
    pub fn new(data_dir: impl Into<PathBuf>) -> Self {
        Self {
            data_dir: data_dir.into(),
            block_tools: Arc::new(BusyboxBlockTools::default()),
            dmsetup_candidates: DMSETUP_CANDIDATES.iter().map(PathBuf::from).collect(),
        }
    }
}

/// Manages template loop devices and per-sandbox dm-snapshot lifecycle.
pub struct CowManager {
    templates: Mutex<HashMap<PathBuf, TemplateEntry>>,
    setup_orphans: Mutex<HashMap<String, SetupOrphan>>,
    /// Serializes the cache-miss attach+insert window so two concurrent
    /// first-time setups for the same template converge on a single
    /// `TemplateEntry` instead of each attaching its own loop device and
    /// leaking the loser.  (The other race — a free loop device claimed by
    /// another process between query and attach — is [`BlockTools`]'s to
    /// handle; `BusyboxBlockTools` re-queries and retries, since busybox
    /// has no atomic `losetup -f --show`.)
    losetup_lock: AsyncMutex<()>,
    cow_dir: PathBuf,
    tools: Arc<dyn BlockTools>,
    dmsetup_bin: Option<PathBuf>,
    #[cfg(any(test, feature = "test-probe"))]
    test_probe: Option<Arc<CowTestProbe>>,
}

// ---------------------------------------------------------------------------
// CowManager
// ---------------------------------------------------------------------------

impl CowManager {
    /// Create a new manager over `options`; COW files are stored under
    /// `{data_dir}/cow/`.
    pub fn new(options: CowOptions) -> Result<Self> {
        let CowOptions {
            data_dir,
            block_tools,
            dmsetup_candidates,
        } = options;
        let cow_dir = data_dir.join("cow");
        let marker_dir = cow_dir.join(TEMPLATE_LOOP_DIR);
        std::fs::create_dir_all(&marker_dir)?;
        std::fs::set_permissions(&data_dir, std::fs::Permissions::from_mode(0o700))?;
        std::fs::set_permissions(&cow_dir, std::fs::Permissions::from_mode(0o700))?;
        std::fs::set_permissions(&marker_dir, std::fs::Permissions::from_mode(0o700))?;
        std::fs::File::open(&marker_dir)?.sync_all()?;
        std::fs::File::open(&cow_dir)?.sync_all()?;
        std::fs::File::open(&data_dir)?.sync_all()?;

        // Existence is not usability: driving device-mapper needs
        // /dev/mapper/control, i.e. root inside the VM. A process that cannot
        // talk to the driver (unprivileged dev host, CI runner) can never have
        // created dm snapshots either, so it degrades to the same copy-mode
        // fallback as a missing binary instead of failing every dm command.
        // Every candidate gets the same test: an existing-but-broken entry
        // earlier in the list must not shadow a working one later.
        let dmsetup_bin = dmsetup_candidates.into_iter().find(|bin| {
            bin.exists()
                && Command::new(bin)
                    .arg("version")
                    .output()
                    .is_ok_and(|out| out.status.success())
        });

        if dmsetup_bin.is_none() {
            warn!("dmsetup not found or unusable; dm-snapshot CoW will be unavailable");
        }

        Ok(Self {
            templates: Mutex::new(HashMap::new()),
            setup_orphans: Mutex::new(HashMap::new()),
            losetup_lock: AsyncMutex::new(()),
            cow_dir,
            tools: block_tools,
            dmsetup_bin,
            #[cfg(any(test, feature = "test-probe"))]
            test_probe: None,
        })
    }

    #[cfg(any(test, feature = "test-probe"))]
    pub fn new_with_test_probe(options: CowOptions, probe: Arc<CowTestProbe>) -> Result<Self> {
        let mut manager = Self::new(options)?;
        manager.test_probe = Some(probe);
        Ok(manager)
    }

    /// [`BlockTools::attach_loop`] on a blocking thread.
    pub(super) async fn attach_loop(&self, backing: &Path, read_only: bool) -> Result<String> {
        let tools = Arc::clone(&self.tools);
        let backing = backing.to_path_buf();
        run_blocking(move || tools.attach_loop(&backing, read_only)).await
    }

    /// [`BlockTools::detach_loop`] on a blocking thread.
    pub(super) async fn detach_loop(&self, device: &str) -> Result<()> {
        let tools = Arc::clone(&self.tools);
        let device = device.to_owned();
        run_blocking(move || tools.detach_loop(&device)).await
    }

    /// [`BlockTools::device_sectors`] on a blocking thread.
    pub(super) async fn device_sectors(&self, device: &str) -> Result<u64> {
        let tools = Arc::clone(&self.tools);
        let device = device.to_owned();
        run_blocking(move || tools.device_sectors(&device)).await
    }

    /// Create a dm-snapshot for `sandbox_id` using `rootfs_path` as template.
    ///
    /// Returns a [`CowHandle`] whose `dm_device` field can be passed to
    /// Firecracker as the rootfs block device.
    pub async fn setup(&self, sandbox_id: &str, rootfs_path: &str) -> Result<CowHandle> {
        self.assemble(sandbox_id, rootfs_path, false).await
    }

    /// Re-assemble the dm-snapshot for a paused sandbox from its preserved
    /// COW file (CORE-21 resume).
    ///
    /// The snapshot table uses persistent mode (`P`), so the exception store
    /// in the retained overlay carries every block the sandbox wrote before
    /// it was paused. Unlike [`Self::setup`], the COW file must already
    /// exist and match the template size, and no failure path deletes it —
    /// the overlay is the sandbox's disk.
    pub async fn reattach(&self, sandbox_id: &str, rootfs_path: &str) -> Result<CowHandle> {
        self.assemble(sandbox_id, rootfs_path, true).await
    }

    async fn assemble(
        &self,
        sandbox_id: &str,
        rootfs_path: &str,
        reuse_existing_cow: bool,
    ) -> Result<CowHandle> {
        validate_dm_name_suffix(sandbox_id)?;
        #[cfg(any(test, feature = "test-probe"))]
        if let Some(probe) = &self.test_probe {
            return Ok(probe.setup(sandbox_id, rootfs_path, &self.cow_dir));
        }
        if self.setup_orphans.lock().unwrap().contains_key(sandbox_id) {
            return Err(SnapshotError::Unavailable(format!(
                "sandbox {sandbox_id} still owns resources from an incomplete CoW setup"
            )));
        }

        let dmsetup = self
            .dmsetup_bin
            .as_deref()
            .ok_or_else(|| SnapshotError::DeviceMapper("dmsetup binary not found".into()))?;

        let template = PathBuf::from(rootfs_path);

        // --- 1. Acquire template loop device (shared, refcounted) -----------
        //
        // Fast path: cache hit under the sync mutex, no I/O needed.
        // Slow path: hold the async losetup_lock across attach+insert so a
        // concurrent first-time setup of the same template cannot race ahead,
        // attach a second loop device, and leak the loser's entry on insert.
        let (template_loop, sectors) = 'acquire: {
            // Fast path under the sync mutex.
            if let Some(cached) = {
                let mut templates = self.templates.lock().unwrap();
                let entry = templates.get_mut(&template);
                if entry.as_ref().is_some_and(|entry| entry.refcount == 0) {
                    return Err(SnapshotError::Unavailable(format!(
                        "template {} still owns resources from an incomplete CoW setup",
                        template.display()
                    )));
                }
                entry.map(|entry| {
                    entry.refcount += 1;
                    debug!(
                        template = %rootfs_path,
                        loop_dev = %entry.loop_device,
                        refcount = entry.refcount,
                        "reusing template loop device"
                    );
                    (entry.loop_device.clone(), entry.sectors)
                })
            } {
                break 'acquire cached;
            }

            // Slow path: serialize attach+insert across all concurrent
            // first-time callers for this template.
            let _losetup_guard = self.losetup_lock.lock().await;

            // Re-check the cache: another caller may have populated it while
            // we were waiting for the lock.
            if let Some(cached) = {
                let mut templates = self.templates.lock().unwrap();
                let entry = templates.get_mut(&template);
                if entry.as_ref().is_some_and(|entry| entry.refcount == 0) {
                    return Err(SnapshotError::Unavailable(format!(
                        "template {} still owns resources from an incomplete CoW setup",
                        template.display()
                    )));
                }
                entry.map(|entry| {
                    entry.refcount += 1;
                    debug!(
                        template = %rootfs_path,
                        loop_dev = %entry.loop_device,
                        refcount = entry.refcount,
                        "reusing template loop device (after lock)"
                    );
                    (entry.loop_device.clone(), entry.sectors)
                })
            } {
                break 'acquire cached;
            }

            // Genuinely first to attach — do the work and publish the entry
            // before releasing the lock.
            let pending = self.write_template_pending(sandbox_id, &template)?;
            let loop_dev = match self.attach_loop(Path::new(rootfs_path), true).await {
                Ok(loop_dev) => loop_dev,
                Err(error) => {
                    return Err(self
                        .abort_template_acquisition(sandbox_id, &pending, None, &template, error)
                        .await);
                }
            };
            // Persist ownership before publishing the loop. If the marker
            // cannot be made durable, detach immediately rather than creating
            // a resource that restart reconciliation cannot identify.
            if let Err(error) = self.write_template_marker(&loop_dev, &template) {
                return Err(self
                    .abort_template_acquisition(
                        sandbox_id,
                        &pending,
                        Some(&loop_dev),
                        &template,
                        error,
                    )
                    .await);
            }
            let sectors = match self.device_sectors(&loop_dev).await {
                Ok(sectors) => sectors,
                Err(error) => {
                    return Err(self
                        .abort_template_acquisition(
                            sandbox_id,
                            &pending,
                            Some(&loop_dev),
                            &template,
                            error,
                        )
                        .await);
                }
            };
            if let Err(error) = clear_owner_marker(&pending) {
                return Err(self
                    .abort_template_acquisition(
                        sandbox_id,
                        &pending,
                        Some(&loop_dev),
                        &template,
                        error,
                    )
                    .await);
            }
            debug!(
                template = %rootfs_path,
                loop_dev = %loop_dev,
                sectors,
                "attached new template loop device"
            );
            {
                let mut templates = self.templates.lock().unwrap();
                templates.insert(
                    template.clone(),
                    TemplateEntry {
                        loop_device: loop_dev.clone(),
                        sectors,
                        refcount: 1,
                    },
                );
            }
            (loop_dev, sectors)
        };

        // --- 2. Create (or, on reattach, verify) the sparse COW file --------
        //
        // On reattach the overlay is the sandbox's retained disk, so every
        // rollback below passes `cow_file: None` — a failed re-assembly must
        // never delete it.
        let cow_file = self
            .cow_dir
            .join(format!("{COW_FILE_PREFIX}{sandbox_id}{COW_FILE_SUFFIX}"));
        let cow_size = sectors * 512;
        if reuse_existing_cow {
            let verified = std::fs::metadata(&cow_file)
                .map_err(|e| {
                    SnapshotError::DeviceMapper(format!(
                        "preserved cow file {}: {e}",
                        cow_file.display()
                    ))
                })
                .and_then(|metadata| {
                    if metadata.len() == cow_size {
                        Ok(())
                    } else {
                        Err(SnapshotError::DeviceMapper(format!(
                            "preserved cow file {} is {} bytes but template needs {cow_size}",
                            cow_file.display(),
                            metadata.len()
                        )))
                    }
                });
            if let Err(e) = verified {
                return Err(self
                    .rollback_setup(sandbox_id, &template, None, None, None, e)
                    .await);
            }
        } else if let Err((e, owns_file)) = create_sparse_file(&cow_file, cow_size).await {
            return Err(self
                .rollback_setup(
                    sandbox_id,
                    &template,
                    None,
                    None,
                    owns_file.then_some(cow_file.as_path()),
                    e,
                )
                .await);
        }
        let rollback_cow_file = (!reuse_existing_cow).then_some(cow_file.clone());
        let rollback_cow_file = rollback_cow_file.as_deref();

        // --- 3. Attach COW file as a loop device ----------------------------
        let cow_loop_result = {
            let losetup_guard = self.losetup_lock.lock().await;
            let result = self.attach_loop(&cow_file, false).await;
            drop(losetup_guard);
            result
        };
        let cow_loop = match cow_loop_result {
            Ok(dev) => dev,
            Err(e) => {
                return Err(self
                    .rollback_setup(sandbox_id, &template, None, None, rollback_cow_file, e)
                    .await);
            }
        };

        // --- 4. Create dm-snapshot device -----------------------------------
        let dm_name = format!("{DM_NAME_PREFIX}{sandbox_id}");
        let table =
            format!("0 {sectors} snapshot {template_loop} {cow_loop} P {SNAPSHOT_CHUNK_SECTORS}");

        if let Err(e) = dmsetup_create(dmsetup, &dm_name, &table).await {
            return Err(self
                .rollback_setup(
                    sandbox_id,
                    &template,
                    Some(&dm_name),
                    Some(&cow_loop),
                    rollback_cow_file,
                    e,
                )
                .await);
        }

        let dm_device = format!("/dev/mapper/{dm_name}");
        info!(
            sandbox_id,
            dm_device = %dm_device,
            cow_file = %cow_file.display(),
            "dm-snapshot created"
        );

        Ok(CowHandle {
            dm_name,
            dm_device,
            cow_loop,
            cow_file,
            template_path: template,
        })
    }

    /// Tear down a dm-snapshot, logging any incomplete cleanup.
    pub async fn teardown(&self, handle: &CowHandle) {
        if let Err(error) = self.teardown_checked(handle).await {
            warn!(dm = %handle.dm_name, error = %error, "dm-snapshot teardown incomplete");
        }
    }

    /// Tear down a dm-snapshot and report whether every owned resource was
    /// released. Crash reconciliation and durable Remove use this result to
    /// avoid declaring cleanup complete when a retry is still required.
    pub async fn teardown_checked(&self, handle: &CowHandle) -> Result<()> {
        #[cfg(any(test, feature = "test-probe"))]
        if let Some(probe) = &self.test_probe {
            probe.teardown(handle);
            return Ok(());
        }
        let dmsetup = self
            .dmsetup_bin
            .as_deref()
            .ok_or_else(|| SnapshotError::DeviceMapper("dmsetup binary not found".into()))?;
        let mut failures = Vec::new();

        // 1. Remove dm device.
        let dm_removed = if !dm_present(&handle.dm_name) {
            true
        } else {
            match dmsetup_remove(dmsetup, &handle.dm_name).await {
                Ok(()) => true,
                Err(error) => {
                    failures.push(format!("remove {}: {error}", handle.dm_name));
                    false
                }
            }
        };

        // 2. Detach COW loop device.
        let loop_detached = if loop_backs_path(&handle.cow_loop, &handle.cow_file)? {
            match self.detach_loop(&handle.cow_loop).await {
                Ok(()) => true,
                Err(error) => {
                    failures.push(format!("detach {}: {error}", handle.cow_loop));
                    false
                }
            }
        } else {
            match loop_devices_for_backing_sync(&handle.cow_file) {
                Ok(devices) if devices.is_empty() => true,
                Ok(devices) => {
                    failures.push(format!(
                        "{} is still attached through {} after {} changed ownership",
                        handle.cow_file.display(),
                        devices.join(", "),
                        handle.cow_loop
                    ));
                    false
                }
                Err(error) => {
                    failures.push(format!(
                        "verify loop ownership for {}: {error}",
                        handle.cow_file.display()
                    ));
                    false
                }
            }
        };

        // 3. Delete COW sparse file only after both dm and loop are released.
        //    Unlinking while still referenced would delay space reclamation
        //    until the last kernel reference drops.
        if dm_removed && loop_detached {
            if let Err(error) = remove_file_durable(&handle.cow_file) {
                failures.push(format!("remove {}: {error}", handle.cow_file.display()));
            }
        }

        if failures.is_empty() {
            // Release the shared template exactly once, after every per-sandbox
            // resource is gone. A failed teardown keeps the handle for retry.
            self.release_template_ref(&handle.template_path, true)
                .await?;
            info!(sandbox = %handle.dm_name, "dm-snapshot teardown complete");
            Ok(())
        } else {
            Err(SnapshotError::DeviceMapper(failures.join("; ")))
        }
    }

    /// Tear down the dm device and COW loop but keep the COW file on disk.
    ///
    /// This is the pause half of CORE-21: the persistent (`P`) exception
    /// store in the retained file preserves every written block, and
    /// [`Self::reattach`] re-assembles the identical device on resume. A
    /// failed step keeps the handle valid for retry, exactly like
    /// [`Self::teardown_checked`].
    pub async fn detach_keep_cow(&self, handle: &CowHandle) -> Result<()> {
        #[cfg(any(test, feature = "test-probe"))]
        if let Some(probe) = &self.test_probe {
            probe.teardown(handle);
            return Ok(());
        }
        let dmsetup = self
            .dmsetup_bin
            .as_deref()
            .ok_or_else(|| SnapshotError::DeviceMapper("dmsetup binary not found".into()))?;
        let mut failures = Vec::new();

        if dm_present(&handle.dm_name)
            && let Err(error) = dmsetup_remove(dmsetup, &handle.dm_name).await
        {
            failures.push(format!("remove {}: {error}", handle.dm_name));
        }
        if failures.is_empty()
            && loop_backs_path(&handle.cow_loop, &handle.cow_file)?
            && let Err(error) = self.detach_loop(&handle.cow_loop).await
        {
            failures.push(format!("detach {}: {error}", handle.cow_loop));
        }

        if failures.is_empty() {
            self.release_template_ref(&handle.template_path, true)
                .await?;
            info!(sandbox = %handle.dm_name, "dm-snapshot detached, cow file retained");
            Ok(())
        } else {
            Err(SnapshotError::DeviceMapper(failures.join("; ")))
        }
    }

    /// Delete the COW file a pause left behind (sandbox Remove / TTL).
    ///
    /// Idempotent: a missing file is success. Any loop still backing the
    /// file is detached first so the unlink actually frees the space.
    pub async fn remove_preserved_cow(&self, sandbox_id: &str) -> Result<()> {
        let cow_file = self
            .cow_dir
            .join(format!("{COW_FILE_PREFIX}{sandbox_id}{COW_FILE_SUFFIX}"));
        if !cow_file.exists() {
            return Ok(());
        }
        for loop_device in loop_devices_for_backing_sync(&cow_file)? {
            self.detach_loop(&loop_device).await?;
        }
        remove_file_durable(&cow_file)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Shell helpers
// ---------------------------------------------------------------------------

/// Run a blocking block-tools operation on a blocking thread.
async fn run_blocking<T: Send + 'static>(
    op: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    tokio::task::spawn_blocking(op)
        .await
        .map_err(|e| SnapshotError::DeviceMapper(format!("spawn_blocking join: {e}")))?
}

/// Run a synchronous [`Command`] on a blocking thread.
///
/// `tokio::process::Command` conflicts with the PID-1 SIGCHLD reaper
/// (`spawn_reaper`), causing `ECHILD` errors.  Using `std::process::Command`
/// inside `spawn_blocking` avoids this because `waitpid` is called
/// synchronously before the signal can be stolen.
async fn run_cmd(mut cmd: Command) -> Result<std::process::Output> {
    tokio::task::spawn_blocking(move || cmd.output())
        .await
        .map_err(|e| SnapshotError::DeviceMapper(format!("spawn_blocking join: {e}")))?
        .map_err(|e| SnapshotError::DeviceMapper(format!("command spawn: {e}")))
}

/// Create a dm-snapshot device via `dmsetup create`.
///
/// Followed by `dmsetup mknodes`, which is what makes `/dev/mapper/<name>`
/// exist on a host running no udevd. Whether `dmsetup create` creates that
/// node itself depends on how the binary was built: the System VM's makes it
/// directly, while a distro's is built against libudev and defers to rules
/// that never run when there is no daemon — leaving the device live, listed
/// by `dmsetup ls`, and reachable only through the kernel's own `/dev/dm-N`.
/// Everything downstream names the device by its `/dev/mapper` path, so it
/// has to be there: without it the guest's disk is staged as a full rootfs
/// copy instead of an overlay, and teardown reads a live device as gone.
///
/// A no-op where udev already made the node. If the node is still missing
/// afterwards this fails rather than returning a handle whose device path
/// resolves to nothing: the caller's next step stats that path, reads ENOENT
/// as "no dm-snapshot here", and stages a full copy of the rootfs instead —
/// so a setup that returned `Ok` would have quietly cost a Computer 32 GB.
async fn dmsetup_create(bin: &Path, name: &str, table: &str) -> Result<()> {
    let mut cmd = Command::new(bin);
    cmd.args(["create", name, "--table", table]);

    let output = run_cmd(cmd).await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(SnapshotError::DeviceMapper(format!(
            "dmsetup create {name}: {stderr}"
        )));
    }

    let mut mknodes = Command::new(bin);
    mknodes.args(["mknodes", name]);
    let mknodes = run_cmd(mknodes).await?;
    if !mknodes.status.success() {
        warn!(
            name,
            stderr = %String::from_utf8_lossy(&mknodes.stderr),
            "dmsetup mknodes failed"
        );
    }
    let node = format!("/dev/mapper/{name}");
    if !Path::new(&node).exists() {
        return Err(SnapshotError::DeviceMapper(format!(
            "dm device {name} exists but has no node at {node}, and dmsetup mknodes did not \
             create one; a sandbox would silently copy its whole rootfs instead of using this \
             overlay"
        )));
    }
    Ok(())
}

/// Remove a dm device via `dmsetup remove --retry`.
///
/// The caller has already reaped the VM process, so its opener is gone, but
/// on a host with udev that very close is what wakes the next one: the dm
/// udev rules put an inotify `watch` on every dm node, a close-after-write
/// re-triggers the blkid probe, and the probe holds the device open for a
/// moment — right when the remove ioctl runs. `--retry` repeats the remove
/// on `EBUSY` for a few seconds instead of failing on the first, which is
/// libdevmapper's own answer to that race; a device that is genuinely still
/// in use fails as before, only later. (Reconciliation at startup uses the
/// same flag: `persistence.rs`.)
async fn dmsetup_remove(bin: &Path, name: &str) -> Result<()> {
    let mut cmd = Command::new(bin);
    cmd.args(["remove", "--retry", name]);

    let output = run_cmd(cmd).await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(SnapshotError::DeviceMapper(format!(
            "dmsetup remove {name}: {stderr}"
        )));
    }
    Ok(())
}

/// Create a sparse file of the given size in bytes.
async fn create_sparse_file(
    path: &Path,
    size: u64,
) -> std::result::Result<(), (SnapshotError, bool)> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || -> std::result::Result<(), (SnapshotError, bool)> {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| {
                (
                    SnapshotError::DeviceMapper(format!("create cow file: {e}")),
                    false,
                )
            })?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|e| {
                (
                    SnapshotError::DeviceMapper(format!("secure cow file: {e}")),
                    true,
                )
            })?;
        file.set_len(size).map_err(|e| {
            (
                SnapshotError::DeviceMapper(format!("truncate cow file: {e}")),
                true,
            )
        })?;
        file.sync_all().map_err(|e| {
            (
                SnapshotError::DeviceMapper(format!("sync cow file: {e}")),
                true,
            )
        })?;
        let parent = path.parent().ok_or_else(|| {
            (
                SnapshotError::DeviceMapper("cow file has no parent".into()),
                true,
            )
        })?;
        std::fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|e| {
                (
                    SnapshotError::DeviceMapper(format!("sync cow directory: {e}")),
                    true,
                )
            })?;
        Ok(())
    })
    .await
    .map_err(|e| {
        (
            SnapshotError::DeviceMapper(format!("spawn_blocking join: {e}")),
            false,
        )
    })?
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    /// A manager over `cow_dir` with nothing attached and no `dmsetup`;
    /// tests that need one adjust the field they are about.
    fn manager(cow_dir: &Path) -> CowManager {
        CowManager {
            templates: Mutex::new(HashMap::new()),
            setup_orphans: Mutex::new(HashMap::new()),
            losetup_lock: AsyncMutex::new(()),
            cow_dir: cow_dir.to_path_buf(),
            tools: Arc::new(BusyboxBlockTools::default()),
            dmsetup_bin: None,
            test_probe: None,
        }
    }

    /// A `dmsetup` that lists `listed` as snapshot devices and appends every
    /// other invocation to `{dir}/dmsetup.log`, so a test can assert which
    /// devices the sweep decided to remove without a device-mapper.
    fn fake_dmsetup(dir: &Path, listed: &[&str]) -> PathBuf {
        let listing = listed
            .iter()
            .enumerate()
            .map(|(minor, name)| format!("{name}\\t(253, {minor})"))
            .collect::<Vec<_>>()
            .join("\\n");
        let binary = dir.join("dmsetup");
        crate::test_support::write_script(
            &binary,
            &format!(
                "#!/bin/sh\n\
                 if [ \"$1\" = ls ]; then printf '{listing}\\n'; else echo \"$@\" >> '{}'; fi\n",
                dir.join("dmsetup.log").display()
            ),
        );
        // `write_script` execs the stand-in once to prove the kernel will
        // let it run, and that argument-less run appends to the log the
        // tests read back. Start them from an empty record.
        std::fs::remove_file(dir.join("dmsetup.log")).ok();
        binary
    }

    fn handle_for(dm_device: &Path, template: &Path) -> CowHandle {
        CowHandle {
            dm_name: "arcbox-snap-box".into(),
            dm_device: dm_device.to_string_lossy().into_owned(),
            cow_loop: "/dev/loop9".into(),
            cow_file: PathBuf::from("/nonexistent/arcbox-cow-box.img"),
            template_path: template.to_path_buf(),
        }
    }

    #[test]
    fn test_dm_name_format() {
        let name = format!("{DM_NAME_PREFIX}test-sandbox-123");
        assert_eq!(name, "arcbox-snap-test-sandbox-123");
    }

    #[test]
    fn validate_dm_name_suffix_accepts_uuid_and_basic_ids() {
        validate_dm_name_suffix("550e8400-e29b-41d4-a716-446655440000").unwrap();
        validate_dm_name_suffix("sandbox_1").unwrap();
        validate_dm_name_suffix("a.b+c-d").unwrap();
    }

    #[test]
    fn validate_dm_name_suffix_rejects_invalid_chars() {
        assert!(validate_dm_name_suffix("").is_err());
        assert!(validate_dm_name_suffix("has space").is_err());
        assert!(validate_dm_name_suffix("with/slash").is_err());
        assert!(validate_dm_name_suffix("with:colon").is_err());
        assert!(validate_dm_name_suffix(&"x".repeat(DM_NAME_MAX_LEN)).is_err());
    }

    #[test]
    fn test_cow_file_path() {
        let cow_dir = PathBuf::from("/var/lib/firecracker-vmm/cow");
        let path = cow_dir.join(format!("arcbox-cow-{}.img", "sandbox-1"));
        assert_eq!(
            path,
            PathBuf::from("/var/lib/firecracker-vmm/cow/arcbox-cow-sandbox-1.img")
        );
    }

    #[test]
    fn test_snapshot_table_format() {
        let sectors = 2097152_u64; // 1 GiB
        let table =
            format!("0 {sectors} snapshot /dev/loop0 /dev/loop1 P {SNAPSHOT_CHUNK_SECTORS}");
        assert_eq!(table, "0 2097152 snapshot /dev/loop0 /dev/loop1 P 8");
    }

    #[test]
    fn template_marker_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let mgr = manager(tmp.path());

        let template = PathBuf::from("/var/lib/arcbox/rootfs.ext4");
        mgr.write_template_marker("/dev/loop7", &template).unwrap();
        let marker = mgr.template_marker_path("/dev/loop7").unwrap();
        assert_eq!(marker.file_name().unwrap(), "loop7");
        assert!(marker.exists());
        let content = std::fs::read_to_string(&marker).unwrap();
        assert_eq!(content, template.to_string_lossy());

        let pending = mgr.write_template_pending("box", &template).unwrap();
        assert!(pending.exists());
        clear_owner_marker(&pending).unwrap();
        assert!(!pending.exists());
    }

    #[test]
    fn stale_marker_temp_is_discarded() {
        let tmp = tempfile::tempdir().unwrap();
        let marker_dir = tmp.path().join(TEMPLATE_LOOP_DIR);
        std::fs::create_dir_all(&marker_dir).unwrap();
        let temporary = marker_dir.join(format!("{TEMPLATE_MARKER_TEMP_PREFIX}loop7"));
        std::fs::write(&temporary, b"/partial").unwrap();
        let mgr = manager(tmp.path());

        mgr.cleanup_stale_template_markers().unwrap();

        assert!(!temporary.exists());
    }

    #[tokio::test]
    async fn sparse_cow_creation_never_overwrites_an_owned_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("cow.img");
        create_sparse_file(&path, 4096).await.unwrap();

        let (_, owns_file) = create_sparse_file(&path, 8192).await.unwrap_err();
        assert!(!owns_file);
        assert_eq!(std::fs::metadata(path).unwrap().len(), 4096);
    }

    #[tokio::test]
    async fn rollback_never_removes_an_unowned_cow_file() {
        let tmp = tempfile::tempdir().unwrap();
        let cow_file = tmp.path().join("existing.img");
        std::fs::write(&cow_file, b"owned by another setup").unwrap();
        let mgr = manager(tmp.path());

        let _ = mgr
            .rollback_setup(
                "box",
                Path::new("/template"),
                None,
                None,
                None,
                SnapshotError::DeviceMapper("create failed".into()),
            )
            .await;

        assert_eq!(std::fs::read(&cow_file).unwrap(), b"owned by another setup");
    }

    #[tokio::test]
    async fn zero_ref_template_is_not_reused() {
        let tmp = tempfile::tempdir().unwrap();
        let template = PathBuf::from("/template");
        let mut mgr = manager(tmp.path());
        mgr.dmsetup_bin = Some("/not-used".into());
        mgr.templates.lock().unwrap().insert(
            template.clone(),
            TemplateEntry {
                loop_device: "/dev/loop7".into(),
                sectors: 1024,
                refcount: 0,
            },
        );

        assert!(matches!(
            mgr.setup("box", template.to_str().unwrap()).await,
            Err(SnapshotError::Unavailable(_))
        ));
        assert_eq!(
            mgr.templates
                .lock()
                .unwrap()
                .get(&template)
                .unwrap()
                .refcount,
            0
        );
    }

    /// The sweep must leave an adopted sandbox's device alone: a live VM
    /// holds it open, so removing it fails — and `reconcile_stale` reports
    /// that failure for the whole sweep, taking every other sandbox's
    /// reconciliation down with it.
    #[test]
    fn a_live_dm_device_is_not_removed() {
        let tmp = tempfile::tempdir().unwrap();
        let mut mgr = manager(tmp.path());
        mgr.dmsetup_bin = Some(fake_dmsetup(
            tmp.path(),
            &["arcbox-snap-live", "arcbox-snap-dead", "foreign-snapshot"],
        ));

        mgr.reconcile_stale(&HashSet::new(), &HashSet::from(["live".to_owned()]))
            .unwrap();

        let removed = std::fs::read_to_string(tmp.path().join("dmsetup.log")).unwrap();
        assert_eq!(
            removed.lines().collect::<Vec<_>>(),
            ["remove --retry arcbox-snap-dead"],
            "the sweep removed the wrong devices"
        );
    }

    /// A live device's overlay is the disk it is running on, so the caller
    /// naming it as live is enough — it does not also have to remember to
    /// list it among the retained files.
    #[test]
    fn a_live_sandbox_cow_file_is_kept() {
        let tmp = tempfile::tempdir().unwrap();
        let overlay = tmp.path().join("arcbox-cow-live.img");
        std::fs::write(&overlay, b"exceptions").unwrap();
        let mgr = manager(tmp.path());

        mgr.reconcile_stale(&HashSet::new(), &HashSet::from(["live".to_owned()]))
            .unwrap();

        assert!(overlay.exists(), "a live sandbox's overlay was deleted");
    }

    /// The template map is the authority on which loops are in use, so a
    /// marker whose template is live survives — detaching that loop would
    /// pull the rootfs out from under the guest running on it, and the
    /// marker is the loop's own recovery record.
    #[test]
    fn a_live_template_loop_survives_the_sweep() {
        let tmp = tempfile::tempdir().unwrap();
        let marker_dir = tmp.path().join(TEMPLATE_LOOP_DIR);
        std::fs::create_dir_all(&marker_dir).unwrap();
        let live = tmp.path().join("live.ext4");
        let stale = tmp.path().join("stale.ext4");
        std::fs::write(marker_dir.join("loop7"), live.to_string_lossy().as_bytes()).unwrap();
        std::fs::write(marker_dir.join("loop8"), stale.to_string_lossy().as_bytes()).unwrap();
        let mgr = manager(tmp.path());
        mgr.templates.lock().unwrap().insert(
            live,
            TemplateEntry {
                loop_device: "/dev/loop7".into(),
                sectors: 1024,
                refcount: 1,
            },
        );

        mgr.reconcile_stale(&HashSet::new(), &HashSet::new())
            .unwrap();

        assert!(
            marker_dir.join("loop7").exists(),
            "the live template's recovery marker was cleared"
        );
        assert!(!marker_dir.join("loop8").exists());
    }

    /// Nothing to re-register, whatever the journal claims — and the caller
    /// has to hear about it, because its fallback is to kill the sandbox.
    #[test]
    fn adopt_refuses_a_missing_dm_device() {
        let tmp = tempfile::tempdir().unwrap();
        let mgr = manager(tmp.path());
        let handle = handle_for(
            &tmp.path().join("arcbox-snap-box"),
            &tmp.path().join("t.ext4"),
        );

        let error = mgr.adopt(&handle).unwrap_err();

        assert!(
            matches!(&error, SnapshotError::FailedPrecondition(m) if m.contains("arcbox-snap-box")),
            "{error}"
        );
        assert!(mgr.templates.lock().unwrap().is_empty());
    }

    /// The loop is the kernel's, so only the kernel can say whether it still
    /// backs the recorded template; nothing backing it means the origin of
    /// that snapshot cannot be identified, let alone held. Linux-only: off
    /// it there is no `/sys/block` to answer either way.
    #[cfg(target_os = "linux")]
    #[test]
    fn adopt_refuses_a_template_no_loop_device_backs() {
        let tmp = tempfile::tempdir().unwrap();
        // Stands in for the live device node: `adopt` asks only whether the
        // guest's device is still there.
        let dm_device = tmp.path().join("arcbox-snap-box");
        std::fs::write(&dm_device, b"").unwrap();
        let template = tmp.path().join("t.ext4");
        std::fs::write(&template, b"rootfs").unwrap();
        let mgr = manager(tmp.path());

        let error = mgr.adopt(&handle_for(&dm_device, &template)).unwrap_err();

        assert!(
            matches!(&error, SnapshotError::FailedPrecondition(m) if m.contains("no loop device backs")),
            "{error}"
        );
        assert!(
            mgr.templates.lock().unwrap().is_empty(),
            "a refused adoption took a template reference"
        );
    }

    /// The kernel answers with the path it resolved, so rediscovering a loop
    /// by the spelling the caller configured only works when that spelling
    /// is already canonical. A data directory reached through a symlink is
    /// not an exotic deployment, and there it would cost a live sandbox its
    /// adoption and hide this manager's own loops from teardown.
    #[test]
    fn a_template_reached_through_a_symlink_is_matched_by_its_resolved_path() {
        let tmp = tempfile::tempdir().unwrap();
        let templates = tmp.path().join("templates");
        std::fs::create_dir(&templates).unwrap();
        std::fs::write(templates.join("rootfs.ext4"), b"rootfs").unwrap();
        let linked = tmp.path().join("data");
        std::os::unix::fs::symlink(&templates, &linked).unwrap();
        let configured = linked.join("rootfs.ext4");

        let spellings = persistence::backing_spellings(&configured);

        let resolved = std::fs::canonicalize(&configured).unwrap();
        assert_ne!(
            configured, resolved,
            "the symlinked spelling has to differ, or this asserts nothing"
        );
        assert!(
            spellings.contains(&configured.to_string_lossy().into_owned()),
            "{spellings:?}"
        );
        assert!(
            spellings.contains(&resolved.to_string_lossy().into_owned()),
            "{spellings:?}"
        );
    }

    /// What makes the eventual teardown balance: the first adopted sandbox
    /// registers the template it found, and every later one holding the same
    /// template adds a reference rather than a second registration.
    #[test]
    fn adopting_a_shared_template_registers_then_references() {
        let mgr = manager(Path::new("/tmp"));
        let template = Path::new("/templates/rootfs.ext4");

        mgr.take_template_ref(template, "/dev/loop7", 2048).unwrap();
        mgr.take_template_ref(template, "/dev/loop7", 2048).unwrap();

        let templates = mgr.templates.lock().unwrap();
        let entry = templates.get(template).unwrap();
        assert_eq!(entry.refcount, 2);
        assert_eq!(entry.loop_device, "/dev/loop7");
        assert_eq!(entry.sectors, 2048);
    }

    /// Two refusals with the same consequence — the caller kills the sandbox
    /// rather than adopt onto a template this manager cannot account for: an
    /// entry left at refcount zero is the incomplete-setup sentinel the
    /// acquire path also refuses on, and an entry naming a different loop
    /// means one of the two is a leak whichever way it is resolved.
    #[test]
    fn adopting_refuses_a_zero_ref_or_relocated_template() {
        let mgr = manager(Path::new("/tmp"));
        let template = Path::new("/templates/rootfs.ext4");
        mgr.templates.lock().unwrap().insert(
            template.to_path_buf(),
            TemplateEntry {
                loop_device: "/dev/loop7".into(),
                sectors: 2048,
                refcount: 0,
            },
        );

        let incomplete = mgr
            .take_template_ref(template, "/dev/loop7", 2048)
            .unwrap_err();
        assert!(
            matches!(&incomplete, SnapshotError::Unavailable(m) if m.contains("incomplete CoW setup")),
            "{incomplete}"
        );

        mgr.templates
            .lock()
            .unwrap()
            .get_mut(template)
            .unwrap()
            .refcount = 1;
        let relocated = mgr
            .take_template_ref(template, "/dev/loop9", 2048)
            .unwrap_err();
        assert!(
            matches!(&relocated, SnapshotError::FailedPrecondition(m) if m.contains("/dev/loop9")),
            "{relocated}"
        );
        assert_eq!(
            mgr.templates
                .lock()
                .unwrap()
                .get(template)
                .unwrap()
                .refcount,
            1,
            "a refused adoption took a template reference"
        );
    }

    #[tokio::test]
    async fn test_release_template_refcount() {
        let mgr = manager(Path::new("/tmp"));

        let path = PathBuf::from("/tmp/template.ext4");
        {
            let mut t = mgr.templates.lock().unwrap();
            t.insert(
                path.clone(),
                TemplateEntry {
                    loop_device: "/dev/loop99".into(),
                    sectors: 1024,
                    refcount: 2,
                },
            );
        }

        // First release: refcount 2 → 1, entry stays.
        mgr.release_template_ref(&path, true).await.unwrap();
        {
            let t = mgr.templates.lock().unwrap();
            assert_eq!(t.get(&path).unwrap().refcount, 1);
        }
    }
}
