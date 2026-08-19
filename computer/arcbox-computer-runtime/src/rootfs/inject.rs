//! Write `vm-agent` into an ext4 image through a loop mount.

#[cfg(target_os = "linux")]
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::sync::Arc;

use anyhow::Result;
#[cfg(target_os = "linux")]
use anyhow::{Context, bail};

use super::RootfsBuilder;

impl RootfsBuilder {
    /// Inject vm-agent into an ext4 image through a loop mount.
    ///
    /// The image is attached as a loop device through the composer's
    /// [`BlockTools`](arcbox_snapshot::snapshot_cow::BlockTools) and mounted
    /// with `mount(2)`; nothing here shells out.
    /// Success means the agent is in the image *and* every resource is
    /// released again: an image whose mount or loop device could not be
    /// torn down is not published, because the caller's rename would cache
    /// a file another mount holds and a leaked `/dev/loopN` per build would
    /// eventually exhaust the pool.
    #[cfg(target_os = "linux")]
    pub(super) async fn inject_vm_agent(&self, ext4_path: &str, req_id: &str) -> Result<()> {
        if !self.paths().vm_agent.exists() {
            bail!("vm-agent not found at {}", self.paths().vm_agent.display());
        }

        // Attach first: a failed attach (no free loop device, tooling
        // missing) then leaves nothing behind.
        let loop_dev = self
            .attach_loop(ext4_path)
            .await
            .context("failed to attach ext4 image for vm-agent injection")?;
        let mount_dir = std::env::temp_dir().join(format!("arcbox-inject-{req_id}"));
        let staged = match tokio::fs::create_dir_all(&mount_dir).await {
            Ok(()) => mount_ext4(&loop_dev, &mount_dir)
                .await
                .with_context(|| format!("mount {loop_dev} for vm-agent injection")),
            Err(e) => Err(e).context("failed to create injection mount dir"),
        };
        if let Err(error) = staged {
            // Nothing is mounted yet: give the loop device back and report
            // the original failure (plus the detach's, should it also fail).
            let mut failures = Vec::new();
            self.detach_loop(&loop_dev)
                .await
                .push_failure(&mut failures);
            let _ = tokio::fs::remove_dir(&mount_dir).await;
            return Err(match failures.pop() {
                Some(detach) => error.context(format!("and then {detach}")),
                None => error,
            });
        }

        let injected = self.write_agent_into(&mount_dir).await;

        // Release everything, collecting rather than short-circuiting so a
        // failed step never skips the ones after it.
        let mut failures = Vec::new();
        unmount(&mount_dir).await.push_failure(&mut failures);
        self.detach_loop(&loop_dev)
            .await
            .push_failure(&mut failures);
        let _ = tokio::fs::remove_dir(&mount_dir).await;

        if !failures.is_empty() {
            bail!(
                "vm-agent injection left resources behind: {}",
                failures.join("; ")
            );
        }
        injected
    }

    /// Copy the agent to `/sbin/vm-agent` (mode 755) and point
    /// `/etc/resolv.conf` at the `/run` tmpfs inside the mounted image.
    #[cfg(target_os = "linux")]
    async fn write_agent_into(&self, mount_dir: &Path) -> Result<()> {
        let sbin = mount_dir.join("sbin");
        let dest = sbin.join("vm-agent");
        tokio::fs::create_dir_all(&sbin)
            .await
            .context("failed to create /sbin in rootfs")?;
        tokio::fs::copy(&self.paths().vm_agent, &dest)
            .await
            .context("failed to copy vm-agent into rootfs")?;
        tokio::fs::set_permissions(&dest, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .await
            .context("failed to chmod vm-agent in rootfs")?;

        // Point resolv.conf at tmpfs, mirroring the default template: DNS
        // rewrites must stay off the CoW block device (CORE-75). Rewriting
        // is safe for Docker images — Docker itself never ships meaningful
        // resolv.conf content (it bind-mounts one at run time).
        let etc = mount_dir.join("etc");
        if tokio::fs::create_dir_all(&etc).await.is_ok() {
            let resolv = etc.join("resolv.conf");
            let _ = tokio::fs::remove_file(&resolv).await;
            if let Err(e) = tokio::fs::symlink("../run/resolv.conf", &resolv).await {
                tracing::warn!(error = %e, "resolv.conf symlink failed; DNS rewrites will hit the CoW device");
            }
        }
        Ok(())
    }

    /// Loop mounts are a Linux operation; the builder compiles elsewhere but
    /// cannot inject.
    #[cfg(not(target_os = "linux"))]
    pub(super) async fn inject_vm_agent(&self, _ext4_path: &str, _req_id: &str) -> Result<()> {
        anyhow::bail!("vm-agent injection needs a Linux loop mount")
    }

    /// [`BlockTools::attach_loop`](arcbox_snapshot::snapshot_cow::BlockTools::attach_loop)
    /// on a blocking thread.
    #[cfg(target_os = "linux")]
    async fn attach_loop(&self, image: &str) -> Result<String> {
        let tools = Arc::clone(&self.block_tools);
        let image = PathBuf::from(image);
        tokio::task::spawn_blocking(move || tools.attach_loop(&image, false))
            .await
            .context("loop attach task panicked")?
            .map_err(anyhow::Error::from)
    }

    /// [`BlockTools::detach_loop`](arcbox_snapshot::snapshot_cow::BlockTools::detach_loop)
    /// on a blocking thread.
    ///
    /// The kernel accepts `LOOP_CLR_FD` on a device that still has users
    /// (it flags the device autoclear and frees it when the last one goes),
    /// so this succeeds after a lazy unmount as well as a clean one.
    #[cfg(target_os = "linux")]
    async fn detach_loop(&self, loop_dev: &str) -> Result<()> {
        let tools = Arc::clone(&self.block_tools);
        let dev = loop_dev.to_owned();
        tokio::task::spawn_blocking(move || tools.detach_loop(&dev))
            .await
            .context("loop detach task panicked")?
            .with_context(|| format!("detach {loop_dev}"))
    }
}

/// `mount(2)` an ext4 image's loop device at `dir`, off the executor —
/// mounting can replay the journal.
#[cfg(target_os = "linux")]
async fn mount_ext4(loop_dev: &str, dir: &Path) -> Result<()> {
    use nix::mount::{MsFlags, mount};

    let dev = loop_dev.to_owned();
    let dir = dir.to_path_buf();
    tokio::task::spawn_blocking(move || {
        mount(
            Some(dev.as_str()),
            &dir,
            Some("ext4"),
            MsFlags::empty(),
            None::<&str>,
        )
    })
    .await
    .context("mount task panicked")?
    .map_err(anyhow::Error::from)
}

/// `umount(2)` `dir`, falling back to a lazy unmount (`MNT_DETACH`) when
/// something still holds the tree, so the following loop detach can at
/// least schedule the device's release instead of stranding it.
#[cfg(target_os = "linux")]
async fn unmount(dir: &Path) -> Result<()> {
    use nix::mount::{MntFlags, umount, umount2};

    let target = dir.to_path_buf();
    tokio::task::spawn_blocking(move || match umount(&target) {
        Ok(()) => Ok(()),
        // Still busy: detach the tree lazily so the loop device can be
        // released once the last user goes, and report the unmount as
        // failed either way — the image is not safe to publish.
        Err(busy) => match umount2(&target, MntFlags::MNT_DETACH) {
            Ok(()) => bail!(
                "umount {}: {busy} (lazily detached instead)",
                target.display()
            ),
            Err(lazy) => bail!("umount {}: {busy}; lazy unmount: {lazy}", target.display()),
        },
    })
    .await
    .context("umount task panicked")?
}

/// Collect a step's failure without stopping the cleanup sequence.
#[cfg(target_os = "linux")]
trait PushFailure {
    fn push_failure(self, failures: &mut Vec<String>);
}

#[cfg(target_os = "linux")]
impl PushFailure for Result<()> {
    fn push_failure(self, failures: &mut Vec<String>) {
        if let Err(e) = self {
            failures.push(format!("{e:#}"));
        }
    }
}
