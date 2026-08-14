//! Same-user runtime ownership for isolated container address pools.

use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::path::Path;
use std::sync::Mutex;

use anyhow::{Context, Result, bail};
use arcbox_constants::container_network::ContainerNetwork;

/// Exclusive runtime lease held for an isolated container address pool.
pub struct ContainerNetworkLease {
    network: ContainerNetwork,
    route_bridge: Mutex<Option<String>>,
    _file: File,
}

impl ContainerNetworkLease {
    /// Acquires the same-user lease for a non-default container network.
    pub fn acquire(network: ContainerNetwork) -> Result<Option<Self>> {
        if network == ContainerNetwork::default() {
            return Ok(None);
        }

        let lease_dir = dirs::data_dir()
            .context("user data directory is required for container network leases")?
            .join("ArcBox/RuntimeCIDRLeases");
        Self::acquire_in(network, &lease_dir).map(Some)
    }

    fn acquire_in(network: ContainerNetwork, lease_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(lease_dir).with_context(|| {
            format!(
                "creating container network lease directory {}",
                lease_dir.display()
            )
        })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            std::fs::set_permissions(lease_dir, std::fs::Permissions::from_mode(0o700))
                .with_context(|| {
                    format!(
                        "restricting container network lease directory {}",
                        lease_dir.display()
                    )
                })?;
        }

        let lock_path = lease_dir.join(format!("{}-{}.lock", network.addr(), network.prefix()));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .with_context(|| format!("opening container network lease {}", lock_path.display()))?;

        // SAFETY: `file` owns a valid descriptor and remains alive in the lease.
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result == 0 {
            return Ok(Self {
                network,
                route_bridge: Mutex::new(None),
                _file: file,
            });
        }

        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::WouldBlock {
            bail!("container CIDR {network} is already in use by another ArcBox daemon");
        }
        Err(error).with_context(|| format!("locking container network lease for {network}"))
    }

    /// Records the bridge route owned by this lease before startup can publish ready.
    pub fn record_route(&self, bridge: String) -> Result<()> {
        *self
            .route_bridge
            .lock()
            .map_err(|_| anyhow::anyhow!("container route lease is poisoned"))? = Some(bridge);
        Ok(())
    }

    /// Removes this lease's exact route after checking the recorded bridge.
    pub async fn cleanup_route(&self) -> Result<()> {
        let bridge = {
            self.route_bridge
                .lock()
                .map_err(|_| anyhow::anyhow!("container route lease is poisoned"))?
                .clone()
        };
        let Some(bridge) = bridge else {
            return Ok(());
        };
        let client = arcbox_helper::client::Client::connect().await?;
        client
            .route_remove_if_owned(&self.network.to_string(), &bridge)
            .await?;
        let mut recorded = self
            .route_bridge
            .lock()
            .map_err(|_| anyhow::anyhow!("container route lease is poisoned"))?;
        if recorded.as_deref() == Some(bridge.as_str()) {
            *recorded = None;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn concurrent_leases_reject_the_same_network_and_allow_release() {
        let directory = tempfile::tempdir().unwrap();
        let network: ContainerNetwork = "10.64.0.0/20".parse().unwrap();
        let other: ContainerNetwork = "10.64.16.0/20".parse().unwrap();

        let first = ContainerNetworkLease::acquire_in(network, directory.path()).unwrap();
        assert!(ContainerNetworkLease::acquire_in(network, directory.path()).is_err());
        let _other = ContainerNetworkLease::acquire_in(other, directory.path()).unwrap();

        drop(first);
        ContainerNetworkLease::acquire_in(network, directory.path()).unwrap();
    }
}
