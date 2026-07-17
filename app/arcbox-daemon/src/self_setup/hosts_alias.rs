//! Ensures the `127.0.0.1 ArcBox` alias in `/etc/hosts`.
//!
//! With the alias installed the guest-data NFS mount uses `ArcBox:/` as
//! its source, so Finder's Locations sidebar shows an "ArcBox" location
//! instead of "127.0.0.1" (see `nfs_mount::mount_source`).

use arcbox_helper::client::{Client, ClientError};

use super::SetupTask;

pub struct HostsAlias;

#[async_trait::async_trait]
impl SetupTask for HostsAlias {
    fn name(&self) -> &'static str {
        "hosts alias"
    }

    fn is_satisfied(&self) -> bool {
        std::fs::read_to_string("/etc/hosts")
            .is_ok_and(|content| arcbox_helper::hosts_alias_installed(&content))
    }

    async fn apply(&self, client: &Client) -> Result<(), ClientError> {
        client.hosts_alias_install().await
    }
}
