//! High-level client for communicating with the arcbox-helper daemon.
//!
//! Wraps the raw tarpc `HelperServiceClient` with ergonomic methods and
//! a unified error type. Consumers (arcbox-core, arcbox-daemon) use this
//! instead of managing tarpc connections directly.

use crate::HelperServiceClient;
use crate::error::HelperError;

/// Errors from helper client operations.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// Cannot connect to the helper socket (daemon not running).
    #[error("helper not reachable: {0}")]
    Connection(#[from] std::io::Error),
    /// tarpc transport or RPC-level failure.
    #[error("helper rpc failed: {0}")]
    Rpc(#[from] tarpc::client::RpcError),
    /// The helper returned a version string that cannot be interpreted safely.
    #[error("unrecognized helper version {0:?}")]
    UnrecognizedVersion(String),
    /// The helper's RPC wire major or minimum version is incompatible.
    #[error("helper {installed} is incompatible; required {required}")]
    IncompatibleVersion {
        /// Version line returned by the helper.
        installed: String,
        /// Minimum compatible helper version.
        required: &'static str,
    },
    /// The helper executed the operation but it returned a structured error.
    #[error(transparent)]
    Helper(#[from] HelperError),
}

/// Client for the arcbox-helper privileged daemon.
pub struct Client {
    inner: HelperServiceClient,
}

impl Client {
    /// Connects to the helper daemon via Unix socket.
    ///
    /// Uses launchd-managed socket by default (`/var/run/arcbox-helper.sock`),
    /// overridable via `ARCBOX_HELPER_SOCKET` env var. The connection is
    /// rejected before any mutation when the helper wire version is
    /// incompatible with this client.
    pub async fn connect() -> Result<Self, ClientError> {
        let inner = crate::connect().await?;
        let client = Self { inner };
        client.ensure_compatible().await?;
        Ok(client)
    }

    /// Connects to the helper daemon at an explicit socket path.
    ///
    /// Unlike [`connect()`](Self::connect), this does not read the
    /// `ARCBOX_HELPER_SOCKET` env var, making it safe for parallel tests. It
    /// enforces the same wire-version check as [`connect()`](Self::connect).
    pub async fn connect_to(path: &str) -> Result<Self, ClientError> {
        let transport = tarpc::serde_transport::unix::connect(
            path,
            tarpc::tokio_serde::formats::Bincode::default,
        )
        .await?;
        let inner =
            crate::HelperServiceClient::new(tarpc::client::Config::default(), transport).spawn();
        let client = Self { inner };
        client.ensure_compatible().await?;
        Ok(client)
    }

    /// Connects only long enough to report the installed helper version.
    ///
    /// This intentionally skips compatibility enforcement so diagnostics can
    /// explain why an old helper must be replaced. It never exposes a client
    /// capable of sending mutation RPCs.
    pub async fn probe_version() -> Result<String, ClientError> {
        let inner = crate::connect().await?;
        Self { inner }.version().await
    }

    /// Adds a host route for `subnet` via `iface`.
    pub async fn route_add(&self, subnet: &str, iface: &str) -> Result<(), ClientError> {
        Ok(self
            .inner
            .route_add(tarpc::context::current(), subnet.into(), iface.into())
            .await??)
    }

    /// Removes the host route for `subnet`.
    pub async fn route_remove(&self, subnet: &str) -> Result<(), ClientError> {
        Ok(self
            .inner
            .route_remove(tarpc::context::current(), subnet.into())
            .await??)
    }

    /// Removes an exact direct route only while it still belongs to `iface`.
    pub async fn route_remove_if_owned(
        &self,
        subnet: &str,
        iface: &str,
    ) -> Result<bool, ClientError> {
        Ok(self
            .inner
            .route_remove_if_owned(tarpc::context::current(), subnet.into(), iface.into())
            .await??)
    }

    /// Installs a DNS resolver file for `domain` on port `port`.
    pub async fn dns_install(&self, domain: &str, port: u16) -> Result<(), ClientError> {
        Ok(self
            .inner
            .dns_install(tarpc::context::current(), domain.into(), port)
            .await??)
    }

    /// Removes the DNS resolver file for `domain`.
    pub async fn dns_uninstall(&self, domain: &str) -> Result<(), ClientError> {
        Ok(self
            .inner
            .dns_uninstall(tarpc::context::current(), domain.into())
            .await??)
    }

    /// Checks if a DNS resolver file is installed for `domain`.
    pub async fn dns_status(&self, domain: &str) -> Result<bool, ClientError> {
        Ok(self
            .inner
            .dns_status(tarpc::context::current(), domain.into())
            .await??)
    }

    /// Appends the fixed `127.0.0.1 ArcBox` alias to `/etc/hosts`.
    pub async fn hosts_alias_install(&self) -> Result<(), ClientError> {
        Ok(self
            .inner
            .hosts_alias_install(tarpc::context::current())
            .await??)
    }

    /// Removes the ArcBox alias line from `/etc/hosts`.
    pub async fn hosts_alias_uninstall(&self) -> Result<(), ClientError> {
        Ok(self
            .inner
            .hosts_alias_uninstall(tarpc::context::current())
            .await??)
    }

    /// Checks whether the ArcBox `/etc/hosts` alias is installed.
    pub async fn hosts_alias_status(&self) -> Result<bool, ClientError> {
        Ok(self
            .inner
            .hosts_alias_status(tarpc::context::current())
            .await??)
    }

    /// Creates the `/var/run/docker.sock` → `target` symlink.
    pub async fn socket_link(&self, target: &str) -> Result<(), ClientError> {
        Ok(self
            .inner
            .socket_link(tarpc::context::current(), target.into())
            .await??)
    }

    /// Removes the `/var/run/docker.sock` symlink.
    pub async fn socket_unlink(&self) -> Result<(), ClientError> {
        Ok(self
            .inner
            .socket_unlink(tarpc::context::current())
            .await??)
    }

    /// Creates `/usr/local/bin/{name}` → `target` symlink.
    pub async fn cli_link(&self, name: &str, target: &str) -> Result<(), ClientError> {
        Ok(self
            .inner
            .cli_link(tarpc::context::current(), name.into(), target.into())
            .await??)
    }

    /// Removes `/usr/local/bin/{name}` symlink if ArcBox-owned.
    pub async fn cli_unlink(&self, name: &str) -> Result<(), ClientError> {
        Ok(self
            .inner
            .cli_unlink(tarpc::context::current(), name.into())
            .await??)
    }

    /// Returns the helper daemon version.
    pub async fn version(&self) -> Result<String, ClientError> {
        Ok(self.inner.version(tarpc::context::current()).await?)
    }

    async fn ensure_compatible(&self) -> Result<(), ClientError> {
        let version = self.version().await?;
        let installed = arcbox_constants::helper::parse_helper_version(&version)
            .ok_or_else(|| ClientError::UnrecognizedVersion(version.clone()))?;
        let required = arcbox_constants::helper::MIN_HELPER_VERSION;
        let minimum = arcbox_constants::helper::parse_semver_triple(required)
            .expect("MIN_HELPER_VERSION is covered by a unit test");

        if arcbox_constants::helper::helper_version_satisfies(installed, minimum) {
            Ok(())
        } else {
            Err(ClientError::IncompatibleVersion {
                installed: version,
                required,
            })
        }
    }
}
