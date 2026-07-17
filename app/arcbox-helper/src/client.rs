//! High-level client for communicating with the arcbox-helper daemon.
//!
//! Wraps the raw tarpc `HelperServiceClient` with ergonomic methods and
//! a unified error type. Consumers (arcbox-core, arcbox-daemon) use this
//! instead of managing tarpc connections directly.

use crate::HelperServiceClient;

/// Errors from helper client operations.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// Cannot connect to the helper socket (daemon not running).
    #[error("helper not reachable: {0}")]
    Connection(#[from] std::io::Error),
    /// tarpc transport or RPC-level failure.
    #[error("helper rpc failed: {0}")]
    Rpc(#[from] tarpc::client::RpcError),
    /// The helper executed the operation but it returned an error.
    #[error("helper error: {0}")]
    Helper(String),
}

/// Client for the arcbox-helper privileged daemon.
pub struct Client {
    inner: HelperServiceClient,
}

impl Client {
    /// Connects to the helper daemon via Unix socket.
    ///
    /// Uses launchd-managed socket by default (`/var/run/arcbox-helper.sock`),
    /// overridable via `ARCBOX_HELPER_SOCKET` env var.
    pub async fn connect() -> Result<Self, ClientError> {
        let inner = crate::connect().await?;
        Ok(Self { inner })
    }

    /// Connects to the helper daemon at an explicit socket path.
    ///
    /// Unlike [`connect()`](Self::connect), this does not read the
    /// `ARCBOX_HELPER_SOCKET` env var, making it safe for parallel tests.
    pub async fn connect_to(path: &str) -> Result<Self, ClientError> {
        let transport = tarpc::serde_transport::unix::connect(
            path,
            tarpc::tokio_serde::formats::Bincode::default,
        )
        .await?;
        let inner =
            crate::HelperServiceClient::new(tarpc::client::Config::default(), transport).spawn();
        Ok(Self { inner })
    }

    /// Adds a host route for `subnet` via `iface`.
    pub async fn route_add(&self, subnet: &str, iface: &str) -> Result<(), ClientError> {
        self.inner
            .route_add(tarpc::context::current(), subnet.into(), iface.into())
            .await?
            .map_err(ClientError::Helper)
    }

    /// Removes the host route for `subnet`.
    pub async fn route_remove(&self, subnet: &str) -> Result<(), ClientError> {
        self.inner
            .route_remove(tarpc::context::current(), subnet.into())
            .await?
            .map_err(ClientError::Helper)
    }

    /// Installs a DNS resolver file for `domain` on port `port`.
    pub async fn dns_install(&self, domain: &str, port: u16) -> Result<(), ClientError> {
        self.inner
            .dns_install(tarpc::context::current(), domain.into(), port)
            .await?
            .map_err(ClientError::Helper)
    }

    /// Removes the DNS resolver file for `domain`.
    pub async fn dns_uninstall(&self, domain: &str) -> Result<(), ClientError> {
        self.inner
            .dns_uninstall(tarpc::context::current(), domain.into())
            .await?
            .map_err(ClientError::Helper)
    }

    /// Checks if a DNS resolver file is installed for `domain`.
    pub async fn dns_status(&self, domain: &str) -> Result<bool, ClientError> {
        self.inner
            .dns_status(tarpc::context::current(), domain.into())
            .await?
            .map_err(ClientError::Helper)
    }

    /// Appends the fixed `127.0.0.1 ArcBox` alias to `/etc/hosts`.
    pub async fn hosts_alias_install(&self) -> Result<(), ClientError> {
        self.inner
            .hosts_alias_install(tarpc::context::current())
            .await?
            .map_err(ClientError::Helper)
    }

    /// Removes the ArcBox alias line from `/etc/hosts`.
    pub async fn hosts_alias_uninstall(&self) -> Result<(), ClientError> {
        self.inner
            .hosts_alias_uninstall(tarpc::context::current())
            .await?
            .map_err(ClientError::Helper)
    }

    /// Checks whether the ArcBox `/etc/hosts` alias is installed.
    pub async fn hosts_alias_status(&self) -> Result<bool, ClientError> {
        self.inner
            .hosts_alias_status(tarpc::context::current())
            .await?
            .map_err(ClientError::Helper)
    }

    /// Creates the `/var/run/docker.sock` → `target` symlink.
    pub async fn socket_link(&self, target: &str) -> Result<(), ClientError> {
        self.inner
            .socket_link(tarpc::context::current(), target.into())
            .await?
            .map_err(ClientError::Helper)
    }

    /// Removes the `/var/run/docker.sock` symlink.
    pub async fn socket_unlink(&self) -> Result<(), ClientError> {
        self.inner
            .socket_unlink(tarpc::context::current())
            .await?
            .map_err(ClientError::Helper)
    }

    /// Creates `/usr/local/bin/{name}` → `target` symlink.
    pub async fn cli_link(&self, name: &str, target: &str) -> Result<(), ClientError> {
        self.inner
            .cli_link(tarpc::context::current(), name.into(), target.into())
            .await?
            .map_err(ClientError::Helper)
    }

    /// Removes `/usr/local/bin/{name}` symlink if ArcBox-owned.
    pub async fn cli_unlink(&self, name: &str) -> Result<(), ClientError> {
        self.inner
            .cli_unlink(tarpc::context::current(), name.into())
            .await?
            .map_err(ClientError::Helper)
    }

    /// Returns the helper daemon version.
    pub async fn version(&self) -> Result<String, ClientError> {
        Ok(self.inner.version(tarpc::context::current()).await?)
    }
}
