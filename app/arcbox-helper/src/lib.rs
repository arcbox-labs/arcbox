//! arcbox-helper shared types and client.
//!
//! This library defines the tarpc service interface for the privileged helper
//! daemon and provides a high-level [`client::Client`] for consumers
//! (arcbox-core, arcbox-daemon).

pub mod client;
pub mod validate;

/// Unix socket path where the helper daemon listens.
pub const HELPER_SOCKET: &str = arcbox_constants::paths::privileged::HELPER_SOCKET;

/// Override the socket path for development/testing.
pub const HELPER_SOCKET_ENV: &str = "ARCBOX_HELPER_SOCKET";

/// Returns the effective socket path, checking the env override first.
pub fn socket_path() -> String {
    std::env::var(HELPER_SOCKET_ENV).unwrap_or_else(|_| HELPER_SOCKET.to_string())
}

/// The tarpc service definition for privileged host mutations.
///
/// All methods perform input validation server-side before executing
/// any privileged operation. Results carry error strings on failure.
#[tarpc::service]
pub trait HelperService {
    /// Adds a host route for `subnet` via `iface`.
    /// Idempotent: returns Ok if the route already exists.
    async fn route_add(subnet: String, iface: String) -> Result<(), String>;

    /// Removes the host route for `subnet`.
    /// Idempotent: returns Ok if the route is already absent.
    async fn route_remove(subnet: String) -> Result<(), String>;

    /// Installs a DNS resolver file for `domain` pointing to `127.0.0.1:port`.
    async fn dns_install(domain: String, port: u16) -> Result<(), String>;

    /// Removes the DNS resolver file for `domain`.
    async fn dns_uninstall(domain: String) -> Result<(), String>;

    /// Checks if a DNS resolver file is installed for `domain`.
    async fn dns_status(domain: String) -> Result<bool, String>;

    /// Creates `/var/run/docker.sock` symlink pointing to `target`.
    async fn socket_link(target: String) -> Result<(), String>;

    /// Removes the `/var/run/docker.sock` symlink.
    async fn socket_unlink() -> Result<(), String>;

    /// Appends the fixed `127.0.0.1 ArcBox` alias to `/etc/hosts` so the
    /// guest-data NFS mount can use `ArcBox:/` as its source (Finder shows
    /// a mount by its source host name). Takes no arguments — the helper
    /// never writes caller-controlled hosts entries.
    async fn hosts_alias_install() -> Result<(), String>;

    /// Removes the ArcBox alias line from `/etc/hosts`.
    async fn hosts_alias_uninstall() -> Result<(), String>;

    /// Checks whether the ArcBox `/etc/hosts` alias is installed.
    async fn hosts_alias_status() -> Result<bool, String>;

    /// Creates `/usr/local/bin/{name}` symlink pointing to `target`.
    /// Used to expose Docker CLI tools from the app bundle.
    async fn cli_link(name: String, target: String) -> Result<(), String>;

    /// Removes `/usr/local/bin/{name}` symlink if it points inside an ArcBox bundle.
    async fn cli_unlink(name: String) -> Result<(), String>;

    /// Returns the helper version string.
    async fn version() -> String;
}

/// Low-level connect — use [`client::Client::connect()`] instead.
pub(crate) async fn connect() -> Result<HelperServiceClient, std::io::Error> {
    let path = socket_path();
    let transport =
        tarpc::serde_transport::unix::connect(&path, tarpc::tokio_serde::formats::Bincode::default)
            .await?;
    Ok(HelperServiceClient::new(tarpc::client::Config::default(), transport).spawn())
}
