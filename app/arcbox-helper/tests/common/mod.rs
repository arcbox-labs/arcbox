//! Shared test infrastructure for arcbox-helper integration tests.
//!
//! Provides a mock tarpc server that validates inputs but skips privileged
//! operations, plus a `setup()` helper that spins up the mock on a temp
//! Unix socket and returns a connected `Client`.

use arcbox_helper::HelperError;
use arcbox_helper::HelperService;
use arcbox_helper::client::Client;
use arcbox_helper::validate;
use futures::prelude::*;
use tarpc::server::{BaseChannel, Channel};
use tarpc::tokio_serde::formats::Bincode;

#[derive(Clone)]
pub struct MockHelperServer {
    version: String,
}

impl HelperService for MockHelperServer {
    async fn route_add(
        self,
        _: tarpc::context::Context,
        subnet: String,
        iface: String,
    ) -> Result<(), HelperError> {
        validate::validate_subnet(&subnet).map_err(HelperError::validation)?;
        validate::validate_iface(&iface).map_err(HelperError::validation)?;
        Ok(())
    }

    async fn route_remove(
        self,
        _: tarpc::context::Context,
        subnet: String,
    ) -> Result<(), HelperError> {
        validate::validate_subnet(&subnet).map_err(HelperError::validation)?;
        Ok(())
    }

    async fn route_remove_if_owned(
        self,
        _: tarpc::context::Context,
        subnet: String,
        iface: String,
    ) -> Result<bool, HelperError> {
        validate::validate_subnet(&subnet).map_err(HelperError::validation)?;
        validate::validate_iface(&iface).map_err(HelperError::validation)?;
        Ok(true)
    }

    async fn dns_install(
        self,
        _: tarpc::context::Context,
        domain: String,
        port: u16,
    ) -> Result<(), HelperError> {
        validate::validate_domain(&domain).map_err(HelperError::validation)?;
        validate::validate_port(port).map_err(HelperError::validation)?;
        Ok(())
    }

    async fn dns_uninstall(
        self,
        _: tarpc::context::Context,
        domain: String,
    ) -> Result<(), HelperError> {
        validate::validate_domain(&domain).map_err(HelperError::validation)?;
        Ok(())
    }

    async fn dns_status(
        self,
        _: tarpc::context::Context,
        domain: String,
    ) -> Result<bool, HelperError> {
        validate::validate_domain(&domain).map_err(HelperError::validation)?;
        Ok(false)
    }

    async fn hosts_alias_install(self, _: tarpc::context::Context) -> Result<(), HelperError> {
        Ok(())
    }

    async fn hosts_alias_uninstall(self, _: tarpc::context::Context) -> Result<(), HelperError> {
        Ok(())
    }

    async fn hosts_alias_status(self, _: tarpc::context::Context) -> Result<bool, HelperError> {
        Ok(false)
    }

    async fn socket_link(
        self,
        _: tarpc::context::Context,
        target: String,
    ) -> Result<(), HelperError> {
        validate::validate_socket_target(&target).map_err(HelperError::validation)?;
        Ok(())
    }

    async fn socket_unlink(self, _: tarpc::context::Context) -> Result<(), HelperError> {
        Ok(())
    }

    async fn cli_link(
        self,
        _: tarpc::context::Context,
        name: String,
        target: String,
    ) -> Result<(), HelperError> {
        validate::validate_cli_name(&name).map_err(HelperError::validation)?;
        validate::validate_cli_target(&target).map_err(HelperError::validation)?;
        Ok(())
    }

    async fn cli_unlink(self, _: tarpc::context::Context, name: String) -> Result<(), HelperError> {
        validate::validate_cli_name(&name).map_err(HelperError::validation)?;
        Ok(())
    }

    async fn version(self, _: tarpc::context::Context) -> String {
        self.version
    }
}

/// Starts a mock server on a temp socket and returns a connected `Client`.
pub async fn setup() -> (Client, tempfile::TempDir) {
    let version = format!("arcbox-helper {}", env!("CARGO_PKG_VERSION"));
    let (client, dir) = setup_with_version(&version).await;
    (client.unwrap(), dir)
}

/// Starts a mock server with a caller-selected version response.
pub async fn setup_with_version(
    version: &str,
) -> (
    Result<Client, arcbox_helper::client::ClientError>,
    tempfile::TempDir,
) {
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("helper.sock");
    let sock_str = sock_path.to_str().unwrap().to_string();

    let listener = tokio::net::UnixListener::bind(&sock_path).unwrap();
    let codec = tarpc::tokio_util::codec::length_delimited::LengthDelimitedCodec::builder();
    let server = MockHelperServer {
        version: version.to_owned(),
    };

    tokio::spawn(async move {
        loop {
            let Ok((conn, _)) = listener.accept().await else {
                break;
            };
            let transport = tarpc::serde_transport::new(codec.new_framed(conn), Bincode::default());
            tokio::spawn(
                BaseChannel::with_defaults(transport)
                    .execute(server.clone().serve())
                    .for_each(|resp| async {
                        tokio::spawn(resp);
                    }),
            );
        }
    });

    let client = Client::connect_to(&sock_str).await;
    (client, dir)
}
