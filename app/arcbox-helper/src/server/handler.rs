//! tarpc service implementation.
//!
//! Dispatches each RPC to the corresponding operation module.
//! Input validation (parse, don't validate) happens here at the RPC
//! boundary — mutation functions only accept validated types.

use arcbox_helper::HelperError;
use arcbox_helper::HelperService;
use arcbox_helper::validate::{
    BridgeIface, CliName, CliTarget, DnsPort, Domain, SocketTarget, Subnet,
};

use super::mutations;

#[derive(Clone)]
pub struct HelperServer;

impl HelperService for HelperServer {
    async fn route_add(
        self,
        _: tarpc::context::Context,
        subnet: String,
        iface: String,
    ) -> Result<(), HelperError> {
        let subnet: Subnet = subnet.parse().map_err(HelperError::validation)?;
        let iface: BridgeIface = iface.parse().map_err(HelperError::validation)?;
        mutations::route::add(&subnet, &iface)
    }

    async fn route_remove(
        self,
        _: tarpc::context::Context,
        subnet: String,
    ) -> Result<(), HelperError> {
        let subnet: Subnet = subnet.parse().map_err(HelperError::validation)?;
        mutations::route::remove(&subnet)
    }

    async fn dns_install(
        self,
        _: tarpc::context::Context,
        domain: String,
        port: u16,
    ) -> Result<(), HelperError> {
        let domain: Domain = domain.parse().map_err(HelperError::validation)?;
        let port = DnsPort::try_from(port).map_err(HelperError::validation)?;
        mutations::dns::install(&domain, port)
    }

    async fn dns_uninstall(
        self,
        _: tarpc::context::Context,
        domain: String,
    ) -> Result<(), HelperError> {
        let domain: Domain = domain.parse().map_err(HelperError::validation)?;
        mutations::dns::uninstall(&domain)
    }

    async fn dns_status(
        self,
        _: tarpc::context::Context,
        domain: String,
    ) -> Result<bool, HelperError> {
        let domain: Domain = domain.parse().map_err(HelperError::validation)?;
        mutations::dns::status(&domain)
    }

    async fn hosts_alias_install(self, _: tarpc::context::Context) -> Result<(), HelperError> {
        mutations::hosts::install()
    }

    async fn hosts_alias_uninstall(self, _: tarpc::context::Context) -> Result<(), HelperError> {
        mutations::hosts::uninstall()
    }

    async fn hosts_alias_status(self, _: tarpc::context::Context) -> Result<bool, HelperError> {
        mutations::hosts::status()
    }

    async fn route_add_for_interface(
        self,
        _: tarpc::context::Context,
        subnet: String,
        iface: String,
        expected_ifindex: u16,
    ) -> Result<(), HelperError> {
        let subnet: Subnet = subnet.parse().map_err(HelperError::validation)?;
        let iface: BridgeIface = iface.parse().map_err(HelperError::validation)?;
        if expected_ifindex == 0 {
            return Err(HelperError::validation(
                "expected interface index must be non-zero",
            ));
        }
        mutations::route::add_for_interface(&subnet, &iface, expected_ifindex)
    }

    async fn socket_link(
        self,
        _: tarpc::context::Context,
        target: String,
    ) -> Result<(), HelperError> {
        let target: SocketTarget = target.parse().map_err(HelperError::validation)?;
        mutations::socket::link(&target)
    }

    async fn socket_unlink(self, _: tarpc::context::Context) -> Result<(), HelperError> {
        mutations::socket::unlink()
    }

    async fn cli_link(
        self,
        _: tarpc::context::Context,
        name: String,
        target: String,
    ) -> Result<(), HelperError> {
        let name: CliName = name.parse().map_err(HelperError::validation)?;
        let target: CliTarget = target.parse().map_err(HelperError::validation)?;
        mutations::cli::link(&name, &target)
    }

    async fn cli_unlink(self, _: tarpc::context::Context, name: String) -> Result<(), HelperError> {
        let name: CliName = name.parse().map_err(HelperError::validation)?;
        mutations::cli::unlink(&name)
    }

    async fn version(self, _: tarpc::context::Context) -> String {
        // Same shape as `arcbox-helper --version` so Desktop/doctor can parse
        // one format from either path.
        format!("arcbox-helper {}", env!("CARGO_PKG_VERSION"))
    }
}
