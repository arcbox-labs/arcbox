//! tarpc service implementation.
//!
//! Dispatches each RPC to the corresponding operation module.
//! Input validation (parse, don't validate) happens here at the RPC
//! boundary — mutation functions only accept validated types.

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
    ) -> Result<(), String> {
        let subnet: Subnet = subnet.parse()?;
        let iface: BridgeIface = iface.parse()?;
        mutations::route::add(&subnet, &iface)
    }

    async fn route_remove(self, _: tarpc::context::Context, subnet: String) -> Result<(), String> {
        let subnet: Subnet = subnet.parse()?;
        mutations::route::remove(&subnet)
    }

    async fn dns_install(
        self,
        _: tarpc::context::Context,
        domain: String,
        port: u16,
    ) -> Result<(), String> {
        let domain: Domain = domain.parse()?;
        let port = DnsPort::try_from(port)?;
        mutations::dns::install(&domain, port)
    }

    async fn dns_uninstall(self, _: tarpc::context::Context, domain: String) -> Result<(), String> {
        let domain: Domain = domain.parse()?;
        mutations::dns::uninstall(&domain)
    }

    async fn dns_status(self, _: tarpc::context::Context, domain: String) -> Result<bool, String> {
        let domain: Domain = domain.parse()?;
        mutations::dns::status(&domain)
    }

    async fn hosts_alias_install(self, _: tarpc::context::Context) -> Result<(), String> {
        mutations::hosts::install()
    }

    async fn hosts_alias_uninstall(self, _: tarpc::context::Context) -> Result<(), String> {
        mutations::hosts::uninstall()
    }

    async fn hosts_alias_status(self, _: tarpc::context::Context) -> Result<bool, String> {
        mutations::hosts::status()
    }

    async fn socket_link(self, _: tarpc::context::Context, target: String) -> Result<(), String> {
        let target: SocketTarget = target.parse()?;
        mutations::socket::link(&target)
    }

    async fn socket_unlink(self, _: tarpc::context::Context) -> Result<(), String> {
        mutations::socket::unlink()
    }

    async fn cli_link(
        self,
        _: tarpc::context::Context,
        name: String,
        target: String,
    ) -> Result<(), String> {
        let name: CliName = name.parse()?;
        let target: CliTarget = target.parse()?;
        mutations::cli::link(&name, &target)
    }

    async fn cli_unlink(self, _: tarpc::context::Context, name: String) -> Result<(), String> {
        let name: CliName = name.parse()?;
        mutations::cli::unlink(&name)
    }

    async fn version(self, _: tarpc::context::Context) -> String {
        // Same shape as `arcbox-helper --version` so Desktop/doctor can parse
        // one format from either path.
        format!("arcbox-helper {}", env!("CARGO_PKG_VERSION"))
    }
}
