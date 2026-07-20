//! Route management via PF_ROUTE routing socket.

use arcbox_helper::HelperError;
use arcbox_helper::validate::{BridgeIface, Subnet};
use arcbox_route::Ipv4Net;

/// Adds a route for `subnet` via `iface`.
pub fn add(subnet: &Subnet, iface: &BridgeIface) -> Result<(), HelperError> {
    let net = to_ipv4net(subnet)?;
    arcbox_route::add(net, iface.as_str()).map_err(HelperError::other)
}

/// Removes the route for `subnet`.
pub fn remove(subnet: &Subnet) -> Result<(), HelperError> {
    let net = to_ipv4net(subnet)?;
    arcbox_route::remove(net).map_err(HelperError::other)
}

fn to_ipv4net(subnet: &Subnet) -> Result<Ipv4Net, HelperError> {
    let inner = subnet.network();
    Ipv4Net::new(inner.ip(), inner.prefix())
        .map_err(|e| HelperError::other(format!("invalid subnet: {e}")))
}
