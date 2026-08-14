//! Route management via PF_ROUTE routing socket.

use arcbox_helper::HelperError;
use arcbox_helper::validate::{BridgeIface, Subnet};
use arcbox_route::Ipv4Net;

/// Adds a route for `subnet` via `iface`.
pub fn add(subnet: &Subnet, iface: &BridgeIface) -> Result<(), HelperError> {
    let net = to_ipv4net(subnet)?;
    match arcbox_route::add(net, iface.as_str()).map_err(HelperError::other)? {
        arcbox_route::AddOutcome::Added => Ok(()),
        arcbox_route::AddOutcome::Conflict => Err(HelperError::RouteConflict {
            subnet: subnet.to_string(),
        }),
    }
}

/// Removes the route for `subnet`.
pub fn remove(subnet: &Subnet) -> Result<(), HelperError> {
    let net = to_ipv4net(subnet)?;
    arcbox_route::remove(net).map_err(HelperError::other)
}

/// Removes an exact direct route after confirming it points to `iface`.
pub fn remove_if_owned(subnet: &Subnet, iface: &BridgeIface) -> Result<bool, HelperError> {
    let net = to_ipv4net(subnet)?;
    let Some(route) = arcbox_route::get(net).map_err(HelperError::other)? else {
        return Ok(false);
    };
    let expected_ifindex =
        arcbox_route::interface_index(iface.as_str()).map_err(HelperError::other)?;
    if !is_owned_route(route, expected_ifindex) {
        return Err(HelperError::RouteConflict {
            subnet: subnet.to_string(),
        });
    }
    // ponytail: PF_ROUTE has no conditional delete; keep this preflight until Darwin adds one.
    arcbox_route::remove(net).map_err(HelperError::other)?;
    Ok(true)
}

fn is_owned_route(route: arcbox_route::RouteInfo, expected_ifindex: u16) -> bool {
    route.ifindex == expected_ifindex && route.flags & libc::RTF_GATEWAY == 0
}

fn to_ipv4net(subnet: &Subnet) -> Result<Ipv4Net, HelperError> {
    let inner = subnet.network();
    Ipv4Net::new(inner.ip(), inner.prefix())
        .map_err(|e| HelperError::other(format!("invalid subnet: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owned_route_must_be_direct_and_use_the_expected_interface() {
        let direct = arcbox_route::RouteInfo {
            ifindex: 42,
            flags: 0,
        };

        assert!(is_owned_route(direct, 42));
        assert!(!is_owned_route(direct, 41));
        assert!(!is_owned_route(
            arcbox_route::RouteInfo {
                flags: libc::RTF_GATEWAY,
                ..direct
            },
            42
        ));
    }
}
