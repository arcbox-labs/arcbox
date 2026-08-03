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

/// Adds a route through the exact bridge identity selected by the daemon.
pub fn add_for_interface(
    subnet: &Subnet,
    iface: &BridgeIface,
    expected_ifindex: u16,
) -> Result<(), HelperError> {
    let actual_ifindex = arcbox_route::interface_index(iface.as_str()).ok();
    if actual_ifindex != Some(expected_ifindex) {
        return Err(HelperError::RouteInterfaceChanged {
            iface: iface.to_string(),
            expected_ifindex,
            actual_ifindex,
        });
    }

    let net = to_ipv4net(subnet)?;
    match arcbox_route::add_by_index(net, iface.as_str(), expected_ifindex)
        .map_err(HelperError::other)?
    {
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

fn to_ipv4net(subnet: &Subnet) -> Result<Ipv4Net, HelperError> {
    let inner = subnet.network();
    Ipv4Net::new(inner.ip(), inner.prefix())
        .map_err(|e| HelperError::other(format!("invalid subnet: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn changed_bridge_identity_is_rejected_before_mutation() {
        let subnet = "172.16.0.0/12".parse().unwrap();
        let iface = "bridge4294967295".parse().unwrap();

        let error = add_for_interface(&subnet, &iface, 1).unwrap_err();

        assert!(matches!(
            error,
            HelperError::RouteInterfaceChanged {
                expected_ifindex: 1,
                actual_ifindex: None,
                ..
            }
        ));
    }
}
