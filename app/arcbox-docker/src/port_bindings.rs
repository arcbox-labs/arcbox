//! Docker container port binding parsing.

/// A parsed port binding from Docker inspect JSON.
#[derive(Debug, Clone)]
pub struct PortBindingInfo {
    pub host_ip: String,
    pub host_port: u16,
    pub container_port: u16,
    pub protocol: String,
}

/// Parse port bindings from a Docker container inspect JSON response.
///
/// Extracts `NetworkSettings.Ports` and `HostConfig.PortBindings` into a flat
/// list of [`PortBindingInfo`] structs suitable for port forwarding setup.
#[must_use]
pub fn parse_port_bindings(inspect_json: &[u8]) -> Vec<PortBindingInfo> {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(inspect_json) else {
        return vec![];
    };

    // Prefer NetworkSettings.Ports (reflects runtime state).
    let ports = value
        .pointer("/NetworkSettings/Ports")
        .or_else(|| value.pointer("/HostConfig/PortBindings"));

    let Some(ports) = ports.and_then(|v| v.as_object()) else {
        return vec![];
    };

    let mut bindings = Vec::new();

    for (container_port_proto, host_bindings) in ports {
        // Parse "80/tcp" or "53/udp"
        let (container_port, protocol) =
            if let Some((port_str, proto)) = container_port_proto.split_once('/') {
                let port: u16 = match port_str.parse() {
                    Ok(p) => p,
                    Err(_) => continue,
                };
                (port, proto.to_string())
            } else {
                let port: u16 = match container_port_proto.parse() {
                    Ok(p) => p,
                    Err(_) => continue,
                };
                (port, "tcp".to_string())
            };

        let Some(bindings_arr) = host_bindings.as_array() else {
            continue;
        };

        for binding in bindings_arr {
            let host_ip = binding
                .get("HostIp")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let host_port: u16 = binding
                .get("HostPort")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);

            if host_port > 0 {
                bindings.push(PortBindingInfo {
                    host_ip,
                    host_port,
                    container_port,
                    protocol: protocol.clone(),
                });
            }
        }
    }

    bindings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_network_settings() {
        let json = serde_json::json!({
            "NetworkSettings": {
                "Ports": {
                    "80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}],
                    "443/tcp": [{"HostIp": "", "HostPort": "8443"}]
                }
            }
        });
        let bindings = parse_port_bindings(serde_json::to_vec(&json).unwrap().as_slice());
        assert_eq!(bindings.len(), 2);

        let b80 = bindings.iter().find(|b| b.container_port == 80).unwrap();
        assert_eq!(b80.host_port, 8080);
        assert_eq!(b80.protocol, "tcp");
        assert_eq!(b80.host_ip, "0.0.0.0");

        let b443 = bindings.iter().find(|b| b.container_port == 443).unwrap();
        assert_eq!(b443.host_port, 8443);
    }

    #[test]
    fn empty_ports() {
        let json = serde_json::json!({"NetworkSettings": {"Ports": {}}});
        let bindings = parse_port_bindings(serde_json::to_vec(&json).unwrap().as_slice());
        assert!(bindings.is_empty());
    }

    #[test]
    fn null_host_bindings() {
        let json = serde_json::json!({
            "NetworkSettings": {
                "Ports": {
                    "80/tcp": null
                }
            }
        });
        let bindings = parse_port_bindings(serde_json::to_vec(&json).unwrap().as_slice());
        assert!(bindings.is_empty());
    }

    #[test]
    fn udp() {
        let json = serde_json::json!({
            "NetworkSettings": {
                "Ports": {
                    "53/udp": [{"HostIp": "", "HostPort": "5353"}]
                }
            }
        });
        let bindings = parse_port_bindings(serde_json::to_vec(&json).unwrap().as_slice());
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0].protocol, "udp");
        assert_eq!(bindings[0].container_port, 53);
        assert_eq!(bindings[0].host_port, 5353);
    }
}
