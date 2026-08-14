//! Input validation for setuid defense-in-depth.
//!
//! Every external input is validated before any privileged operation runs.
//! This module is deliberately strict — it rejects anything that doesn't
//! match the expected patterns for ArcBox's use cases.
//!
//! Types in this module follow the "parse, don't validate" pattern: each
//! newtype can only be constructed through validated parsing, so downstream
//! code can rely on invariants being upheld at the type level.

mod bridge_iface;
mod cli_name;
mod cli_target;
mod dns_port;
mod domain;
mod socket_target;
mod subnet;

pub use bridge_iface::BridgeIface;
pub use cli_name::CliName;
pub use cli_target::CliTarget;
pub use dns_port::DnsPort;
pub use domain::Domain;
pub use socket_target::SocketTarget;
pub use subnet::Subnet;

pub fn validate_subnet(s: &str) -> Result<(), String> {
    s.parse::<Subnet>().map(|_| ())
}

pub fn validate_iface(s: &str) -> Result<(), String> {
    s.parse::<BridgeIface>().map(|_| ())
}

pub fn validate_domain(s: &str) -> Result<(), String> {
    s.parse::<Domain>().map(|_| ())
}

pub fn validate_port(port: u16) -> Result<(), String> {
    DnsPort::try_from(port).map(|_| ())
}

pub fn validate_socket_target(s: &str) -> Result<(), String> {
    s.parse::<SocketTarget>().map(|_| ())
}

pub fn validate_cli_name(name: &str) -> Result<(), String> {
    name.parse::<CliName>().map(|_| ())
}

pub fn validate_cli_target(target: &str) -> Result<(), String> {
    target.parse::<CliTarget>().map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_subnets() {
        assert!("10.0.0.0/8".parse::<Subnet>().is_ok());
        assert!("172.16.0.0/12".parse::<Subnet>().is_ok());
        assert!("192.168.1.0/24".parse::<Subnet>().is_ok());
        assert!("10.10.10.0/24".parse::<Subnet>().is_ok());
    }

    #[test]
    fn invalid_subnets() {
        assert!("8.8.8.0/24".parse::<Subnet>().is_err());
        assert!("1.1.1.0/24".parse::<Subnet>().is_err());
        assert!("not-a-cidr".parse::<Subnet>().is_err());
        assert!("10.0.0.0".parse::<Subnet>().is_err());
        assert!("10.0.0.0/33".parse::<Subnet>().is_err());
    }

    #[test]
    fn subnet_rejects_nonzero_host_bits() {
        let r = "10.0.0.5/8".parse::<Subnet>();
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("host bits"));

        let r = "192.168.1.1/24".parse::<Subnet>();
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("192.168.1.0/24"));
    }

    #[test]
    fn subnet_display_roundtrip() {
        let s = "10.0.0.0/8".parse::<Subnet>().unwrap();
        assert_eq!(s.to_string(), "10.0.0.0/8");
    }

    #[test]
    fn valid_ifaces() {
        assert!("bridge0".parse::<BridgeIface>().is_ok());
        assert!("bridge100".parse::<BridgeIface>().is_ok());
        assert!("bridge999".parse::<BridgeIface>().is_ok());
    }

    #[test]
    fn invalid_ifaces() {
        assert!("eth0".parse::<BridgeIface>().is_err());
        assert!("bridge".parse::<BridgeIface>().is_err());
        assert!("bridge100a".parse::<BridgeIface>().is_err());
        assert!("BRIDGE100".parse::<BridgeIface>().is_err());
    }

    #[test]
    fn iface_rejects_overflow() {
        assert!("bridge99999999999999999".parse::<BridgeIface>().is_err());
    }

    #[test]
    fn valid_domains() {
        assert!("arcbox.local".parse::<Domain>().is_ok());
        assert!("test.arcbox.local".parse::<Domain>().is_ok());
        assert!("my-domain.local".parse::<Domain>().is_ok());
    }

    #[test]
    fn invalid_domains() {
        assert!("".parse::<Domain>().is_err());
        assert!("UPPER.case".parse::<Domain>().is_err());
        assert!("has space.local".parse::<Domain>().is_err());
        let long = "a".repeat(254);
        assert!(long.parse::<Domain>().is_err());
        assert!(".".parse::<Domain>().is_err());
        assert!("..".parse::<Domain>().is_err());
        assert!(".leading".parse::<Domain>().is_err());
        assert!("trailing.".parse::<Domain>().is_err());
        assert!("empty..label".parse::<Domain>().is_err());
    }

    #[test]
    fn domain_rejects_label_starting_or_ending_with_hyphen() {
        assert!("-bad.local".parse::<Domain>().is_err());
        assert!("bad-.local".parse::<Domain>().is_err());
        assert!("ok.-bad".parse::<Domain>().is_err());
        assert!("ok.bad-".parse::<Domain>().is_err());
    }

    #[test]
    fn domain_rejects_label_exceeding_63_chars() {
        let long_label = "a".repeat(64);
        assert!(format!("{long_label}.local").parse::<Domain>().is_err());

        let ok_label = "a".repeat(63);
        assert!(format!("{ok_label}.local").parse::<Domain>().is_ok());
    }

    #[test]
    fn valid_ports() {
        assert!(DnsPort::try_from(1024_u16).is_ok());
        assert!(DnsPort::try_from(5553_u16).is_ok());
        assert!(DnsPort::try_from(65535_u16).is_ok());
    }

    #[test]
    fn invalid_ports() {
        assert!(DnsPort::try_from(0_u16).is_err());
        assert!(DnsPort::try_from(80_u16).is_err());
        assert!(DnsPort::try_from(1023_u16).is_err());
    }

    #[test]
    fn valid_socket_targets() {
        assert!(
            "/Users/alice/.arcbox/run/docker.sock"
                .parse::<SocketTarget>()
                .is_ok()
        );
        assert!(
            "/Users/bob/.arcbox/run/arcbox.sock"
                .parse::<SocketTarget>()
                .is_ok()
        );
    }

    #[test]
    fn invalid_socket_targets() {
        assert!("/tmp/docker.sock".parse::<SocketTarget>().is_err());
        assert!(
            "/Users//.arcbox/run/docker.sock"
                .parse::<SocketTarget>()
                .is_err()
        );
        assert!(
            "/Users/alice/.config/docker.sock"
                .parse::<SocketTarget>()
                .is_err()
        );
        assert!(
            "/Users/alice/.arcbox/run/docker.txt"
                .parse::<SocketTarget>()
                .is_err()
        );
    }

    #[test]
    fn socket_target_rejects_uppercase_extension() {
        assert!(
            "/Users/alice/.arcbox/run/docker.SOCK"
                .parse::<SocketTarget>()
                .is_err()
        );
        assert!(
            "/Users/alice/.arcbox/run/docker.Sock"
                .parse::<SocketTarget>()
                .is_err()
        );
    }

    #[test]
    fn socket_target_rejects_path_traversal() {
        let r = "/Users/alice/.arcbox/../../../../var/run/other.sock".parse::<SocketTarget>();
        assert!(r.is_err());
        assert!(r.unwrap_err().contains(".."));
    }

    #[test]
    fn valid_cli_names() {
        assert!("docker".parse::<CliName>().is_ok());
        assert!("docker-buildx".parse::<CliName>().is_ok());
        assert!("docker-compose".parse::<CliName>().is_ok());
        assert!("docker-credential-osxkeychain".parse::<CliName>().is_ok());
    }

    #[test]
    fn invalid_cli_names() {
        assert!("".parse::<CliName>().is_err());
        assert!("curl".parse::<CliName>().is_err());
        assert!("rm".parse::<CliName>().is_err());
        assert!("../docker".parse::<CliName>().is_err());
    }

    #[test]
    fn valid_cli_targets() {
        assert!(
            "/Applications/ArcBox.app/Contents/MacOS/xbin/docker"
                .parse::<CliTarget>()
                .is_ok()
        );
        assert!(
            "/Users/test/Apps/ArcBox.app/Contents/MacOS/xbin/docker-compose"
                .parse::<CliTarget>()
                .is_ok()
        );
    }

    #[test]
    fn invalid_cli_targets() {
        assert!("Contents/MacOS/xbin/docker".parse::<CliTarget>().is_err());
        assert!("/usr/local/bin/docker".parse::<CliTarget>().is_err());
        assert!(
            "/Applications/ArcBox.app/Contents/MacOS/xbin/../../evil"
                .parse::<CliTarget>()
                .is_err()
        );
        assert!(
            "/tmp/evil.app/Contents/MacOS/xbin/docker"
                .parse::<CliTarget>()
                .is_err()
        );
    }

    #[test]
    fn cli_target_allows_nested_app_structure() {
        assert!(
            "/Users/evil/not-really.app/Contents/MacOS/xbin/nested.app/Contents/MacOS/xbin/docker"
                .parse::<CliTarget>()
                .is_ok()
        );
    }

    #[test]
    fn is_arcbox_owned_agrees_with_cli_target_for_valid_paths() {
        let paths = [
            "/Applications/ArcBox.app/Contents/MacOS/xbin/docker",
            "/Users/test/Apps/ArcBox.app/Contents/MacOS/xbin/docker-compose",
        ];
        for p in paths {
            assert!(
                p.parse::<CliTarget>().is_ok(),
                "CliTarget should accept {p}"
            );
            assert!(
                arcbox_constants::paths::is_arcbox_owned(std::path::Path::new(p)),
                "is_arcbox_owned should accept {p}"
            );
        }
    }

    #[test]
    fn is_arcbox_owned_agrees_with_cli_target_for_invalid_paths() {
        let paths = [
            "Contents/MacOS/xbin/docker",
            "/usr/local/bin/docker",
            "/Applications/ArcBox.app/Contents/MacOS/xbin/../../evil",
            "/tmp/evil.app/Contents/MacOS/xbin/docker",
        ];
        for p in paths {
            assert!(
                p.parse::<CliTarget>().is_err(),
                "CliTarget should reject {p}"
            );
            assert!(
                !arcbox_constants::paths::is_arcbox_owned(std::path::Path::new(p)),
                "is_arcbox_owned should reject {p}"
            );
        }
    }
}
