//! Guest IP discovery from the host's DHCP lease table.
//!
//! macOS guests use NAT (vmnet shared) networking, whose DHCP server is the
//! system's `bootpd`. It records every lease in `/var/db/dhcpd_leases` as
//! plain-text `{ key=value ... }` blocks (bootp's `PLCache` format). A guest
//! is found by the MAC address pinned to its network device at boot: the
//! lease whose `hw_address` matches is the guest's current address.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// The system DHCP lease table written by `bootpd`.
const DHCPD_LEASES: &str = "/var/db/dhcpd_leases";

/// A single unexpired DHCP lease.
struct Lease {
    mac: [u8; 6],
    ip: String,
    expires_at: u64,
}

/// A lease block mid-parse: fields arrive line by line and any may be
/// missing or malformed.
#[derive(Default)]
struct RawLease {
    mac: Option<[u8; 6]>,
    ip: Option<String>,
    expires_at: Option<u64>,
}

/// Resolves the IPv4 address leased to `mac`, or `None` when the guest has
/// no current lease (not yet booted far enough to DHCP, or expired).
pub(super) fn resolve_ip(mac: &str) -> Option<String> {
    resolve_ip_in(Path::new(DHCPD_LEASES), mac)
}

fn resolve_ip_in(leases_path: &Path, mac: &str) -> Option<String> {
    let mac = parse_mac(mac)?;
    let contents = std::fs::read_to_string(leases_path).ok()?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    parse_leases(&contents, now)
        .into_iter()
        .filter(|lease| lease.mac == mac)
        // Duplicate leases for one MAC: the newest is the live one.
        .max_by_key(|lease| lease.expires_at)
        .map(|lease| lease.ip)
}

/// Parses a MAC address in colon-separated hex. `bootpd` strips leading
/// zeros from octets (`0e` is written `e`), so octets are parsed as hex
/// values rather than compared textually.
fn parse_mac(mac: &str) -> Option<[u8; 6]> {
    let mut bytes = [0u8; 6];
    let mut octets = mac.split(':');
    for byte in &mut bytes {
        *byte = u8::from_str_radix(octets.next()?, 16).ok()?;
    }
    octets.next().is_none().then_some(bytes)
}

/// Parses the lease table, keeping only unexpired Ethernet leases.
///
/// Blocks are `{`, `key=value` lines, `}`. Individually malformed blocks or
/// fields are skipped: the file belongs to `bootpd` and holds entries for
/// every vmnet consumer on the host, so one odd entry must not hide the
/// guest's.
fn parse_leases(contents: &str, now_epoch: u64) -> Vec<Lease> {
    let mut leases = Vec::new();
    let mut current: Option<RawLease> = None;

    for line in contents.lines() {
        let line = line.trim();
        match line {
            "{" => current = Some(RawLease::default()),
            "}" => {
                if let Some(RawLease {
                    mac: Some(mac),
                    ip: Some(ip),
                    expires_at: Some(expires_at),
                }) = current.take()
                    && expires_at > now_epoch
                {
                    leases.push(Lease {
                        mac,
                        ip,
                        expires_at,
                    });
                }
            }
            _ => {
                let (Some(entry), Some((key, value))) = (current.as_mut(), line.split_once('='))
                else {
                    continue;
                };
                match key {
                    // "1,aa:bb:c:dd:ee:ff" — 1 is ARPHRD_ETHER.
                    "hw_address" => {
                        entry.mac = value.strip_prefix("1,").and_then(parse_mac);
                    }
                    "ip_address" => entry.ip = Some(value.to_owned()),
                    // Absolute expiry as hex epoch seconds, e.g. "0x686bb84a".
                    "lease" => {
                        entry.expires_at = value
                            .strip_prefix("0x")
                            .and_then(|hex| u64::from_str_radix(hex, 16).ok());
                    }
                    _ => {}
                }
            }
        }
    }
    leases
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAR_FUTURE: u64 = 0xffff_ffff;

    fn table() -> String {
        format!(
            "{{\n\
             \tname=ci-runner\n\
             \tip_address=192.168.64.7\n\
             \thw_address=1,6:aa:bb:cc:dd:e\n\
             \tidentifier=1,6:aa:bb:cc:dd:e\n\
             \tlease=0x{FAR_FUTURE:x}\n\
             }}\n\
             {{\n\
             \tname=other\n\
             \tip_address=192.168.64.3\n\
             \thw_address=1,86:66:3e:78:c9:e5\n\
             \tlease=0x{FAR_FUTURE:x}\n\
             }}\n"
        )
    }

    #[test]
    fn matches_mac_with_stripped_leading_zeros() {
        // The pinned MAC is zero-padded; bootpd writes "6:aa:bb:cc:dd:e".
        let leases = parse_leases(&table(), 0);
        let mac = parse_mac("06:aa:bb:cc:dd:0e").unwrap();
        let lease = leases.iter().find(|l| l.mac == mac).unwrap();
        assert_eq!(lease.ip, "192.168.64.7");
    }

    #[test]
    fn expired_leases_are_dropped() {
        assert_eq!(parse_leases(&table(), FAR_FUTURE + 1).len(), 0);
        assert_eq!(parse_leases(&table(), 0).len(), 2);
    }

    #[test]
    fn newest_duplicate_lease_wins() {
        let contents = "{\n\
             ip_address=192.168.64.2\n\
             hw_address=1,aa:aa:aa:aa:aa:aa\n\
             lease=0x10\n\
             }\n\
             {\n\
             ip_address=192.168.64.9\n\
             hw_address=1,aa:aa:aa:aa:aa:aa\n\
             lease=0x20\n\
             }\n";
        let newest = parse_leases(contents, 0)
            .into_iter()
            .max_by_key(|l| l.expires_at)
            .unwrap();
        assert_eq!(newest.ip, "192.168.64.9");
    }

    #[test]
    fn malformed_blocks_are_skipped() {
        let contents = "{\n\
             garbage line without equals\n\
             hw_address=not-a-mac\n\
             }\n\
             stray line\n\
             {\n\
             ip_address=192.168.64.5\n\
             hw_address=1,bb:bb:bb:bb:bb:bb\n\
             lease=0xffffffff\n\
             }\n";
        let leases = parse_leases(contents, 0);
        assert_eq!(leases.len(), 1);
        assert_eq!(leases[0].ip, "192.168.64.5");
    }

    #[test]
    fn non_ethernet_hw_address_is_ignored() {
        let contents = "{\n\
             ip_address=192.168.64.5\n\
             hw_address=6,cc:cc:cc:cc:cc:cc\n\
             lease=0xffffffff\n\
             }\n";
        assert!(parse_leases(contents, 0).is_empty());
    }

    #[test]
    fn mac_parsing_rejects_wrong_shapes() {
        assert!(parse_mac("aa:bb:cc:dd:ee").is_none());
        assert!(parse_mac("aa:bb:cc:dd:ee:ff:00").is_none());
        assert!(parse_mac("zz:bb:cc:dd:ee:ff").is_none());
        assert_eq!(parse_mac("6:AA:bb:CC:dd:e"), parse_mac("06:aa:bb:cc:dd:0e"));
    }
}
