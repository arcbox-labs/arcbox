//! What a VM looks like before it runs: the serializable per-VM shape.
//!
//! Everything here is data. Node-wide knobs — VMM binary paths, seccomp,
//! jailer defaults, MTU — are the adapter's own `DriverConfig`; a
//! `VmSpec` says only what *this* VM is made of, so the same spec renders
//! into a Firecracker API payload, a Virtualization.framework configuration,
//! or an in-process VMM's config without the orchestrator knowing which.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// The identity of a VM: non-empty, at most 64 characters, `[A-Za-z0-9._-]`.
///
/// Drivers use it as a runtime-directory and socket-name component, which is
/// what the character set protects.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct VmId(String);

impl VmId {
    /// The longest id a driver has to fit into a path or socket name.
    pub const MAX_LEN: usize = 64;

    /// Validates `id` and wraps it.
    pub fn new(id: impl Into<String>) -> Result<Self> {
        let id = id.into();
        if id.is_empty() {
            return Err(Error::InvalidSpec("vm id must not be empty".into()));
        }
        if id.len() > Self::MAX_LEN {
            return Err(Error::InvalidSpec(format!(
                "vm id `{id}` exceeds {} characters",
                Self::MAX_LEN
            )));
        }
        if let Some(bad) = id
            .chars()
            .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')))
        {
            return Err(Error::InvalidSpec(format!(
                "vm id `{id}` contains `{bad}`; allowed: A-Z a-z 0-9 . _ -"
            )));
        }
        Ok(Self(id))
    }

    /// The id as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for VmId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for VmId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for VmId {
    type Error = Error;

    fn try_from(value: String) -> Result<Self> {
        Self::new(value)
    }
}

impl From<VmId> for String {
    fn from(id: VmId) -> Self {
        id.0
    }
}

/// A 48-bit Ethernet address, written `aa:bb:cc:dd:ee:ff`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddr([u8; 6]);

impl MacAddr {
    /// Wraps six octets, most significant first.
    pub const fn new(octets: [u8; 6]) -> Self {
        Self(octets)
    }

    /// The six octets, most significant first.
    pub const fn octets(&self) -> [u8; 6] {
        self.0
    }

    /// `true` unless the group (multicast) bit is set.
    pub const fn is_unicast(&self) -> bool {
        self.0[0] & 0x01 == 0
    }

    /// `true` when every octet is zero — no NIC may carry this address.
    pub const fn is_nil(&self) -> bool {
        matches!(self.0, [0, 0, 0, 0, 0, 0])
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, octet) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(":")?;
            }
            write!(f, "{octet:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for MacAddr {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let invalid =
            || Error::InvalidSpec(format!("`{s}` is not a MAC address (aa:bb:cc:dd:ee:ff)"));
        let mut octets = [0u8; 6];
        let mut parts = s.split(':');
        for octet in &mut octets {
            let part = parts.next().ok_or_else(invalid)?;
            if part.len() != 2 {
                return Err(invalid());
            }
            *octet = u8::from_str_radix(part, 16).map_err(|_| invalid())?;
        }
        if parts.next().is_some() {
            return Err(invalid());
        }
        Ok(Self(octets))
    }
}

impl Serialize for MacAddr {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for MacAddr {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mac(n: u8) -> MacAddr {
        MacAddr::new([0x02, 0, 0, 0, 0, n])
    }

    #[test]
    fn vm_id_accepts_the_documented_alphabet_and_nothing_else() {
        assert!(VmId::new("a.b_c-D9").is_ok());
        assert!(VmId::new("x".repeat(VmId::MAX_LEN)).is_ok());
        assert!(VmId::new("").is_err());
        assert!(VmId::new("x".repeat(VmId::MAX_LEN + 1)).is_err());
        assert!(VmId::new("has space").is_err());
        assert!(VmId::new("slash/y").is_err());
        assert!(VmId::new("ünïcode").is_err());
    }

    #[test]
    fn vm_id_deserialization_validates() {
        let ok: VmId = serde_json::from_str("\"vm-1\"").unwrap();
        assert_eq!(ok.as_str(), "vm-1");
        assert!(serde_json::from_str::<VmId>("\"bad id\"").is_err());
        assert_eq!(serde_json::to_string(&ok).unwrap(), "\"vm-1\"");
    }

    #[test]
    fn mac_parses_and_prints_canonical_form() {
        let m: MacAddr = "AA:bb:0C:dd:ee:0f".parse().unwrap();
        assert_eq!(m.octets(), [0xaa, 0xbb, 0x0c, 0xdd, 0xee, 0x0f]);
        assert_eq!(m.to_string(), "aa:bb:0c:dd:ee:0f");
        for bad in [
            "aa:bb:cc:dd:ee",
            "aa:bb:cc:dd:ee:ff:00",
            "aa:bb:cc:dd:ee:g0",
            "aabbccddeeff",
            "a:b:c:d:e:f",
        ] {
            assert!(bad.parse::<MacAddr>().is_err(), "{bad} parsed");
        }
        assert_eq!(serde_json::to_string(&m).unwrap(), "\"aa:bb:0c:dd:ee:0f\"");
        assert_eq!(
            serde_json::from_str::<MacAddr>("\"aa:bb:0c:dd:ee:0f\"").unwrap(),
            m
        );
        assert!(serde_json::from_str::<MacAddr>("\"nope\"").is_err());
    }

    #[test]
    fn mac_classifies_unicast_and_nil() {
        assert!(MacAddr::new([0x02, 1, 2, 3, 4, 5]).is_unicast());
        assert!(!MacAddr::new([0x01, 0, 0x5e, 0, 0, 1]).is_unicast());
        assert!(MacAddr::new([0; 6]).is_nil());
        assert!(!mac(1).is_nil());
    }
}
