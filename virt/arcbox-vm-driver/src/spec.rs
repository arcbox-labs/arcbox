//! What a VM looks like before it runs: the serializable per-VM shape.
//!
//! Everything here is data. Node-wide knobs — VMM binary paths, seccomp,
//! jailer defaults, MTU — are the adapter's own `DriverConfig`; a
//! [`VmSpec`] says only what *this* VM is made of, so the same spec renders
//! into a Firecracker API payload, a Virtualization.framework configuration,
//! or an in-process VMM's config without the orchestrator knowing which.

use std::collections::HashSet;
use std::fmt;
use std::os::fd::RawFd;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// The identity of a VM: a plain name — non-empty, at most 64 characters,
/// and `[A-Za-z0-9-]`.
///
/// Drivers use it as a runtime-directory and socket-name component, and hand
/// it to the VMM as the instance id it runs under. The alphabet is therefore
/// the *intersection* of what those uses allow, not the union: Firecracker
/// validates its `--id` as `[A-Za-z0-9-]`, 1..=64, and **panics** on anything
/// else — `Invalid instance ID: InvalidChar('_', 4)`, raised from inside
/// whatever task spawned the VMM, with nothing tying it back to the request
/// that supplied the id. A separator this type accepted but a driver could
/// not run would be a promise the port cannot keep, so it accepts only `-`.
/// [`MAX_LEN`](Self::MAX_LEN) is that same VMM-imposed 64.
///
/// A driver-internal name that never becomes a VMM identity — [`DiskSpec::id`]
/// is the one here — keeps the wider path-safe alphabet (`.` and `_` too).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct VmId(String);

impl VmId {
    /// The longest id a driver has to fit into a path or socket name, and
    /// the longest a VMM will take as its instance id.
    pub const MAX_LEN: usize = 64;

    /// Validates `id` and wraps it.
    pub fn new(id: impl Into<String>) -> Result<Self> {
        let id = id.into();
        require_name_length("vm id", &id)?;
        if let Some(bad) = id
            .chars()
            .find(|c| !(c.is_ascii_alphanumeric() || *c == '-'))
        {
            return Err(Error::InvalidSpec(format!(
                "vm id `{id}` contains `{bad}`; allowed: A-Z a-z 0-9 -"
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

/// Everything a driver needs to boot one VM.
///
/// Validate with [`VmSpec::validate`] before handing it to a driver; drivers
/// validate again at `VmDriver::boot`, so an orchestrator that
/// forgets still gets [`Error::InvalidSpec`] rather than a half-built VM.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VmSpec {
    /// The VM's identity.
    pub id: VmId,
    /// Virtual CPU count, at least 1.
    pub cpus: u32,
    /// Guest memory in MiB, at least 1.
    pub memory_mib: u32,
    /// How the guest starts.
    pub boot: BootSpec,
    /// Block devices, in bus order.
    #[serde(default)]
    pub disks: Vec<DiskSpec>,
    /// Network interfaces, in bus order.
    #[serde(default)]
    pub nics: Vec<NicSpec>,
    /// The vsock device, when the guest should have one.
    #[serde(default)]
    pub vsock: Option<VsockSpec>,
    /// Shared host directories (virtiofs).
    #[serde(default)]
    pub shares: Vec<ShareSpec>,
    /// Where the guest console goes.
    #[serde(default)]
    pub console: ConsoleSpec,
    /// Attach a memory balloon.
    #[serde(default)]
    pub balloon: bool,
    /// Attach an entropy (virtio-rng) device.
    #[serde(default)]
    pub entropy: bool,
    /// Track dirty pages so a checkpoint can be incremental.
    #[serde(default)]
    pub dirty_tracking: bool,
    /// How the VMM process is confined.
    #[serde(default)]
    pub isolation: IsolationSpec,
}

impl VmSpec {
    /// Checks the invariants no driver can repair.
    ///
    /// CPU and memory are at least 1; disk ids are plain names (the path-safe
    /// alphabet, wider than [`VmId`]'s) and unique; NIC ids and share tags are
    /// non-empty and unique; at most one disk is the root; every MAC is a
    /// non-nil unicast address; every boot, disk and share path is non-empty;
    /// the vsock guest CID is 3 or above.
    pub fn validate(&self) -> Result<()> {
        if self.cpus == 0 {
            return Err(Error::InvalidSpec("cpus must be at least 1".into()));
        }
        if self.memory_mib == 0 {
            return Err(Error::InvalidSpec("memory_mib must be at least 1".into()));
        }
        self.boot.validate()?;
        let mut disk_ids = HashSet::new();
        for disk in &self.disks {
            require_plain_name("disk id", &disk.id)?;
            if !disk_ids.insert(disk.id.as_str()) {
                return Err(Error::InvalidSpec(format!(
                    "duplicate disk id `{}`",
                    disk.id
                )));
            }
            require_path("disk path", &disk.path)?;
        }
        if self.disks.iter().filter(|d| d.root).count() > 1 {
            return Err(Error::InvalidSpec(
                "more than one disk is marked root".into(),
            ));
        }
        let mut nic_ids = HashSet::new();
        for nic in &self.nics {
            if nic.id.is_empty() {
                return Err(Error::InvalidSpec("nic id must not be empty".into()));
            }
            if !nic_ids.insert(nic.id.as_str()) {
                return Err(Error::InvalidSpec(format!("duplicate nic id `{}`", nic.id)));
            }
            if nic.mac.is_nil() || !nic.mac.is_unicast() {
                return Err(Error::InvalidSpec(format!(
                    "nic `{}` mac {} is not a unicast address",
                    nic.id, nic.mac
                )));
            }
        }
        if let Some(vsock) = &self.vsock
            && vsock.guest_cid < VsockSpec::FIRST_GUEST_CID
        {
            return Err(Error::InvalidSpec(format!(
                "vsock guest_cid {} is reserved; use {} or above",
                vsock.guest_cid,
                VsockSpec::FIRST_GUEST_CID
            )));
        }
        let mut share_tags = HashSet::new();
        for share in &self.shares {
            if share.tag.is_empty() {
                return Err(Error::InvalidSpec("share tag must not be empty".into()));
            }
            if !share_tags.insert(share.tag.as_str()) {
                return Err(Error::InvalidSpec(format!(
                    "duplicate share tag `{}`",
                    share.tag
                )));
            }
            require_path("share host path", &share.host_path)?;
        }
        Ok(())
    }
}

fn require_path(what: &str, path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() {
        return Err(Error::InvalidSpec(format!("{what} must not be empty")));
    }
    Ok(())
}

/// The half of the name rules that does not depend on the alphabet:
/// non-empty and at most [`VmId::MAX_LEN`] bytes.
fn require_name_length(what: &str, name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(Error::InvalidSpec(format!("{what} must not be empty")));
    }
    if name.len() > VmId::MAX_LEN {
        return Err(Error::InvalidSpec(format!(
            "{what} `{name}` exceeds {} characters",
            VmId::MAX_LEN
        )));
    }
    Ok(())
}

/// The rule for a driver-internal name — one a driver may turn into a path
/// component or a URL segment, but never hands to a VMM as its instance id:
/// [`require_name_length`] plus `[A-Za-z0-9._-]`, and not the `.` / `..`
/// traversal names. Wider than [`VmId`]'s alphabet, which a VMM constrains.
fn require_plain_name(what: &str, name: &str) -> Result<()> {
    require_name_length(what, name)?;
    if let Some(bad) = name
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')))
    {
        return Err(Error::InvalidSpec(format!(
            "{what} `{name}` contains `{bad}`; allowed: A-Z a-z 0-9 . _ -"
        )));
    }
    if name == "." || name == ".." {
        return Err(Error::InvalidSpec(format!(
            "{what} `{name}` is a path traversal name"
        )));
    }
    Ok(())
}

/// How the guest starts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum BootSpec {
    /// Direct kernel boot.
    Kernel {
        /// The kernel image (vmlinux / Image).
        image: PathBuf,
        /// The kernel command line, verbatim.
        cmdline: String,
        /// An optional initial ramdisk.
        initrd: Option<PathBuf>,
    },
    /// Firmware (UEFI) boot; the firmware finds the OS on the disks.
    Firmware {
        /// The firmware image.
        image: PathBuf,
    },
    /// A macOS guest under Virtualization.framework.
    MacOs {
        /// The auxiliary storage (NVRAM) file.
        aux_storage: PathBuf,
        /// The opaque hardware-model blob the guest was installed for.
        hardware_model: Vec<u8>,
        /// The opaque machine-identifier blob.
        machine_id: Vec<u8>,
    },
}

impl BootSpec {
    fn validate(&self) -> Result<()> {
        match self {
            Self::Kernel { image, initrd, .. } => {
                require_path("kernel image", image)?;
                if let Some(initrd) = initrd {
                    require_path("initrd", initrd)?;
                }
                Ok(())
            }
            Self::Firmware { image } => require_path("firmware image", image),
            Self::MacOs { aux_storage, .. } => require_path("aux storage", aux_storage),
        }
    }
}

/// One block device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiskSpec {
    /// Unique within the spec; drivers use it as the device's name, and as
    /// a file name or URL segment, so it is held to the [`VmId`] rule
    /// (`[A-Za-z0-9._-]`, at most 64 characters, not `.` or `..`).
    pub id: String,
    /// The backing file on the host.
    pub path: PathBuf,
    /// Expose the disk read-only.
    #[serde(default)]
    pub read_only: bool,
    /// This disk holds the root filesystem (at most one per spec).
    #[serde(default)]
    pub root: bool,
    /// Host-side write caching.
    #[serde(default)]
    pub cache: CacheMode,
}

/// Host-side write caching for a disk (Firecracker's `DriveCacheType`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheMode {
    /// Writes complete when the host has them in memory (today's value).
    #[default]
    Unsafe,
    /// Writes complete when the host has flushed them.
    Writeback,
}

/// One network interface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NicSpec {
    /// Unique within the spec; drivers use it as the device's name.
    pub id: String,
    /// The guest-visible MAC address.
    pub mac: MacAddr,
    /// What the host side of the interface is plugged into.
    pub attachment: NicAttachment,
}

/// The host side of a NIC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum NicAttachment {
    /// A Linux TAP device the guest network created.
    Tap {
        /// The interface name (`tap12`).
        name: String,
    },
    /// The VMM's own NAT (Virtualization.framework's `NAT` attachment).
    HostNat,
    /// A host socket the VMM reads and writes Ethernet frames on.
    ///
    /// The number is a *borrowed* descriptor: the caller keeps it open for the
    /// duration of `VmDriver::boot`, and the driver duplicates it if
    /// the VMM needs it beyond that call.
    ///
    /// It is meaningful only in the process that opened it, so a spec
    /// carrying this variant is process-local: it serializes (the number is
    /// just data), but it is not what goes into a durable record or a TOML
    /// file — an orchestrator persists the VM's identity as
    /// [`VmRecord`](crate::driver::VmRecord) and re-derives the attachment
    /// when it builds the next spec.
    FileHandle {
        /// The raw descriptor number, valid in the calling process.
        fd: RawFd,
    },
    /// A host bridge interface (vmnet bridged mode, a Linux bridge).
    Bridge {
        /// The host interface to bridge onto.
        interface: String,
    },
}

/// The vsock device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VsockSpec {
    /// The guest's context id: [`Self::FIRST_GUEST_CID`] or above (0 and 1
    /// are reserved, 2 is the host).
    pub guest_cid: u32,
}

impl VsockSpec {
    /// The lowest context id a guest may take.
    pub const FIRST_GUEST_CID: u32 = 3;
}

/// One shared host directory (virtiofs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareSpec {
    /// The mount tag the guest sees.
    pub tag: String,
    /// The host directory.
    pub host_path: PathBuf,
    /// Export read-only.
    #[serde(default)]
    pub read_only: bool,
}

/// Where the guest console goes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ConsoleSpec {
    /// No console device.
    #[default]
    Off,
    /// Append console output to a file.
    File(PathBuf),
    /// Serve the console on a Unix socket.
    Socket(PathBuf),
}

/// How the VMM process is confined.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum IsolationSpec {
    /// Run the VMM as the caller, unconfined.
    #[default]
    None,
    /// Run under a jailer (Firecracker's `jailer`, or an equivalent).
    Jailer {
        /// The uid the VMM drops to.
        uid: u32,
        /// The gid the VMM drops to.
        gid: u32,
        /// The directory the per-VM chroot is created under.
        chroot_base: PathBuf,
        /// A network namespace to enter (`/var/run/netns/<name>`).
        netns: Option<PathBuf>,
        /// Start the VMM in a fresh PID namespace.
        new_pid_ns: bool,
        /// Cgroup placement.
        cgroup: Option<CgroupSpec>,
    },
}

/// Cgroup placement for a jailed VMM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CgroupSpec {
    /// The cgroup hierarchy version (1 or 2).
    pub version: u8,
    /// The parent cgroup, relative to the hierarchy root.
    pub parent: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mac(n: u8) -> MacAddr {
        MacAddr::new([0x02, 0, 0, 0, 0, n])
    }

    fn spec() -> VmSpec {
        VmSpec {
            id: VmId::new("vm-1").unwrap(),
            cpus: 2,
            memory_mib: 512,
            boot: BootSpec::Kernel {
                image: "/boot/vmlinux".into(),
                cmdline: "console=ttyS0".into(),
                initrd: None,
            },
            disks: vec![DiskSpec {
                id: "rootfs".into(),
                path: "/img/rootfs.ext4".into(),
                read_only: false,
                root: true,
                cache: CacheMode::default(),
            }],
            nics: vec![NicSpec {
                id: "eth0".into(),
                mac: mac(1),
                attachment: NicAttachment::Tap {
                    name: "tap0".into(),
                },
            }],
            vsock: Some(VsockSpec { guest_cid: 3 }),
            shares: vec![],
            console: ConsoleSpec::Off,
            balloon: false,
            entropy: true,
            dirty_tracking: false,
            isolation: IsolationSpec::None,
        }
    }

    fn invalid(spec: &VmSpec) -> String {
        match spec.validate() {
            Err(Error::InvalidSpec(msg)) => msg,
            other => panic!("expected InvalidSpec, got {other:?}"),
        }
    }

    #[test]
    fn vm_id_accepts_the_documented_alphabet_and_nothing_else() {
        assert!(VmId::new("a-b-c-D9").is_ok());
        assert!(VmId::new("x".repeat(VmId::MAX_LEN)).is_ok());
        assert!(VmId::new("").is_err());
        assert!(VmId::new("x".repeat(VmId::MAX_LEN + 1)).is_err());
        assert!(VmId::new("has space").is_err());
        assert!(VmId::new("slash/y").is_err());
        assert!(VmId::new("ünïcode").is_err());
    }

    /// A VMM validates the id it is given and refuses it late and loudly —
    /// Firecracker `panic!`s on `--id inst_abc` from inside whatever task
    /// spawned it. The separators a path would tolerate are refused here so
    /// no such id can be built in the first place.
    #[test]
    fn vm_id_refuses_the_separators_a_vmm_will_not_take() {
        for bad in ["inst_abc", "a.b", ".hidden", "...", ".", ".."] {
            match VmId::new(bad) {
                Err(Error::InvalidSpec(msg)) => {
                    assert!(msg.contains("allowed: A-Z a-z 0-9 -"), "{msg}");
                }
                other => panic!("`{bad}` gave {other:?}"),
            }
            assert!(serde_json::from_str::<VmId>(&format!("\"{bad}\"")).is_err());
        }
        // A disk id is a driver-internal name, never a VMM identity, so it
        // keeps the wider alphabet.
        let mut spec = spec();
        spec.disks[0].id = "root_disk.img".to_owned();
        assert!(spec.validate().is_ok());
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

    #[test]
    fn a_well_formed_spec_validates() {
        spec().validate().unwrap();
    }

    #[test]
    fn zero_cpus_or_memory_are_rejected() {
        let mut s = spec();
        s.cpus = 0;
        assert!(invalid(&s).contains("cpus"));
        let mut s = spec();
        s.memory_mib = 0;
        assert!(invalid(&s).contains("memory_mib"));
    }

    #[test]
    fn disk_ids_must_be_unique_and_root_is_singular() {
        let mut s = spec();
        s.disks.push(s.disks[0].clone());
        assert!(invalid(&s).contains("duplicate disk id"));
        let mut s = spec();
        let mut second = s.disks[0].clone();
        second.id = "data".into();
        s.disks.push(second);
        assert!(invalid(&s).contains("root"));
        let mut s = spec();
        s.disks[0].id.clear();
        assert!(invalid(&s).contains("disk id"));
        let mut s = spec();
        s.disks[0].path = PathBuf::new();
        assert!(invalid(&s).contains("disk path"));
    }

    #[test]
    fn disk_ids_are_plain_names() {
        for bad in [
            ".",
            "..",
            "a/b",
            "has space",
            "x".repeat(VmId::MAX_LEN + 1).as_str(),
        ] {
            let mut s = spec();
            s.disks[0].id = bad.into();
            assert!(invalid(&s).contains("disk id"), "`{bad}` accepted");
        }
        let mut s = spec();
        s.disks[0].id = "root.fs_v2-a".into();
        s.validate().unwrap();
    }

    #[test]
    fn nic_ids_must_be_unique_and_macs_unicast() {
        let mut s = spec();
        let mut second = s.nics[0].clone();
        second.mac = mac(2);
        s.nics.push(second);
        assert!(invalid(&s).contains("duplicate nic id"));
        let mut s = spec();
        s.nics[0].mac = MacAddr::new([0x01, 0, 0, 0, 0, 1]);
        assert!(invalid(&s).contains("unicast"));
        let mut s = spec();
        s.nics[0].mac = MacAddr::new([0; 6]);
        assert!(invalid(&s).contains("unicast"));
        let mut s = spec();
        s.nics[0].id.clear();
        assert!(invalid(&s).contains("nic id"));
    }

    #[test]
    fn vsock_guest_cid_must_not_be_reserved() {
        for cid in 0..VsockSpec::FIRST_GUEST_CID {
            let mut s = spec();
            s.vsock = Some(VsockSpec { guest_cid: cid });
            assert!(invalid(&s).contains("guest_cid"), "cid {cid} accepted");
        }
        let mut s = spec();
        s.vsock = Some(VsockSpec {
            guest_cid: VsockSpec::FIRST_GUEST_CID,
        });
        s.validate().unwrap();
    }

    #[test]
    fn share_tags_must_be_unique_and_paths_non_empty() {
        let share = ShareSpec {
            tag: "data".into(),
            host_path: "/srv/data".into(),
            read_only: false,
        };
        let mut s = spec();
        s.shares = vec![share.clone(), share.clone()];
        assert!(invalid(&s).contains("duplicate share tag"));
        let mut s = spec();
        s.shares = vec![ShareSpec {
            tag: String::new(),
            ..share.clone()
        }];
        assert!(invalid(&s).contains("share tag"));
        let mut s = spec();
        s.shares = vec![ShareSpec {
            host_path: PathBuf::new(),
            ..share.clone()
        }];
        assert!(invalid(&s).contains("share host path"));
        let mut s = spec();
        s.shares = vec![share];
        s.validate().unwrap();
    }

    #[test]
    fn boot_paths_must_be_non_empty() {
        let mut s = spec();
        s.boot = BootSpec::Kernel {
            image: PathBuf::new(),
            cmdline: String::new(),
            initrd: None,
        };
        assert!(invalid(&s).contains("kernel image"));
        let mut s = spec();
        s.boot = BootSpec::Kernel {
            image: "/boot/vmlinux".into(),
            cmdline: String::new(),
            initrd: Some(PathBuf::new()),
        };
        assert!(invalid(&s).contains("initrd"));
        let mut s = spec();
        s.boot = BootSpec::Firmware {
            image: PathBuf::new(),
        };
        assert!(invalid(&s).contains("firmware image"));
        let mut s = spec();
        s.boot = BootSpec::MacOs {
            aux_storage: PathBuf::new(),
            hardware_model: vec![],
            machine_id: vec![],
        };
        assert!(invalid(&s).contains("aux storage"));
    }

    #[test]
    fn spec_round_trips_through_json_with_defaults_filled() {
        let mut s = spec();
        s.isolation = IsolationSpec::Jailer {
            uid: 1000,
            gid: 1000,
            chroot_base: "/srv/jailer".into(),
            netns: None,
            new_pid_ns: true,
            cgroup: Some(CgroupSpec {
                version: 2,
                parent: Some("arcbox".into()),
            }),
        };
        s.console = ConsoleSpec::File("/tmp/console.log".into());
        s.nics.push(NicSpec {
            id: "eth1".into(),
            mac: mac(3),
            attachment: NicAttachment::FileHandle { fd: 7 },
        });
        let json = serde_json::to_string(&s).unwrap();
        let back: VmSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);

        // A minimal document — only the required fields — decodes with the
        // documented defaults, which is what a hand-written TOML relies on.
        let minimal = serde_json::json!({
            "id": "vm-2",
            "cpus": 1,
            "memory_mib": 128,
            "boot": { "firmware": { "image": "/fw/OVMF.fd" } },
        });
        let s: VmSpec = serde_json::from_value(minimal).unwrap();
        assert_eq!(s.console, ConsoleSpec::Off);
        assert_eq!(s.isolation, IsolationSpec::None);
        assert!(s.disks.is_empty() && s.nics.is_empty() && s.vsock.is_none());
        assert!(!s.balloon && !s.entropy && !s.dirty_tracking);
    }
}
