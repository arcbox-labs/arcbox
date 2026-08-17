//! Discovery half of the live-container NFS view (ABX-424).
//!
//! A running container's merged rootfs is an overlay mount, and the docker
//! data mount is bind-propagated into the NFS export root, so every container
//! already appears at
//! `/run/arcbox/nfs-export/docker/rootfs/overlayfs/<container id>` without any
//! bind of its own. What it does *not* have is an `/etc/exports` entry, and
//! NFSv4 will not cross into an unexported child mount — the host sees the
//! empty directory the overlay is mounted over, which reads as "the container
//! has no files" rather than as an error.
//!
//! `crossmnt` would cross automatically and is banned: it SIGSEGVs the
//! shipped `rpc.mountd`, leaving a zombie whose name still satisfies the
//! respawn guard, after which every export upcall goes unanswered and the
//! host's `mount_nfs` wedges in uninterruptible sleep with no diagnostics. So
//! each mount gets an explicit entry, and something has to notice them coming
//! and going.
//!
//! **Departures need no ordering.** Measured 2026-08-17: an export entry does
//! not pin its mount — `docker rm -f` unmounts a currently-exported rootfs
//! without complaint. So this can be driven entirely by watching the mount
//! table, with no container-lifecycle event source and no requirement to
//! unexport before dockerd tears a container down. (An earlier spike concluded
//! the opposite, but that was with `crossmnt` in play.)
//!
//! This module is the pure half — parsing and naming — kept out of
//! `agent/linux/` on purpose so its tests run on a macOS dev host too.

/// Where container rootfs overlays surface inside the export root.
pub const EXPORT_ROOTFS_PREFIX: &str = "/run/arcbox/nfs-export/docker/rootfs/overlayfs/";

/// Mountpoints of the container rootfs overlays currently inside the export
/// root, in a stable order.
///
/// Reads `/proc/self/mountinfo` rather than `/proc/self/mounts` because only
/// the former can be `poll()`ed for changes, and parsing whatever we watch
/// avoids the two disagreeing. Its fstype lives after the ` - ` separator,
/// which is also what makes the separator load-bearing: optional fields sit
/// before it and their count varies per mount.
#[must_use]
pub fn rootfs_mountpoints(mountinfo: &str) -> Vec<String> {
    let mut found: Vec<String> = mountinfo
        .lines()
        .filter_map(parse_overlay_mountpoint)
        .filter(|mountpoint| mountpoint.starts_with(EXPORT_ROOTFS_PREFIX))
        .map(str::to_owned)
        .collect();
    found.sort();
    found.dedup();
    found
}

fn parse_overlay_mountpoint(line: &str) -> Option<&str> {
    let (before, after) = line.split_once(" - ")?;
    // fstype is the first field after the separator.
    if after.split_whitespace().next()? != "overlay" {
        return None;
    }
    // mountpoint is the 5th field of the fixed prefix.
    before.split_whitespace().nth(4)
}

/// A stable, collision-resistant `fsid` for an export entry.
///
/// Every export needs its own fsid, and the obvious counter would need
/// allocation state that survives an agent restart and container churn. A
/// digest of the mountpoint needs none: it is identical across restarts,
/// distinct per container, and computable by anyone holding the path.
///
/// Rendered in UUID shape because `exportfs` accepts `fsid=<uuid>` alongside
/// the small-integer form, which is what makes a stateless 128-bit id usable
/// at all — verified against the shipped nfs-utils and kernel before this was
/// built on.
#[must_use]
pub fn fsid_for(mountpoint: &str) -> String {
    use std::fmt::Write as _;

    use sha2::{Digest, Sha256};

    let digest = Sha256::digest(mountpoint.as_bytes());
    let mut hex = String::with_capacity(32);
    for byte in digest.iter().take(16) {
        let _ = write!(hex, "{byte:02x}");
    }
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real lines, including the two shapes that matter: a container rootfs
    /// inside the export root, and its twin under `/var/lib/docker` which must
    /// not be exported (it is the same filesystem, reachable through the
    /// export root already).
    const MOUNTINFO: &str = "\
25 24 0:23 / /proc rw,nosuid,nodev,noexec,relatime shared:5 - proc proc rw
71 30 0:52 / /var/lib/docker/rootfs/overlayfs/9aa873fd rw,relatime - overlay overlay rw,lowerdir=/a:/b,upperdir=/c,workdir=/d,index=on,nfs_export=on
72 31 0:52 / /run/arcbox/nfs-export/docker/rootfs/overlayfs/9aa873fd rw,relatime - overlay overlay rw,lowerdir=/a:/b,upperdir=/c,workdir=/d,index=on,nfs_export=on
73 31 0:11 / /run/arcbox/nfs-export/docker/containerd ro,noatime - btrfs /dev/vdb ro,subvol=/@containerd
";

    #[test]
    fn only_overlays_inside_the_export_root_are_returned() {
        assert_eq!(
            rootfs_mountpoints(MOUNTINFO),
            vec!["/run/arcbox/nfs-export/docker/rootfs/overlayfs/9aa873fd".to_owned()]
        );
    }

    /// The optional-field count before ` - ` varies per mount (`shared:5`
    /// above, nothing on the overlays), so the fstype must be read from after
    /// the separator rather than at a fixed offset.
    #[test]
    fn optional_fields_do_not_shift_the_fstype() {
        let with_optionals = "\
72 31 0:52 / /run/arcbox/nfs-export/docker/rootfs/overlayfs/abc rw,relatime shared:9 master:2 - overlay overlay rw,index=on
";
        assert_eq!(
            rootfs_mountpoints(with_optionals),
            vec!["/run/arcbox/nfs-export/docker/rootfs/overlayfs/abc".to_owned()]
        );
    }

    /// A btrfs mount whose *source* string contains "overlay" must not be
    /// mistaken for an overlay mount.
    #[test]
    fn the_fstype_decides_not_the_source_string() {
        let misleading = "\
74 31 0:11 / /run/arcbox/nfs-export/docker/rootfs/overlayfs/abc ro,noatime - btrfs /dev/overlay ro
";
        assert!(rootfs_mountpoints(misleading).is_empty());
    }

    #[test]
    fn fsid_is_uuid_shaped_stable_and_distinct() {
        let one = fsid_for("/run/arcbox/nfs-export/docker/rootfs/overlayfs/aaa");
        let two = fsid_for("/run/arcbox/nfs-export/docker/rootfs/overlayfs/bbb");

        assert_eq!(
            one,
            fsid_for("/run/arcbox/nfs-export/docker/rootfs/overlayfs/aaa")
        );
        assert_ne!(one, two);
        assert_eq!(one.len(), 36);
        assert_eq!(
            one.split('-').map(str::len).collect::<Vec<_>>(),
            vec![8, 4, 4, 4, 12]
        );
        assert!(one.chars().all(|c| c.is_ascii_hexdigit() || c == '-'));
    }

    /// fsid 0 and 1 are taken by the docker and containerd exports; a derived
    /// id must never render as one of those.
    #[test]
    fn a_derived_fsid_never_collides_with_the_static_exports() {
        for id in ["/x", "/y", EXPORT_ROOTFS_PREFIX] {
            let fsid = fsid_for(id);
            assert_ne!(fsid, "0");
            assert_ne!(fsid, "1");
        }
    }
}
