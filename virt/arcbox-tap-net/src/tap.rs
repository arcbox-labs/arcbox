//! The persistent TAP device of one VM: created over `/dev/net/tun`,
//! brought up, and given its point-to-point addresses through `ioctl`;
//! destroyed by clearing the persist flag, with `ip link delete` as the
//! fallback. Linux-only — the crate root gates the module.

use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};

use crate::error::{Result, TapNetError};

/// Create the persistent TAP `tap_name`, bring it up, and configure the
/// point-to-point link `local` -> `ip` with a /32 netmask so the kernel
/// installs a host route to the peer. Any stale device of the same name
/// is removed first; a failure part-way through destroys what was
/// created.
pub fn create(tap_name: &str, local: Ipv4Addr, ip: Ipv4Addr) -> Result<()> {
    // Remove any stale TAP left over from a previous crashed run.
    destroy_checked(tap_name)?;

    let name_bytes = tap_name.as_bytes();
    if name_bytes.len() >= libc::IFNAMSIZ {
        return Err(TapNetError::Network(format!(
            "TAP name too long: {tap_name}"
        )));
    }

    // 1. Create persistent TAP device via /dev/net/tun.
    let tun = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/net/tun")
        .map_err(|e| TapNetError::Network(format!("open /dev/net/tun: {e}")))?;

    let mut ifr = new_ifreq(name_bytes);
    ifr.ifr_ifru.ifru_flags = (libc::IFF_TAP | libc::IFF_NO_PI) as i16;

    const TUNSETIFF: libc::c_ulong = 0x400454ca;
    const TUNSETPERSIST: libc::c_ulong = 0x400454cb;

    // SAFETY: tun fd is valid, ifr is initialized with name and flags.
    if unsafe { libc::ioctl(tun.as_raw_fd(), TUNSETIFF as _, &ifr) } < 0 {
        return Err(TapNetError::Network(format!(
            "TUNSETIFF {tap_name}: {}",
            std::io::Error::last_os_error()
        )));
    }

    // Make persistent so Firecracker can reopen the TAP by name.
    // SAFETY: tun fd is attached to the TAP device after TUNSETIFF.
    if unsafe { libc::ioctl(tun.as_raw_fd(), TUNSETPERSIST as _, 1i32) } < 0 {
        return Err(TapNetError::Network(format!(
            "TUNSETPERSIST {tap_name}: {}",
            std::io::Error::last_os_error()
        )));
    }
    drop(tun);

    // 2. Bring interface up via ioctl on a helper socket.
    // SAFETY: standard socket creation.
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        destroy(tap_name);
        return Err(TapNetError::Network(format!(
            "socket: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: sock is a valid fd returned by socket().
    let sock = unsafe { OwnedFd::from_raw_fd(sock) };

    // SAFETY: sock and ifr.ifr_name are valid; kernel writes ifr_flags.
    if unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCGIFFLAGS as _, &ifr) } < 0 {
        destroy(tap_name);
        return Err(TapNetError::Network(format!(
            "SIOCGIFFLAGS {tap_name}: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: ifr_flags is valid from SIOCGIFFLAGS; adding IFF_UP.
    unsafe { ifr.ifr_ifru.ifru_flags |= libc::IFF_UP as i16 };
    // SAFETY: sock and ifr are valid.
    if unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCSIFFLAGS as _, &ifr) } < 0 {
        destroy(tap_name);
        return Err(TapNetError::Network(format!(
            "SIOCSIFFLAGS UP {tap_name}: {}",
            std::io::Error::last_os_error()
        )));
    }

    // 3. Configure point-to-point IP on TAP host end (the gateway the
    //    guest routes through) so the sandbox can use it as its default
    //    gateway. Each TAP is an isolated link — sandboxes cannot see
    //    each other at L2.
    //
    // Wrap in a closure so a failure in any set_ifaddr triggers TAP cleanup.
    if let Err(e) = (|| -> Result<()> {
        // Set local address (gateway).
        set_ifaddr(
            &sock,
            &ifr,
            libc::SIOCSIFADDR,
            local,
            tap_name,
            "SIOCSIFADDR",
        )?;
        // Set peer (destination) address (sandbox IP).
        set_ifaddr(
            &sock,
            &ifr,
            libc::SIOCSIFDSTADDR,
            ip,
            tap_name,
            "SIOCSIFDSTADDR",
        )?;
        // Set /32 netmask so the kernel creates a proper host route to the peer.
        set_ifaddr(
            &sock,
            &ifr,
            libc::SIOCSIFNETMASK,
            Ipv4Addr::BROADCAST, // 255.255.255.255
            tap_name,
            "SIOCSIFNETMASK",
        )?;
        Ok(())
    })() {
        destroy(tap_name);
        return Err(e);
    }

    Ok(())
}

/// Creates a zero-initialized `ifreq` with the given interface name.
fn new_ifreq(name_bytes: &[u8]) -> libc::ifreq {
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    // SAFETY: caller must ensure name_bytes.len() < IFNAMSIZ.
    unsafe {
        std::ptr::copy_nonoverlapping(
            name_bytes.as_ptr(),
            ifr.ifr_name.as_mut_ptr().cast::<u8>(),
            name_bytes.len(),
        );
    }
    ifr
}

/// Sets an IPv4 address on an interface via ioctl.
fn set_ifaddr(
    sock: &OwnedFd,
    ifr: &libc::ifreq,
    request: libc::c_ulong,
    addr: Ipv4Addr,
    tap_name: &str,
    label: &str,
) -> Result<()> {
    let mut req = *ifr;
    let mut addr_in: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    addr_in.sin_family = libc::AF_INET as libc::sa_family_t;
    addr_in.sin_addr.s_addr = u32::from(addr).to_be();

    // SAFETY: sockaddr_in fits within ifr_ifru (both are >= 16 bytes).
    unsafe {
        std::ptr::copy_nonoverlapping(
            (&raw const addr_in).cast::<u8>(),
            (&raw mut req.ifr_ifru).cast::<u8>(),
            std::mem::size_of::<libc::sockaddr_in>(),
        );
    }
    // SAFETY: sock and req are valid; kernel reads ifr_name and sockaddr.
    if unsafe { libc::ioctl(sock.as_raw_fd(), request as _, &req) } < 0 {
        return Err(TapNetError::Network(format!(
            "{label} {tap_name} {addr}: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// Destroys a persistent TAP device.
///
/// First attempts to clear the persist flag via ioctl (re-attach then
/// `TUNSETPERSIST 0`). If the interface still exists afterwards, falls back
/// to `ip link delete` which works regardless of fd state.
pub fn destroy(tap_name: &str) {
    if let Err(error) = destroy_checked(tap_name) {
        tracing::warn!(tap = tap_name, error = %error, "failed to destroy TAP");
    }
}

pub fn destroy_checked(tap_name: &str) -> Result<()> {
    let name_bytes = tap_name.as_bytes();
    if name_bytes.len() >= libc::IFNAMSIZ {
        return Err(TapNetError::Network(format!(
            "TAP name too long: {tap_name}"
        )));
    }

    // Try ioctl-based removal first.
    if let Ok(tun) = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/net/tun")
    {
        let mut ifr = new_ifreq(name_bytes);
        ifr.ifr_ifru.ifru_flags = (libc::IFF_TAP | libc::IFF_NO_PI) as i16;

        const TUNSETIFF: libc::c_ulong = 0x400454ca;
        const TUNSETPERSIST: libc::c_ulong = 0x400454cb;

        // SAFETY: tun fd is valid, ifr is properly initialized.
        if unsafe { libc::ioctl(tun.as_raw_fd(), TUNSETIFF as _, &ifr) } >= 0 {
            // SAFETY: tun fd is attached to the TAP device; clearing persist removes it.
            let _ = unsafe { libc::ioctl(tun.as_raw_fd(), TUNSETPERSIST as _, 0i32) };
        }
        drop(tun);
    }

    // Fallback: if the interface still exists, use ip link delete.
    //
    // The existence check and the delete race the kernel: clearing
    // TUNSETPERSIST above and dropping the fd removes a non-persistent TAP
    // asynchronously, so the sysfs entry can outlive the decision to delete
    // and vanish before `ip` runs. A delete that fails because the device
    // is already gone has reached exactly the state this function exists to
    // reach, so the post-check below — not the exit status — decides: the
    // device being absent is success no matter why `ip` complained.
    //
    // Deliberately not a message match: the System VM ships busybox `ip`
    // ("can't find device 'x'", exit 2) while a dev host has iproute2
    // ("Cannot find device \"x\"", exit 1), so any wording test would pass
    // CI and still fail in production.
    //
    // PATH lookup, not an absolute path: the System VM rootfs installs the
    // busybox `ip` applet at /bin/ip (BUSYBOX_SYMLINKS in boot-assets
    // rootfs.rs) while Linux hosts carry iproute2 in /sbin or /usr/sbin —
    // no single absolute path exists in both environments, and the old
    // hardcoded /usr/sbin/ip made every create that lost the sysfs race
    // above fail with ENOENT inside the guest.
    let sysfs = format!("/sys/class/net/{tap_name}");
    let mut delete_error = None;
    if std::path::Path::new(&sysfs).exists() {
        let output = std::process::Command::new("ip")
            .args(["link", "delete", tap_name])
            .output()
            .map_err(|error| {
                TapNetError::Network(format!("run ip link delete {tap_name}: {error}"))
            })?;
        if !output.status.success() {
            delete_error = Some(String::from_utf8_lossy(&output.stderr).trim().to_owned());
        }
    }
    if std::path::Path::new(&sysfs).exists() {
        return Err(TapNetError::Network(match delete_error {
            Some(stderr) => format!("ip link delete {tap_name}: {stderr}"),
            None => format!("TAP {tap_name} still exists after deletion"),
        }));
    }
    Ok(())
}
