//! TAP-device backend (Linux only).

#![cfg(target_os = "linux")]

use std::os::unix::io::RawFd;

use crate::backend::{NetBackend, NetOffloadFlags};
use crate::header::NetPacket;

// Linux kernel `TUNSETOFFLOAD` / `TUNSETVNETHDRSZ` ioctl numbers and the
// `TUN_F_*` flag bits. See `<linux/if_tun.h>` — we encode them inline rather
// than pulling in another crate because only the TAP backend needs them.
const TUNSETOFFLOAD: libc::c_ulong = 0x400454d0;
const TUNSETVNETHDRSZ: libc::c_ulong = 0x400454d8;

const TUN_F_CSUM: u32 = 0x01;
const TUN_F_TSO4: u32 = 0x02;
const TUN_F_TSO6: u32 = 0x04;
const TUN_F_TSO_ECN: u32 = 0x08;
const TUN_F_UFO: u32 = 0x10;

/// TAP network backend for Linux.
pub struct TapBackend {
    /// TAP file descriptor.
    fd: RawFd,
    /// TAP device name.
    name: String,
    /// Non-blocking mode.
    nonblocking: bool,
}

impl TapBackend {
    /// Creates a new TAP device.
    ///
    /// # Errors
    ///
    /// Returns an error if TAP device creation fails.
    pub fn new(name: Option<&str>) -> std::io::Result<Self> {
        // SAFETY: open() with a static null-terminated path string. The
        // returned fd (if non-negative) is owned by `Self` and closed in `Drop`.
        let fd: RawFd = unsafe {
            libc::open(
                b"/dev/net/tun\0".as_ptr() as *const libc::c_char,
                libc::O_RDWR | libc::O_CLOEXEC,
            )
        };

        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }

        #[repr(C)]
        struct Ifreq {
            ifr_name: [libc::c_char; libc::IFNAMSIZ],
            ifr_flags: libc::c_short,
            _padding: [u8; 22], // Padding to match ifreq size
        }

        let mut ifr = Ifreq {
            ifr_name: [0; libc::IFNAMSIZ],
            ifr_flags: (libc::IFF_TAP | libc::IFF_NO_PI) as libc::c_short,
            _padding: [0; 22],
        };

        if let Some(dev_name) = name {
            let name_bytes = dev_name.as_bytes();
            let len = name_bytes.len().min(libc::IFNAMSIZ - 1);
            for (i, &b) in name_bytes[..len].iter().enumerate() {
                ifr.ifr_name[i] = b as libc::c_char;
            }
        }

        // Create TAP device
        const TUNSETIFF: libc::c_ulong = 0x400454ca;
        // SAFETY: ioctl reads `&ifr` for the duration of the call; on failure
        // we close the fd we just opened.
        let ret = unsafe { libc::ioctl(fd, TUNSETIFF, &ifr) };
        if ret < 0 {
            unsafe { libc::close(fd) };
            return Err(std::io::Error::last_os_error());
        }

        let name = {
            let len = ifr
                .ifr_name
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(libc::IFNAMSIZ);
            let bytes: Vec<u8> = ifr.ifr_name[..len].iter().map(|&c| c as u8).collect();
            String::from_utf8_lossy(&bytes).into_owned()
        };

        tracing::info!("Created TAP device: {}", name);

        Ok(Self {
            fd,
            name,
            nonblocking: false,
        })
    }

    /// Sets non-blocking mode.
    pub fn set_nonblocking(&mut self, nonblocking: bool) -> std::io::Result<()> {
        // SAFETY: F_GETFL/F_SETFL on a fd we exclusively own.
        let flags = unsafe { libc::fcntl(self.fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(std::io::Error::last_os_error());
        }

        let new_flags = if nonblocking {
            flags | libc::O_NONBLOCK
        } else {
            flags & !libc::O_NONBLOCK
        };

        // SAFETY: see above.
        let ret = unsafe { libc::fcntl(self.fd, libc::F_SETFL, new_flags) };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }

        self.nonblocking = nonblocking;
        Ok(())
    }

    /// Returns the TAP device name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Brings the interface up.
    pub fn bring_up(&self) -> std::io::Result<()> {
        use std::process::Command;

        let status = Command::new("ip")
            .args(["link", "set", &self.name, "up"])
            .status()?;

        if status.success() {
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Failed to bring interface up",
            ))
        }
    }

    /// Sets the IP address.
    pub fn set_ip(&self, ip: &str, prefix_len: u8) -> std::io::Result<()> {
        use std::process::Command;

        let addr = format!("{}/{}", ip, prefix_len);
        let status = Command::new("ip")
            .args(["addr", "add", &addr, "dev", &self.name])
            .status()?;

        if status.success() {
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Failed to set IP address",
            ))
        }
    }
}

impl Drop for TapBackend {
    fn drop(&mut self) {
        if self.fd >= 0 {
            // SAFETY: closing an fd we exclusively own.
            unsafe { libc::close(self.fd) };
        }
    }
}

impl NetBackend for TapBackend {
    fn send(&mut self, packet: &NetPacket) -> std::io::Result<usize> {
        // SAFETY: write reads packet.data.len() bytes from a borrowed slice.
        let ret = unsafe {
            libc::write(
                self.fd,
                packet.data.as_ptr() as *const libc::c_void,
                packet.data.len(),
            )
        };

        if ret < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(ret as usize)
        }
    }

    fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // SAFETY: read writes at most buf.len() bytes into a borrowed mut slice.
        let ret = unsafe { libc::read(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };

        if ret < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                Ok(0)
            } else {
                Err(err)
            }
        } else {
            Ok(ret as usize)
        }
    }

    fn has_data(&self) -> bool {
        let mut pollfd = libc::pollfd {
            fd: self.fd,
            events: libc::POLLIN,
            revents: 0,
        };

        // SAFETY: poll borrows our pollfd for the duration of the call (timeout 0).
        let ret = unsafe { libc::poll(&mut pollfd, 1, 0) };
        ret > 0 && (pollfd.revents & libc::POLLIN) != 0
    }

    fn configure_offload(&mut self, flags: NetOffloadFlags) -> std::io::Result<()> {
        let mut tun_flags: u32 = 0;
        if flags.csum {
            tun_flags |= TUN_F_CSUM;
        }
        if flags.tso4 {
            tun_flags |= TUN_F_TSO4;
        }
        if flags.tso6 {
            tun_flags |= TUN_F_TSO6;
        }
        if flags.tso_ecn {
            tun_flags |= TUN_F_TSO_ECN;
        }
        if flags.ufo {
            tun_flags |= TUN_F_UFO;
        }

        // SAFETY: TUNSETOFFLOAD reads `tun_flags` as an unsigned int. The fd
        // is exclusively owned by `self`.
        let ret = unsafe { libc::ioctl(self.fd, TUNSETOFFLOAD, tun_flags) };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
        tracing::debug!(
            "TAP {}: configured offload flags=0x{:x} (csum={} tso4={} tso6={} tso_ecn={} ufo={})",
            self.name,
            tun_flags,
            flags.csum,
            flags.tso4,
            flags.tso6,
            flags.tso_ecn,
            flags.ufo,
        );
        Ok(())
    }

    fn set_vnet_hdr_sz(&mut self, size: u32) -> std::io::Result<()> {
        let sz: libc::c_int = size as libc::c_int;
        // SAFETY: TUNSETVNETHDRSZ reads `sz` as an int. The fd is exclusively owned.
        let ret = unsafe { libc::ioctl(self.fd, TUNSETVNETHDRSZ, &sz) };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
        tracing::debug!("TAP {}: set vnet_hdr_sz = {}", self.name, size);
        Ok(())
    }
}
