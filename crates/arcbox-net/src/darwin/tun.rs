//! macOS utun device for host-side packet I/O.
//!
//! Provides a Layer 3 tunnel interface for sending/receiving IP packets
//! between the NAT engine and the host network stack.
//!
//! # Architecture
//!
//! ```text
//! Guest VM
//!   │  (virtio-net)
//!   ▼
//! NAT Engine (SNAT/DNAT)
//!   │
//!   ▼
//! DarwinTun (utun device)
//!   │  (IP packets)
//!   ▼
//! macOS network stack → Internet
//! ```
//!
//! # Protocol
//!
//! The utun device on macOS uses a 4-byte address family header prepended
//! to each IP packet. For IPv4, this header is `AF_INET` (2) in host
//! byte order as a `u32`.
//!
//! # Requirements
//!
//! - macOS 10.10+ (no root required for creating utun devices)
//! - IP forwarding must be enabled for routing: `sysctl net.inet.ip.forwarding=1`

use std::io;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

/// 4-byte AF header size prepended to each packet on the utun device.
const AF_HEADER_SIZE: usize = 4;

/// Maximum reasonable MTU including the AF header.
const MAX_PACKET_SIZE: usize = 65535 + AF_HEADER_SIZE;

// macOS ioctl constants not exposed by the libc crate.
// Values are from <sys/sockio.h> on macOS (arm64/x86_64).
const SIOCSIFADDR: libc::c_ulong = 0x8020_690c;
const SIOCSIFDSTADDR: libc::c_ulong = 0x8020_690e;
const SIOCSIFFLAGS: libc::c_ulong = 0x8020_6910;
const SIOCGIFFLAGS: libc::c_ulong = 0xc020_6911;
const SIOCSIFNETMASK: libc::c_ulong = 0x8020_6916;

/// macOS utun device for host-side packet I/O.
///
/// Creates a point-to-point tunnel interface that allows sending and
/// receiving IP packets between userspace and the macOS network stack.
/// The NAT engine writes translated packets here, and the host kernel
/// routes them to their destination.
pub struct DarwinTun {
    /// Owned file descriptor for the utun socket.
    fd: OwnedFd,
    /// Interface name assigned by the kernel (e.g., "utun5").
    name: String,
}

impl DarwinTun {
    /// Creates a new utun device.
    ///
    /// The kernel assigns the next available utun interface number.
    /// No root privileges are required on macOS 10.10+.
    ///
    /// # Errors
    ///
    /// Returns an error if the utun device cannot be created (e.g.,
    /// the system control socket fails or the connection is refused).
    pub fn new() -> io::Result<Self> {
        // Step 1: Create a PF_SYSTEM socket with SYSPROTO_CONTROL protocol.
        // Safety: socket() is safe to call with valid parameters.
        let fd = unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // Safety: fd is valid from the socket() call above.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };

        // Step 2: Look up the control ID for "com.apple.net.utun_control".
        let mut ctl_info: libc::ctl_info = unsafe { std::mem::zeroed() };
        let ctl_name = b"com.apple.net.utun_control\0";
        // Safety: ctl_name fits within ctl_info.ctl_name (MAX_KCTL_NAME = 96 bytes).
        unsafe {
            std::ptr::copy_nonoverlapping(
                ctl_name.as_ptr(),
                ctl_info.ctl_name.as_mut_ptr().cast::<u8>(),
                ctl_name.len(),
            );
        }

        // Safety: CTLIOCGINFO ioctl is safe with a valid fd and ctl_info pointer.
        let ret = unsafe { libc::ioctl(fd.as_raw_fd(), libc::CTLIOCGINFO, &mut ctl_info) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        // Step 3: Connect to the control to create the utun interface.
        // sc_unit = 0 means "assign next available utun number".
        let addr = libc::sockaddr_ctl {
            sc_len: std::mem::size_of::<libc::sockaddr_ctl>() as u8,
            sc_family: libc::AF_SYSTEM as u8,
            ss_sysaddr: libc::AF_SYS_CONTROL as u16,
            sc_id: ctl_info.ctl_id,
            sc_unit: 0,
            sc_reserved: [0; 5],
        };

        // Safety: connect() is safe with valid fd and properly initialized addr.
        let ret = unsafe {
            libc::connect(
                fd.as_raw_fd(),
                &addr as *const libc::sockaddr_ctl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ctl>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        // Step 4: Retrieve the assigned interface name via SIOCGIFNAME
        // or getsockopt with UTUN_OPT_IFNAME.
        let name = Self::get_interface_name(fd.as_raw_fd())?;

        tracing::info!(interface = %name, "Created utun device");

        Ok(Self { fd, name })
    }

    /// Retrieves the interface name from the utun socket.
    fn get_interface_name(fd: RawFd) -> io::Result<String> {
        // Use getsockopt with SYSPROTO_CONTROL / UTUN_OPT_IFNAME
        // to get the interface name.
        const UTUN_OPT_IFNAME: libc::c_int = 2;
        let mut name_buf = [0u8; libc::IFNAMSIZ];
        let mut name_len: libc::socklen_t = name_buf.len() as libc::socklen_t;

        // Safety: getsockopt is safe with valid fd and properly sized buffer.
        let ret = unsafe {
            libc::getsockopt(
                fd,
                libc::SYSPROTO_CONTROL,
                UTUN_OPT_IFNAME,
                name_buf.as_mut_ptr().cast(),
                &mut name_len,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        // Convert to string, trimming the null terminator.
        let name = std::str::from_utf8(&name_buf[..name_len as usize])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
            .trim_end_matches('\0')
            .to_string();

        Ok(name)
    }

    /// Returns the interface name (e.g., "utun5").
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the raw file descriptor for the utun socket.
    ///
    /// Useful for integrating with async runtimes (e.g., registering
    /// with tokio's `AsyncFd`).
    #[must_use]
    pub fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// Configures the utun interface with IP addresses and brings it up.
    ///
    /// This runs the equivalent of:
    /// ```text
    /// ifconfig utunN inet <local_ip> <peer_ip> netmask <netmask> up
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the interface configuration fails (typically
    /// requires appropriate permissions).
    pub fn configure(
        &self,
        local_ip: Ipv4Addr,
        peer_ip: Ipv4Addr,
        netmask: Ipv4Addr,
    ) -> io::Result<()> {
        // Use a temporary DGRAM socket for ioctl operations on the interface.
        // Safety: socket() with AF_INET/SOCK_DGRAM is always safe.
        let ctl_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if ctl_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // Safety: ctl_fd is valid from socket() above.
        let ctl_fd = unsafe { OwnedFd::from_raw_fd(ctl_fd) };

        // Build the interface name as a C-compatible fixed-size array.
        let mut ifr_name = [0u8; libc::IFNAMSIZ];
        let name_bytes = self.name.as_bytes();
        if name_bytes.len() >= libc::IFNAMSIZ {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "interface name too long",
            ));
        }
        ifr_name[..name_bytes.len()].copy_from_slice(name_bytes);

        // Set the local (source) address with SIOCSIFADDR.
        Self::set_ifaddr(ctl_fd.as_raw_fd(), &ifr_name, SIOCSIFADDR, local_ip)?;

        // Set the peer (destination) address with SIOCSIFDSTADDR.
        Self::set_ifaddr(ctl_fd.as_raw_fd(), &ifr_name, SIOCSIFDSTADDR, peer_ip)?;

        // Set the netmask with SIOCSIFNETMASK.
        Self::set_ifaddr(ctl_fd.as_raw_fd(), &ifr_name, SIOCSIFNETMASK, netmask)?;

        // Bring the interface up with SIOCSIFFLAGS.
        Self::set_if_up(ctl_fd.as_raw_fd(), &ifr_name)?;

        tracing::info!(
            interface = %self.name,
            local = %local_ip,
            peer = %peer_ip,
            netmask = %netmask,
            "Configured utun interface"
        );

        Ok(())
    }

    /// Sets an IPv4 address on the interface using an ioctl.
    fn set_ifaddr(
        ctl_fd: RawFd,
        ifr_name: &[u8; libc::IFNAMSIZ],
        ioctl_cmd: libc::c_ulong,
        addr: Ipv4Addr,
    ) -> io::Result<()> {
        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        // Safety: ifr_name is IFNAMSIZ bytes.
        unsafe {
            std::ptr::copy_nonoverlapping(
                ifr_name.as_ptr(),
                ifr.ifr_name.as_mut_ptr().cast::<u8>(),
                libc::IFNAMSIZ,
            );
        }

        // Build sockaddr_in for the address.
        let sin = Self::make_sockaddr_in(addr);
        // Safety: sockaddr_in fits within the ifr_ifru union.
        unsafe {
            std::ptr::copy_nonoverlapping(
                &sin as *const libc::sockaddr_in as *const u8,
                &mut ifr.ifr_ifru as *mut _ as *mut u8,
                std::mem::size_of::<libc::sockaddr_in>(),
            );
        }

        // Safety: ioctl with valid fd and properly initialized ifreq.
        let ret = unsafe { libc::ioctl(ctl_fd, ioctl_cmd, &ifr) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    /// Brings the interface up by setting the IFF_UP flag.
    fn set_if_up(ctl_fd: RawFd, ifr_name: &[u8; libc::IFNAMSIZ]) -> io::Result<()> {
        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        // Safety: ifr_name is IFNAMSIZ bytes.
        unsafe {
            std::ptr::copy_nonoverlapping(
                ifr_name.as_ptr(),
                ifr.ifr_name.as_mut_ptr().cast::<u8>(),
                libc::IFNAMSIZ,
            );
        }

        // First, get current flags.
        // Safety: SIOCGIFFLAGS ioctl is safe with valid fd and ifreq.
        let ret = unsafe { libc::ioctl(ctl_fd, SIOCGIFFLAGS, &mut ifr) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        // Set IFF_UP and IFF_RUNNING.
        // Safety: ifr_ifru contains the flags after SIOCGIFFLAGS.
        unsafe {
            let flags = ifr.ifr_ifru.ifru_flags;
            ifr.ifr_ifru.ifru_flags = flags | (libc::IFF_UP as i16) | (libc::IFF_RUNNING as i16);
        }

        // Apply the new flags.
        // Safety: SIOCSIFFLAGS ioctl is safe with valid fd and ifreq.
        let ret = unsafe { libc::ioctl(ctl_fd, SIOCSIFFLAGS, &ifr) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    /// Constructs a `sockaddr_in` for the given IPv4 address.
    fn make_sockaddr_in(addr: Ipv4Addr) -> libc::sockaddr_in {
        let mut sin: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        sin.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
        sin.sin_family = libc::AF_INET as u8;
        sin.sin_addr.s_addr = u32::from(addr).to_be();
        sin
    }

    /// Sends an IP packet through the tunnel to the host network stack.
    ///
    /// The packet should be a raw IP packet (starting with the IP header).
    /// The 4-byte AF header is automatically prepended.
    ///
    /// # Errors
    ///
    /// Returns an error if the write fails.
    pub fn send_packet(&self, packet: &[u8]) -> io::Result<usize> {
        if packet.is_empty() {
            return Ok(0);
        }

        // Determine the address family from the IP version field.
        let af: u32 = match packet[0] >> 4 {
            4 => libc::AF_INET as u32,
            6 => libc::AF_INET6 as u32,
            v => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unsupported IP version: {}", v),
                ));
            }
        };

        // Build the buffer: 4-byte AF header + IP packet.
        let af_bytes = af.to_ne_bytes();
        let iov = [
            libc::iovec {
                iov_base: af_bytes.as_ptr() as *mut _,
                iov_len: AF_HEADER_SIZE,
            },
            libc::iovec {
                iov_base: packet.as_ptr() as *mut _,
                iov_len: packet.len(),
            },
        ];

        // Use writev for scatter-gather I/O to avoid copying into a
        // contiguous buffer.
        // Safety: writev is safe with valid fd and properly initialized iovecs.
        let n = unsafe { libc::writev(self.fd.as_raw_fd(), iov.as_ptr(), 2) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }

        // Return the number of IP bytes written (subtract AF header).
        let written = (n as usize).saturating_sub(AF_HEADER_SIZE);
        Ok(written)
    }

    /// Receives an IP packet from the tunnel (coming from the host network stack).
    ///
    /// The returned data is a raw IP packet (the 4-byte AF header is stripped).
    /// `buf` must be large enough to hold the maximum expected packet.
    ///
    /// # Errors
    ///
    /// Returns an error if the read fails.
    pub fn recv_packet(&self, buf: &mut [u8]) -> io::Result<usize> {
        // Read into a buffer that includes space for the AF header.
        let mut af_header = [0u8; AF_HEADER_SIZE];
        let iov = [
            libc::iovec {
                iov_base: af_header.as_mut_ptr().cast(),
                iov_len: AF_HEADER_SIZE,
            },
            libc::iovec {
                iov_base: buf.as_mut_ptr().cast(),
                iov_len: buf.len(),
            },
        ];

        // Safety: readv is safe with valid fd and properly initialized iovecs.
        let n = unsafe { libc::readv(self.fd.as_raw_fd(), iov.as_ptr(), 2) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }

        let total = n as usize;
        if total <= AF_HEADER_SIZE {
            // Only got the AF header or less, no IP data.
            return Ok(0);
        }

        Ok(total - AF_HEADER_SIZE)
    }

    /// Sets the socket to non-blocking mode.
    ///
    /// # Errors
    ///
    /// Returns an error if the fcntl call fails.
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        // Safety: fcntl with F_GETFL is safe on a valid fd.
        let flags = unsafe { libc::fcntl(self.fd.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }

        let new_flags = if nonblocking {
            flags | libc::O_NONBLOCK
        } else {
            flags & !libc::O_NONBLOCK
        };

        // Safety: fcntl with F_SETFL is safe on a valid fd.
        let ret = unsafe { libc::fcntl(self.fd.as_raw_fd(), libc::F_SETFL, new_flags) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }
}

impl std::fmt::Debug for DarwinTun {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DarwinTun")
            .field("name", &self.name)
            .field("fd", &self.fd.as_raw_fd())
            .finish()
    }
}

impl crate::nat_backend::HostNetIO for DarwinTun {
    fn send_packet(&self, packet: &[u8]) -> io::Result<usize> {
        self.send_packet(packet)
    }

    fn recv_packet(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.recv_packet(buf)
    }

    fn has_data(&self) -> bool {
        // Use poll(2) with zero timeout for non-blocking readability check.
        let mut pfd = libc::pollfd {
            fd: self.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // Safety: poll with timeout=0 is non-blocking and safe with a valid fd.
        let ret = unsafe { libc::poll(&mut pfd, 1, 0) };
        ret > 0 && (pfd.revents & libc::POLLIN) != 0
    }

    fn name(&self) -> &str {
        self.name()
    }
}

// Safety: DarwinTun holds an OwnedFd which is Send, and the utun socket
// can be safely used from any thread (reads/writes are atomic at the
// kernel level for datagram sockets).
unsafe impl Send for DarwinTun {}
unsafe impl Sync for DarwinTun {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_af_header_size() {
        assert_eq!(AF_HEADER_SIZE, 4);
    }

    #[test]
    fn test_make_sockaddr_in() {
        let addr = Ipv4Addr::new(192, 168, 64, 1);
        let sin = DarwinTun::make_sockaddr_in(addr);

        assert_eq!(sin.sin_family, libc::AF_INET as u8);
        assert_eq!(sin.sin_len, std::mem::size_of::<libc::sockaddr_in>() as u8);
        // 192.168.64.1 in network byte order = 0xC0A84001
        assert_eq!(sin.sin_addr.s_addr, u32::from(addr).to_be());
    }

    // Integration tests that require creating actual utun devices.
    // Run with: cargo test -p arcbox-net darwin::tun -- --ignored
    #[test]
    #[ignore]
    fn test_create_utun() {
        let tun = DarwinTun::new().expect("Failed to create utun device");
        assert!(
            tun.name().starts_with("utun"),
            "Expected utun prefix, got: {}",
            tun.name()
        );
        assert!(tun.as_raw_fd() >= 0);
        println!("Created interface: {}", tun.name());
    }

    #[test]
    #[ignore]
    fn test_configure_utun() {
        let tun = DarwinTun::new().expect("Failed to create utun device");
        let result = tun.configure(
            Ipv4Addr::new(192, 168, 64, 1),
            Ipv4Addr::new(192, 168, 64, 2),
            Ipv4Addr::new(255, 255, 255, 0),
        );
        // May fail without privileges, but should not panic.
        if let Err(e) = &result {
            println!("Configure failed (may need privileges): {}", e);
        } else {
            println!("Configured {} successfully", tun.name());
        }
    }

    #[test]
    #[ignore]
    fn test_nonblocking_mode() {
        let tun = DarwinTun::new().expect("Failed to create utun device");

        tun.set_nonblocking(true)
            .expect("Failed to set nonblocking");

        // Try to read in nonblocking mode — should return WouldBlock.
        let mut buf = [0u8; 1500];
        match tun.recv_packet(&mut buf) {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                // Expected
            }
            Err(e) => panic!("Unexpected error: {}", e),
            Ok(n) => println!("Unexpectedly received {} bytes", n),
        }
    }

    #[test]
    #[ignore]
    fn test_send_recv_loopback() {
        let tun = DarwinTun::new().expect("Failed to create utun device");
        tun.configure(
            Ipv4Addr::new(10, 200, 0, 1),
            Ipv4Addr::new(10, 200, 0, 2),
            Ipv4Addr::new(255, 255, 255, 0),
        )
        .expect("Failed to configure");
        tun.set_nonblocking(true)
            .expect("Failed to set nonblocking");

        // Construct a minimal IPv4 UDP packet destined for the peer.
        // IP header (20 bytes) + UDP header (8 bytes) + payload.
        let mut packet = vec![0u8; 28 + 4]; // IP + UDP + "test"
        // IPv4, IHL=5, total_length=32
        packet[0] = 0x45; // version=4, ihl=5
        packet[2..4].copy_from_slice(&32u16.to_be_bytes()); // total length
        packet[8] = 64; // TTL
        packet[9] = 17; // Protocol: UDP
        packet[12..16].copy_from_slice(&[10, 200, 0, 1]); // src IP
        packet[16..20].copy_from_slice(&[10, 200, 0, 2]); // dst IP
        // UDP: src_port=12345, dst_port=54321, length=12
        packet[20..22].copy_from_slice(&12345u16.to_be_bytes());
        packet[22..24].copy_from_slice(&54321u16.to_be_bytes());
        packet[24..26].copy_from_slice(&12u16.to_be_bytes());
        // Payload
        packet[28..32].copy_from_slice(b"test");

        let written = tun.send_packet(&packet).expect("Failed to send");
        assert_eq!(written, packet.len());
        println!("Sent {} bytes through {}", written, tun.name());
    }
}
