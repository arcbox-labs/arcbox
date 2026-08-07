//! `vm-agent` — in-VM daemon that accepts exec/run sessions over vsock.
//!
//! The agent listens on AF_VSOCK port 52.  For each connection it:
//!
//! 1. Reads an initial `MSG_START` frame carrying a JSON [`StartCommand`].
//! 2. Spawns the requested process (with pipes for non-TTY, with openpty for TTY).
//! 3. Streams `MSG_STDOUT` / `MSG_STDERR` frames back to the host.
//! 4. For interactive sessions, forwards `MSG_STDIN` / `MSG_RESIZE` frames to
//!    the process.
//! 5. Sends a final `MSG_EXIT` frame when the process terminates.
//!
//! Once the exec (52) and file I/O (53) listeners are both bound, the agent
//! dials out to host port 51 (`READY_PORT`) and writes one byte — the
//! host's cold-boot readiness event.
//!
//! The agent also owns its wall clock: once at startup and again on every
//! accepted exec connection (rate-limited to one attempt per second) it
//! re-syncs `CLOCK_REALTIME` from the hypervisor via `ptp_kvm` (see
//! [`ptp`]), so a restored snapshot regains correct time before any
//! workload command runs, without waiting for the host's `MSG_CLOCK_SYNC`
//! RPC (CORE-80).
//!
//! ## Frame format
//!
//! ```text
//! [u8: msg_type][u32 LE: payload_len][payload_len bytes]
//! ```
//!
//! | Type | Direction   | Payload                          |
//! |------|-------------|----------------------------------|
//! | 0x01 | Host→Agent  | JSON `StartCommand`              |
//! | 0x02 | Host→Agent  | raw stdin bytes                  |
//! | 0x03 | Host→Agent  | `[u16 LE width][u16 LE height]`  |
//! | 0x04 | Host→Agent  | empty — stdin EOF                |
//! | 0x05 | Host→Agent  | `[i64 LE secs][u32 LE nanos]` — clock sync |
//! | 0x06 | Host→Agent  | JSON `NetReconfigCommand` — re-address eth0 |
//! | 0x07 | Host→Agent  | `[i32 LE signal]` — signal the workload's process group |
//! | 0x10 | Agent→Host  | raw stdout bytes                 |
//! | 0x11 | Agent→Host  | raw stderr bytes                 |
//! | 0x12 | Agent→Host  | `[i32 LE code][i32 LE signal]` — signal 0 = normal exit. Net-reconfig replies append six `u32 LE` micros (addr/netmask/delrt/addrt ioctls, resolv write, whole handler); legacy agents send only the 4-byte code. Readers key on payload length. |
//!
//! This binary requires Linux — it uses AF_VSOCK, accept4, openpty, and fork,
//! none of which are available on other platforms.  The workspace compiles the
//! crate everywhere, but the implementation is gated on `target_os = "linux"`.

/// Guest-clock self-sync from the hypervisor via the `ptp_kvm` PTP clock.
///
/// `/dev/ptp0` is the kernel's `ptp_kvm` device: reading it issues the SMCCC
/// vendor-hyp `PTP_KVM` call, answered directly by the L1 KVM with the host
/// `CLOCK_REALTIME` — no VMM device, no vsock round-trip, nesting-safe.
/// `PTP_SYS_OFFSET` brackets each PHC read between two guest system-clock
/// reads, so the tightest bracket bounds the measurement error.
///
/// Struct layouts and the ioctl encoding mirror `<linux/ptp_clock.h>`. The
/// offset math is portable and unit-tested on every host; the ioctl half is
/// Linux-only.
#[cfg(any(target_os = "linux", test))]
mod ptp {
    /// `struct ptp_clock_time` (`<linux/ptp_clock.h>`).
    #[derive(Debug, Clone, Copy)]
    #[repr(C)]
    pub struct PtpClockTime {
        pub sec: i64,
        pub nsec: u32,
        #[allow(dead_code, reason = "kernel ABI reserved padding, never read")]
        pub reserved: u32,
    }

    /// `PTP_MAX_SAMPLES` (`<linux/ptp_clock.h>`) — the kernel rejects
    /// `n_samples` above it with `EINVAL`.
    pub const PTP_MAX_SAMPLES: usize = 25;

    /// `struct ptp_sys_offset` (`<linux/ptp_clock.h>`).
    #[repr(C)]
    pub struct PtpSysOffset {
        pub n_samples: u32,
        #[allow(dead_code, reason = "kernel ABI reserved padding, never read")]
        pub rsv: [u32; 3],
        pub ts: [PtpClockTime; 2 * PTP_MAX_SAMPLES + 1],
    }

    /// ABI pin: `PTP_SYS_OFFSET` encodes the struct size, so a layout drift
    /// would silently turn it into a different (unknown) ioctl number.
    const _: () = assert!(std::mem::size_of::<PtpSysOffset>() == 832);

    /// `PTP_SYS_OFFSET` = `_IOW('=', 5, struct ptp_sys_offset)` in the
    /// asm-generic ioctl encoding (which arm64 uses):
    /// `dir(write = 1) << 30 | size << 16 | type << 8 | nr`. The kernel
    /// copies the filled struct back despite the `_IOW` label — a historical
    /// quirk of the PTP ABI.
    pub const PTP_SYS_OFFSET: u32 =
        (1 << 30) | ((std::mem::size_of::<PtpSysOffset>() as u32) << 16) | ((b'=' as u32) << 8) | 5;

    /// Samples per `PTP_SYS_OFFSET` call: enough that one preempted bracket
    /// never decides the offset, while the ioctl stays microseconds-cheap.
    #[cfg(target_os = "linux")]
    pub const N_SAMPLES: u32 = 5;

    /// Step the clock only when the measured skew exceeds this (100 ms).
    /// Restore skew is seconds to days; anything smaller is normal drift the
    /// sync must not fight.
    pub const STEP_THRESHOLD_NS: i128 = 100_000_000;

    const NANOS_PER_SEC: i128 = 1_000_000_000;

    fn ns(t: PtpClockTime) -> i128 {
        i128::from(t.sec) * NANOS_PER_SEC + i128::from(t.nsec)
    }

    /// Whether a measured guest→host offset warrants stepping the clock.
    pub fn should_step(offset_ns: i128) -> bool {
        offset_ns.abs() > STEP_THRESHOLD_NS
    }

    /// The offset to add to the guest `CLOCK_REALTIME` to land on the host
    /// clock, from a filled `PTP_SYS_OFFSET` sample array.
    ///
    /// The kernel fills `2 * n_samples + 1` entries — `sys, phc, sys, phc,
    /// …, sys` — bracketing every PHC read (under `ptp_kvm`: the host
    /// `CLOCK_REALTIME`) between two guest system-clock reads, adjacent
    /// samples sharing a boundary. The sample with the tightest bracket
    /// carries the least scheduling noise; its offset is measured against
    /// the bracket midpoint. Brackets that run backwards (the guest clock
    /// was stepped mid-call) are discarded. `None` when no usable sample
    /// exists.
    pub fn realtime_offset_ns(ts: &[PtpClockTime], n_samples: u32) -> Option<i128> {
        let n = n_samples as usize;
        let filled = ts.get(..n.checked_mul(2)?.checked_add(1)?)?;
        (0..n)
            .map(|i| {
                let before = ns(filled[2 * i]);
                let phc = ns(filled[2 * i + 1]);
                let after = ns(filled[2 * i + 2]);
                (after - before, phc - i128::midpoint(before, after))
            })
            .filter(|&(bracket, _)| bracket >= 0)
            .min_by_key(|&(bracket, _)| bracket)
            .map(|(_, offset)| offset)
    }

    /// Outcome of one successful `/dev/ptp0` sample.
    #[cfg(target_os = "linux")]
    pub enum SyncOutcome {
        /// Skew exceeded the threshold; `CLOCK_REALTIME` was stepped.
        Stepped { offset_ns: i128 },
        /// Skew within the threshold; the clock was left alone.
        InSync { offset_ns: i128 },
    }

    /// One self-sync: sample `/dev/ptp0` and step `CLOCK_REALTIME` when the
    /// skew exceeds [`STEP_THRESHOLD_NS`].
    ///
    /// `ptp_kvm` is the microVM kernel's only PTP clock, so it is always
    /// index 0; a missing `/dev/ptp0` (kernel without ptp_kvm) is an error
    /// the caller logs and ignores — such a guest keeps exactly the
    /// host-driven `MSG_CLOCK_SYNC` semantics it has today.
    #[cfg(target_os = "linux")]
    pub fn sync_clock_from_ptp() -> Result<SyncOutcome, String> {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

        // SAFETY: plain open(2) on a static C string; result checked below.
        let raw = unsafe { libc::open(c"/dev/ptp0".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if raw < 0 {
            return Err(format!(
                "open /dev/ptp0: {}",
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: raw is a freshly opened, owned fd.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };

        // SAFETY: PtpSysOffset is POD; n_samples set below, rest zeroed.
        let mut req: PtpSysOffset = unsafe { std::mem::zeroed() };
        req.n_samples = N_SAMPLES;
        #[allow(
            clippy::cast_possible_wrap,
            reason = "the PTP_SYS_OFFSET request number fits musl's c_int ioctl request type"
        )]
        let request = PTP_SYS_OFFSET as libc::Ioctl;
        // SAFETY: fd is a valid chardev fd; req is a properly sized, live
        // ptp_sys_offset the kernel reads, fills, and copies back.
        if unsafe { libc::ioctl(fd.as_raw_fd(), request, &raw mut req) } < 0 {
            return Err(format!(
                "PTP_SYS_OFFSET: {}",
                std::io::Error::last_os_error()
            ));
        }

        let offset_ns = realtime_offset_ns(&req.ts, req.n_samples)
            .ok_or_else(|| "PTP_SYS_OFFSET returned no usable sample".to_owned())?;
        if !should_step(offset_ns) {
            return Ok(SyncOutcome::InSync { offset_ns });
        }

        // Step relative to the CURRENT clock: both clocks tick at the same
        // rate, so the microseconds elapsed since the ioctl cancel out.
        let mut now = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: valid out-pointer to a live timespec.
        if unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &raw mut now) } != 0 {
            return Err(format!(
                "clock_gettime: {}",
                std::io::Error::last_os_error()
            ));
        }
        let target_ns =
            i128::from(now.tv_sec) * NANOS_PER_SEC + i128::from(now.tv_nsec) + offset_ns;
        let ts = libc::timespec {
            // Inferred field type: naming libc::time_t is deprecated on musl.
            tv_sec: target_ns
                .div_euclid(NANOS_PER_SEC)
                .try_into()
                .map_err(|_| format!("target wall time out of range: {target_ns} ns"))?,
            // rem_euclid of a positive modulus is in [0, 1e9): lossless.
            tv_nsec: target_ns.rem_euclid(NANOS_PER_SEC) as libc::c_long,
        };
        // SAFETY: clock_settime requires CAP_SYS_TIME; vm-agent is guest
        // root (the same contract MSG_CLOCK_SYNC's handler relies on). A
        // negative target is rejected by the kernel with EINVAL.
        if unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &raw const ts) } != 0 {
            return Err(format!(
                "clock_settime: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(SyncOutcome::Stepped { offset_ns })
    }

    /// Accept-path sync: at most one `/dev/ptp0` attempt per second.
    ///
    /// The first post-resume interaction with a restored guest is always an
    /// accepted exec connection, so running this before the handler spawns
    /// guarantees correct wall time before any workload command. The slot
    /// is claimed by CAS before syncing so concurrent accepts never pile
    /// onto the device — losers of the race skip. The timestamp is
    /// `CLOCK_MONOTONIC`, which Firecracker restores across
    /// snapshot/resume, so post-restore deltas stay sane.
    ///
    /// Within-threshold outcomes are deliberately NOT logged: /dev/console
    /// is the FC serial device (byte-by-byte nested MMIO exits), and steady
    /// exec traffic would otherwise pay for one line per second.
    #[cfg(target_os = "linux")]
    pub fn sync_rate_limited() {
        use std::sync::atomic::{AtomicU64, Ordering};

        /// Monotonic milliseconds of the last sync attempt. Zero reads as
        /// "attempted at boot", which is accurate: `run()` performs an
        /// unconditional startup sync.
        static LAST_ATTEMPT_MS: AtomicU64 = AtomicU64::new(0);

        let mut now = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: valid out-pointer; CLOCK_MONOTONIC cannot fail on Linux.
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &raw mut now) };
        let now_ms = u64::try_from(now.tv_sec).unwrap_or(0) * 1000
            + u64::try_from(now.tv_nsec).unwrap_or(0) / 1_000_000;

        let last = LAST_ATTEMPT_MS.load(Ordering::Relaxed);
        if now_ms.saturating_sub(last) < 1000
            || LAST_ATTEMPT_MS
                .compare_exchange(last, now_ms, Ordering::Relaxed, Ordering::Relaxed)
                .is_err()
        {
            return;
        }

        match sync_clock_from_ptp() {
            Ok(SyncOutcome::Stepped { offset_ns }) => eprintln!(
                "vm-agent: ptp clock sync: stepped CLOCK_REALTIME by {} ms",
                offset_ns / 1_000_000
            ),
            Ok(SyncOutcome::InSync { .. }) => {}
            Err(e) => eprintln!("vm-agent: ptp clock sync: {e}"),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn t(sec: i64, nsec: u32) -> PtpClockTime {
            PtpClockTime {
                sec,
                nsec,
                reserved: 0,
            }
        }

        #[test]
        fn tightest_bracket_wins() {
            // Sample 0: 10 ms bracket, says +5 s. Sample 1: 1.5 µs bracket,
            // says ~+2 s — the tight bracket must decide.
            let ts = [
                t(100, 0),
                t(105, 5_000_000),
                t(100, 10_000_000),
                t(102, 10_000_500),
                t(100, 10_001_500),
            ];
            assert_eq!(realtime_offset_ns(&ts, 2), Some(1_999_999_750));
        }

        #[test]
        fn guest_ahead_of_host_yields_a_negative_offset() {
            // Guest at 200 s, host (PHC) at 100 s, 2 ns bracket.
            let ts = [t(200, 0), t(100, 0), t(200, 2)];
            assert_eq!(realtime_offset_ns(&ts, 1), Some(-100_000_000_001));
        }

        #[test]
        fn backwards_bracket_is_discarded() {
            // Sample 0's bracket runs backwards (clock stepped mid-call) and
            // would win a naive min; sample 1 must be picked instead.
            let ts = [t(500, 0), t(100, 0), t(10, 0), t(60, 0), t(10, 1000)];
            assert_eq!(realtime_offset_ns(&ts, 2), Some(49_999_999_500));
        }

        #[test]
        fn no_usable_sample_yields_none() {
            // All brackets backwards.
            assert_eq!(
                realtime_offset_ns(&[t(500, 0), t(100, 0), t(10, 0)], 1),
                None
            );
            // Kernel filled fewer entries than 2 * n + 1.
            assert_eq!(realtime_offset_ns(&[t(1, 0); 5], 3), None);
            // Zero samples.
            assert_eq!(realtime_offset_ns(&[t(1, 0); 1], 0), None);
            // Hostile sample count never indexes out of bounds.
            assert_eq!(realtime_offset_ns(&[t(1, 0); 3], u32::MAX), None);
        }

        #[test]
        fn extreme_timestamps_do_not_overflow() {
            let edge = t(i64::MAX, 999_999_999);
            assert_eq!(realtime_offset_ns(&[edge, edge, edge], 1), Some(0));
        }

        #[test]
        fn threshold_is_exclusive_and_sign_agnostic() {
            assert!(!should_step(0));
            assert!(!should_step(STEP_THRESHOLD_NS));
            assert!(!should_step(-STEP_THRESHOLD_NS));
            assert!(should_step(STEP_THRESHOLD_NS + 1));
            assert!(should_step(-(STEP_THRESHOLD_NS + 1)));
        }

        #[test]
        fn offset_reads_through_the_full_abi_struct() {
            // Mirrors the real call path: the kernel-filled struct's ts
            // array and echoed n_samples feed the offset derivation.
            let mut req = PtpSysOffset {
                n_samples: 1,
                rsv: [0; 3],
                ts: [t(0, 0); 2 * PTP_MAX_SAMPLES + 1],
            };
            req.ts[0] = t(10, 0);
            req.ts[1] = t(20, 0);
            req.ts[2] = t(10, 2);
            assert_eq!(
                realtime_offset_ns(&req.ts, req.n_samples),
                Some(9_999_999_999)
            );
        }

        #[test]
        fn ioctl_request_matches_the_kernel_abi() {
            // _IOW('=', 5, struct ptp_sys_offset) with sizeof == 832 on
            // asm-generic platforms (arm64 among them).
            assert_eq!(PTP_SYS_OFFSET, 0x4340_3d05);
        }
    }
}

// =============================================================================
// Linux implementation
// =============================================================================

#[cfg(target_os = "linux")]
mod agent {
    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::os::unix::io::RawFd;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Condvar, Mutex, OnceLock, mpsc};
    use std::thread;

    use serde::Deserialize;

    // -------------------------------------------------------------------------
    // Protocol constants
    // -------------------------------------------------------------------------

    pub const AGENT_PORT: u32 = 52;

    // Exec channel (vsock:52) frame types.
    const MSG_START: u8 = 0x01;
    const MSG_STDIN: u8 = 0x02;
    const MSG_RESIZE: u8 = 0x03;
    const MSG_EOF: u8 = 0x04;
    const MSG_CLOCK_SYNC: u8 = 0x05;
    const MSG_NET_RECONFIG: u8 = 0x06;
    const MSG_SIGNAL: u8 = 0x07;
    const MSG_STDOUT: u8 = 0x10;
    const MSG_STDERR: u8 = 0x11;
    const MSG_EXIT: u8 = 0x12;

    // File I/O channel (vsock:53) — imported from the shared proto module.
    use arcbox_vm::boot_proto::{KernelIpParam, NetReconfigCommand};
    use arcbox_vm::file_io::proto::{
        FILE_ACK, FILE_DATA, FILE_DONE, FILE_ERR, FILE_PORT, FILE_READ_REQ, FILE_WRITE_REQ,
        MAX_FILE_SIZE,
    };
    // Readiness dial-out port — shared with the host-side boot gate.
    use arcbox_vm::vsock::READY_PORT;

    const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;

    /// Maximum number of concurrently active connection-handling threads.
    /// Prevents memory exhaustion during exec bursts (e.g. health checks).
    const MAX_ACTIVE_CONNECTIONS: usize = 64;

    /// Stack size for connection-handling threads (1 MB instead of the default 8 MB).
    const THREAD_STACK_SIZE: usize = 1 << 20;

    // -------------------------------------------------------------------------
    // Protocol types
    // -------------------------------------------------------------------------

    #[derive(Debug, Deserialize)]
    struct StartCommand {
        cmd: Vec<String>,
        #[serde(default)]
        env: HashMap<String, String>,
        #[serde(default)]
        working_dir: String,
        #[serde(default)]
        user: String,
        #[serde(default)]
        tty: bool,
        #[serde(default = "default_tty_width")]
        tty_width: u16,
        #[serde(default = "default_tty_height")]
        tty_height: u16,
        #[serde(default)]
        timeout_seconds: u32,
    }

    fn default_tty_width() -> u16 {
        80
    }
    fn default_tty_height() -> u16 {
        24
    }

    // -------------------------------------------------------------------------
    // Framed I/O over a raw socket fd
    // -------------------------------------------------------------------------

    struct VsockStream {
        fd: RawFd,
    }

    impl VsockStream {
        /// # Safety
        /// `fd` must be a valid, open, connected socket file descriptor.
        unsafe fn from_raw_fd(fd: RawFd) -> Self {
            Self { fd }
        }
    }

    impl Read for VsockStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            // SAFETY: buf is a valid mutable slice; fd is a valid socket.
            let n =
                unsafe { libc::read(self.fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
            if n < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        }
    }

    impl Write for VsockStream {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            // SAFETY: buf is a valid slice; fd is a valid socket.
            let n = unsafe { libc::write(self.fd, buf.as_ptr().cast::<libc::c_void>(), buf.len()) };
            if n < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Drop for VsockStream {
        fn drop(&mut self) {
            // SAFETY: fd is valid and owned by this struct.
            unsafe { libc::close(self.fd) };
        }
    }

    // -------------------------------------------------------------------------
    // Frame helpers
    // -------------------------------------------------------------------------

    fn read_frame(r: &mut impl Read) -> std::io::Result<(u8, Vec<u8>)> {
        let mut type_buf = [0u8; 1];
        r.read_exact(&mut type_buf)?;
        let mut len_buf = [0u8; 4];
        r.read_exact(&mut len_buf)?;
        let len = u32::from_le_bytes(len_buf) as usize;
        if len > MAX_FRAME_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("frame too large: {len} bytes (max {MAX_FRAME_SIZE})"),
            ));
        }
        let mut payload = vec![0u8; len];
        if len > 0 {
            r.read_exact(&mut payload)?;
        }
        Ok((type_buf[0], payload))
    }

    /// Write all bytes in a single call to avoid interleaving across threads.
    fn write_frame(w: &mut impl Write, msg_type: u8, payload: &[u8]) -> std::io::Result<()> {
        let mut buf = Vec::with_capacity(5 + payload.len());
        buf.push(msg_type);
        buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        buf.extend_from_slice(payload);
        w.write_all(&buf)
    }

    // -------------------------------------------------------------------------
    // Per-connection handler
    // -------------------------------------------------------------------------

    fn handle_connection(conn_fd: RawFd) {
        // SAFETY: conn_fd is a freshly accepted socket fd.
        let mut conn = unsafe { VsockStream::from_raw_fd(conn_fd) };

        let (msg_type, payload) = match read_frame(&mut conn) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("agent: read first frame: {e}");
                return;
            }
        };

        match msg_type {
            MSG_CLOCK_SYNC => handle_clock_sync(conn, &payload),
            MSG_NET_RECONFIG => handle_net_reconfig(conn, &payload),
            MSG_START => {
                let start: StartCommand = match serde_json::from_slice(&payload) {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("agent: parse StartCommand: {e}");
                        return;
                    }
                };
                if start.tty {
                    handle_tty(conn, start);
                } else {
                    handle_piped(conn, start);
                }
            }
            other => {
                eprintln!("agent: unexpected frame type 0x{other:02x} on exec port");
            }
        }
    }

    fn handle_clock_sync(mut conn: VsockStream, payload: &[u8]) {
        if payload.len() < 12 {
            eprintln!(
                "agent: MSG_CLOCK_SYNC: payload too short ({} bytes)",
                payload.len()
            );
            let _ = write_frame(&mut conn, MSG_EXIT, &(-1i32).to_le_bytes());
            return;
        }
        let secs = i64::from_le_bytes(payload[..8].try_into().unwrap());
        let nanos = u32::from_le_bytes(payload[8..12].try_into().unwrap());

        // SAFETY: clock_settime requires CAP_SYS_TIME; vm-agent runs as root inside guest.
        let ret = unsafe {
            let ts = libc::timespec {
                tv_sec: secs,
                tv_nsec: libc::c_long::from(nanos),
            };
            libc::clock_settime(libc::CLOCK_REALTIME, &raw const ts)
        };
        if ret != 0 {
            eprintln!(
                "agent: clock_settime failed: {}",
                std::io::Error::last_os_error()
            );
            let _ = write_frame(&mut conn, MSG_EXIT, &(-1i32).to_le_bytes());
            return;
        }
        let _ = write_frame(&mut conn, MSG_EXIT, &0i32.to_le_bytes());
    }

    fn handle_net_reconfig(mut conn: VsockStream, payload: &[u8]) {
        let cmd: NetReconfigCommand = match serde_json::from_slice(payload) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("agent: parse NetReconfigCommand: {e}");
                let _ = write_frame(&mut conn, MSG_EXIT, &(-1i32).to_le_bytes());
                return;
            }
        };

        let handler_started = std::time::Instant::now();
        let steps = match net_reconfig::apply(&cmd) {
            Ok(steps) => steps,
            Err(e) => {
                eprintln!("agent: net reconfig failed: {e}");
                let _ = write_frame(&mut conn, MSG_EXIT, &(-1i32).to_le_bytes());
                return;
            }
        };

        // Repoint DNS at the new gateway, mirroring the boot-time setup_dns.
        let resolv_started = std::time::Instant::now();
        let content = format!("nameserver {}\n", cmd.gateway);
        if let Err(e) = std::fs::write("/etc/resolv.conf", &content) {
            eprintln!("agent: net reconfig: failed to write /etc/resolv.conf: {e}");
        }
        let clamp = |d: std::time::Duration| u32::try_from(d.as_micros()).unwrap_or(u32::MAX);
        let resolv_us = clamp(resolv_started.elapsed());
        let handler_us = clamp(handler_started.elapsed());

        // Exit payload: [i32 code][i32 signal] plus six u32 micros (four
        // per-ioctl, resolv write, whole handler) so the host can attribute
        // reconfig latency. Hosts read the first 4 bytes only, so the
        // extension is backward compatible.
        let mut payload = [0u8; 32];
        let timings = steps.iter().copied().chain([resolv_us, handler_us]);
        for (slot, ms) in payload[8..].chunks_exact_mut(4).zip(timings) {
            slot.copy_from_slice(&ms.to_le_bytes());
        }
        let _ = write_frame(&mut conn, MSG_EXIT, &payload);

        // Console logging goes AFTER the response: /dev/console is the FC
        // serial device, written byte-by-byte through nested MMIO exits —
        // putting it before the reply held the restore RPC hostage to it.
        eprintln!(
            "agent: reconfigured eth0 to {}/{} via {}",
            cmd.ip, cmd.netmask, cmd.gateway
        );
    }

    /// eth0 re-addressing via raw `ioctl(2)`, self-contained so it works on
    /// any sandbox rootfs (no dependence on busybox `ip`/`route` applets).
    mod net_reconfig {
        use arcbox_vm::boot_proto::NetReconfigCommand;
        use std::net::Ipv4Addr;
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

        const IFNAME: &[u8] = b"eth0";

        fn sockaddr_in(ip: Ipv4Addr) -> libc::sockaddr {
            let sin = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: 0,
                sin_addr: libc::in_addr {
                    s_addr: u32::from(ip).to_be(),
                },
                sin_zero: [0; 8],
            };
            // SAFETY: sockaddr_in and sockaddr are layout-compatible for the
            // kernel ABI; sockaddr is larger or equal, remainder zeroed below.
            let mut sa: libc::sockaddr = unsafe { std::mem::zeroed() };
            // SAFETY: copying sizeof(sockaddr_in) <= sizeof(sockaddr) bytes.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    (&raw const sin).cast::<u8>(),
                    (&raw mut sa).cast::<u8>(),
                    std::mem::size_of::<libc::sockaddr_in>(),
                );
            }
            sa
        }

        fn ifreq_with_addr(addr: libc::sockaddr) -> libc::ifreq {
            // SAFETY: ifreq is POD; fully initialized below.
            let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
            for (dst, src) in req.ifr_name.iter_mut().zip(IFNAME) {
                *dst = *src as libc::c_char;
            }
            req.ifr_ifru.ifru_addr = addr;
            req
        }

        fn ioctl(
            fd: &OwnedFd,
            request: libc::c_ulong,
            arg: *mut libc::c_void,
        ) -> Result<(), std::io::Error> {
            #[allow(
                clippy::cast_possible_truncation,
                clippy::cast_possible_wrap,
                reason = "SIOC* request numbers fit musl's c_int ioctl request type"
            )]
            let request = request as libc::Ioctl;
            // SAFETY: fd is a valid socket; arg points at a properly sized,
            // initialized kernel struct owned by the caller.
            if unsafe { libc::ioctl(fd.as_raw_fd(), request, arg) } < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        }

        /// Set eth0's address + netmask and replace the default route.
        ///
        /// Returns per-step micros `[addr, netmask, delrt, addrt]` so the
        /// host can attribute reconfig latency (CORE-75 diagnostics).
        pub fn apply(cmd: &NetReconfigCommand) -> Result<[u32; 4], String> {
            let mut steps = [0u32; 4];
            let mut mark = std::time::Instant::now();
            // Microseconds: the ioctls land well under a millisecond each,
            // and u32 micros still spans ~71 minutes.
            let mut lap = |slot: &mut u32| {
                *slot = u32::try_from(mark.elapsed().as_micros()).unwrap_or(u32::MAX);
                mark = std::time::Instant::now();
            };

            // SAFETY: plain socket(2) call; result checked below.
            let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
            if raw < 0 {
                return Err(format!("socket: {}", std::io::Error::last_os_error()));
            }
            // SAFETY: raw is a freshly opened, owned socket fd.
            let fd = unsafe { OwnedFd::from_raw_fd(raw) };

            let mut req = ifreq_with_addr(sockaddr_in(cmd.ip));
            ioctl(&fd, libc::SIOCSIFADDR, (&raw mut req).cast())
                .map_err(|e| format!("SIOCSIFADDR: {e}"))?;
            lap(&mut steps[0]);

            let mut req = ifreq_with_addr(sockaddr_in(cmd.netmask));
            ioctl(&fd, libc::SIOCSIFNETMASK, (&raw mut req).cast())
                .map_err(|e| format!("SIOCSIFNETMASK: {e}"))?;
            lap(&mut steps[1]);

            // The kernel flushes routes through the interface when its
            // primary address changes, but don't rely on that implicit
            // behavior: drop any surviving default route first so the add
            // below never races an EEXIST. ESRCH just means none survived.
            // SAFETY: rtentry is POD; fields set below, rest zeroed.
            let mut stale: libc::rtentry = unsafe { std::mem::zeroed() };
            stale.rt_dst = sockaddr_in(Ipv4Addr::UNSPECIFIED);
            stale.rt_genmask = sockaddr_in(Ipv4Addr::UNSPECIFIED);
            stale.rt_flags = libc::RTF_UP;
            if let Err(e) = ioctl(&fd, libc::SIOCDELRT, (&raw mut stale).cast()) {
                if e.raw_os_error() != Some(libc::ESRCH) {
                    eprintln!("agent: net reconfig: SIOCDELRT stale default: {e}");
                }
            }
            lap(&mut steps[2]);

            // Add the default route via the new gateway.
            // SAFETY: rtentry is POD; fields set below, rest zeroed.
            let mut route: libc::rtentry = unsafe { std::mem::zeroed() };
            route.rt_dst = sockaddr_in(Ipv4Addr::UNSPECIFIED);
            route.rt_genmask = sockaddr_in(Ipv4Addr::UNSPECIFIED);
            route.rt_gateway = sockaddr_in(cmd.gateway);
            route.rt_flags = libc::RTF_UP | libc::RTF_GATEWAY;
            ioctl(&fd, libc::SIOCADDRT, (&raw mut route).cast())
                .map_err(|e| format!("SIOCADDRT default via {}: {e}", cmd.gateway))?;
            lap(&mut steps[3]);

            Ok(steps)
        }
    }

    // -------------------------------------------------------------------------
    // File I/O handler (vsock:53)
    //
    // Trust model: the host is fully trusted — it owns and controls the VM.
    // The guest agent intentionally allows arbitrary file paths because only
    // the host can initiate vsock connections.
    // -------------------------------------------------------------------------

    fn handle_file_connection(conn_fd: RawFd) {
        // SAFETY: conn_fd is a freshly accepted socket fd.
        let mut conn = unsafe { VsockStream::from_raw_fd(conn_fd) };

        let (msg_type, payload) = match read_frame(&mut conn) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("agent: file: read first frame: {e}");
                return;
            }
        };

        match msg_type {
            FILE_WRITE_REQ => handle_file_write(conn, &payload),
            FILE_READ_REQ => handle_file_read(conn, &payload),
            other => eprintln!("agent: file: unexpected frame type 0x{other:02x}"),
        }
    }

    #[derive(serde::Deserialize)]
    struct WriteReq {
        path: String,
        #[serde(default)]
        mode: u32,
    }

    #[derive(serde::Deserialize)]
    struct ReadReq {
        path: String,
    }

    fn handle_file_write(mut conn: VsockStream, header_payload: &[u8]) {
        let req: WriteReq = match serde_json::from_slice(header_payload) {
            Ok(r) => r,
            Err(e) => {
                let _ = write_frame(
                    &mut conn,
                    FILE_ERR,
                    format!("parse WriteReq: {e}").as_bytes(),
                );
                return;
            }
        };
        let mode = if req.mode == 0 { 0o644 } else { req.mode };

        // Collect FILE_DATA chunks until FILE_DONE.
        let mut data: Vec<u8> = Vec::new();
        loop {
            match read_frame(&mut conn) {
                Ok((FILE_DATA, chunk)) => {
                    data.extend_from_slice(&chunk);
                    if data.len() > MAX_FILE_SIZE {
                        let _ = write_frame(
                            &mut conn,
                            FILE_ERR,
                            format!("file too large (>{} bytes)", MAX_FILE_SIZE).as_bytes(),
                        );
                        return;
                    }
                }
                Ok((FILE_DONE, _)) => break,
                Ok((other, _)) => {
                    let _ = write_frame(
                        &mut conn,
                        FILE_ERR,
                        format!("expected FILE_DATA/DONE, got 0x{other:02x}").as_bytes(),
                    );
                    return;
                }
                Err(e) => {
                    let _ = write_frame(&mut conn, FILE_ERR, format!("read data: {e}").as_bytes());
                    return;
                }
            }
        }

        let path = std::path::Path::new(&req.path);
        if let Some(parent) = path.parent()
            && let Err(e) = std::fs::create_dir_all(parent)
        {
            let _ = write_frame(&mut conn, FILE_ERR, format!("create dirs: {e}").as_bytes());
            return;
        }

        use std::os::unix::fs::OpenOptionsExt;
        let result = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(path)
            .and_then(|mut f| {
                use std::io::Write;
                f.write_all(&data)
            });

        match result {
            Ok(()) => {
                let _ = write_frame(&mut conn, FILE_ACK, &[]);
            }
            Err(e) => {
                let _ = write_frame(&mut conn, FILE_ERR, format!("write file: {e}").as_bytes());
            }
        }
    }

    fn handle_file_read(mut conn: VsockStream, header_payload: &[u8]) {
        let req: ReadReq = match serde_json::from_slice(header_payload) {
            Ok(r) => r,
            Err(e) => {
                let _ = write_frame(
                    &mut conn,
                    FILE_ERR,
                    format!("parse ReadReq: {e}").as_bytes(),
                );
                return;
            }
        };

        let data = match std::fs::read(&req.path) {
            Ok(d) => d,
            Err(e) => {
                let _ = write_frame(&mut conn, FILE_ERR, format!("read file: {e}").as_bytes());
                return;
            }
        };

        for chunk in data.chunks(MAX_FRAME_SIZE) {
            if write_frame(&mut conn, FILE_DATA, chunk).is_err() {
                return;
            }
        }
        let _ = write_frame(&mut conn, FILE_DONE, &[]);
    }

    // -------------------------------------------------------------------------
    // Non-interactive execution (piped stdio)
    // -------------------------------------------------------------------------

    /// Resolve `StartCommand.user` against the rootfs passwd/group files.
    fn resolve_start_user(
        user: &str,
    ) -> Result<Option<arcbox_vm::user_spec::ResolvedUser>, String> {
        let passwd = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
        let group = std::fs::read_to_string("/etc/group").unwrap_or_default();
        arcbox_vm::user_spec::resolve_user(user, &passwd, &group)
    }

    /// Report a start failure to the host as a stderr chunk plus an exit
    /// frame, so clients see the reason instead of a bare stream EOF.
    fn report_start_failure(conn: &mut VsockStream, exit_code: i32, message: &str) {
        let _ = write_frame(conn, MSG_STDERR, message.as_bytes());
        let _ = write_frame(conn, MSG_EXIT, &exit_code.to_le_bytes());
    }

    // -------------------------------------------------------------------------
    // Child reaping (this agent is guest PID 1)
    // -------------------------------------------------------------------------

    /// Registry of workload children awaiting their exit status, keyed by pid.
    ///
    /// `vm-agent` runs as init, so every process in the guest is (eventually)
    /// its child, including grandchildren reparented by double-forking daemons.
    /// A single reaper thread owns *all* `waitpid` calls: workloads that exit
    /// have their status routed back to the waiting handler via the registered
    /// sender; reparented orphans are simply reaped and dropped. Handlers must
    /// therefore never call `waitpid`/`Child::wait` themselves — that would race
    /// the reaper and either lose an exit code or double-reap.
    /// How a reaped workload terminated: a normal exit code or a fatal signal.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum WaitOutcome {
        Exited(i32),
        Signaled(i32),
    }

    /// Encode the `MSG_EXIT` payload: `[i32 LE code][i32 LE signal]`.
    ///
    /// The code slot keeps the shell convention (`128 + signal` for signal
    /// deaths) so a reader that parses only the first 4 bytes sees the same
    /// value the pre-signal protocol carried.
    fn exit_payload(outcome: WaitOutcome) -> [u8; 8] {
        let (code, signal) = match outcome {
            WaitOutcome::Exited(code) => (code, 0),
            WaitOutcome::Signaled(signal) => (128 + signal, signal),
        };
        let mut buf = [0u8; 8];
        buf[..4].copy_from_slice(&code.to_le_bytes());
        buf[4..].copy_from_slice(&signal.to_le_bytes());
        buf
    }

    fn reap_registry() -> &'static Mutex<HashMap<libc::pid_t, mpsc::Sender<WaitOutcome>>> {
        static REGISTRY: OnceLock<Mutex<HashMap<libc::pid_t, mpsc::Sender<WaitOutcome>>>> =
            OnceLock::new();
        REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
    }

    /// Wakes the reaper out of its no-children park when a spawn registers a
    /// child (paired with the [`reap_registry`] mutex).
    fn reap_wakeup() -> &'static Condvar {
        static WAKEUP: OnceLock<Condvar> = OnceLock::new();
        WAKEUP.get_or_init(Condvar::new)
    }

    /// Register a spawned child for reaping AND wake the parked reaper.
    ///
    /// The single entry point for both spawn paths: an insert without the
    /// wakeup would strand that child's exit for up to the reaper's park
    /// timeout, so the two steps must never be separated.
    fn register_child(
        registry: &mut HashMap<libc::pid_t, mpsc::Sender<WaitOutcome>>,
        pid: libc::pid_t,
        exit_tx: mpsc::Sender<WaitOutcome>,
    ) {
        registry.insert(pid, exit_tx);
        reap_wakeup().notify_all();
    }

    /// Narrow a `std::process::Child::id()` (u32) to a `pid_t`. Linux pids are
    /// bounded well below `i32::MAX`, so this never wraps.
    #[allow(clippy::cast_possible_wrap, reason = "pids fit in pid_t")]
    fn as_pid(id: u32) -> libc::pid_t {
        id as libc::pid_t
    }

    /// Map a raw `wait` status to a termination outcome.
    fn wait_status_to_outcome(status: libc::c_int) -> Option<WaitOutcome> {
        if libc::WIFEXITED(status) {
            Some(WaitOutcome::Exited(libc::WEXITSTATUS(status)))
        } else if libc::WIFSIGNALED(status) {
            Some(WaitOutcome::Signaled(libc::WTERMSIG(status)))
        } else {
            None // stopped / continued — not a termination
        }
    }

    /// Deliver a host-requested signal to the workload's process group.
    ///
    /// Both exec paths `setsid` the child, so its pgid equals its pid; the
    /// group kill reaches descendants, matching `kill_if_alive` semantics.
    fn deliver_signal(pid: libc::pid_t, payload: &[u8]) {
        let Some(bytes) = payload.get(..4) else {
            eprintln!(
                "agent: MSG_SIGNAL payload too short ({} bytes)",
                payload.len()
            );
            return;
        };
        let signal = i32::from_le_bytes(bytes.try_into().unwrap());
        if !(1..=64).contains(&signal) {
            eprintln!("agent: MSG_SIGNAL rejected out-of-range signal {signal}");
            return;
        }
        // SAFETY: signal 0 on the leader only probes liveness; the group kill
        // targets the setsid'd process group led by `pid`.
        unsafe {
            if libc::kill(pid, 0) == 0 {
                let _ = libc::kill(-pid, signal);
            }
        }
    }

    /// Start the single reaper thread. Reaps every child; routes the exit code
    /// of registered workloads to their handler and discards orphan statuses.
    fn start_reaper() {
        thread::spawn(|| {
            loop {
                let mut status: libc::c_int = 0;
                // SAFETY: waitpid with a valid status pointer; -1 waits on any child.
                let pid = unsafe { libc::waitpid(-1, &raw mut status, 0) };
                if pid <= 0 {
                    // ECHILD (no children) or EINTR. Park until a spawn
                    // registers a child instead of polling: the old 50 ms
                    // backoff put a flat ~50 ms floor under every short
                    // execution whose child spawned and exited inside one
                    // sleep. ECHILD means zero children of any kind — an
                    // orphan can only be reparented to us while we still have
                    // children, and then waitpid blocks rather than failing —
                    // so a registry insert is the only way a child appears.
                    // The timeout is a belt-and-braces bound, not a poll.
                    let guard = reap_registry().lock().unwrap();
                    let _ = reap_wakeup()
                        .wait_timeout_while(guard, std::time::Duration::from_millis(500), |r| {
                            r.is_empty()
                        })
                        .unwrap();
                    continue;
                }
                let Some(outcome) = wait_status_to_outcome(status) else {
                    continue;
                };
                // Drop the registry lock before sending so a handler's recv
                // never contends with it.
                let waiter = reap_registry().lock().unwrap().remove(&pid);
                if let Some(tx) = waiter {
                    let _ = tx.send(outcome);
                }
                // Otherwise a reparented orphan: reaped above, nothing to route.
            }
        });
    }

    fn handle_piped(mut conn: VsockStream, start: StartCommand) {
        use std::os::unix::process::CommandExt;
        use std::process::{Command, Stdio};

        let user = match resolve_start_user(&start.user) {
            Ok(u) => u,
            Err(msg) => {
                report_start_failure(&mut conn, 126, &msg);
                return;
            }
        };

        let Some(program) = start.cmd.first() else {
            report_start_failure(&mut conn, 127, "empty command");
            return;
        };
        let mut cmd = Command::new(program);
        cmd.args(start.cmd.get(1..).unwrap_or(&[]));
        cmd.envs(&start.env);
        if !start.working_dir.is_empty() {
            cmd.current_dir(&start.working_dir);
        }
        // Run in a fresh session/process group and drop privileges in pre_exec,
        // mirroring handle_tty: setsid so a timeout/disconnect kill can target
        // the whole process group (descendants included), then supplementary
        // groups → gid → uid, fail-closed. std's .uid()/.gid() skip setgroups,
        // leaving the workload with root's supplementary group list.
        let creds = user.map(|u| (u.uid as libc::uid_t, u.gid as libc::gid_t));
        // SAFETY: the closure runs in the forked child before exec and calls
        // only async-signal-safe syscalls.
        unsafe {
            cmd.pre_exec(move || {
                if libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if let Some((uid, gid)) = creds
                    && (libc::setgroups(1, &raw const gid) != 0
                        || libc::setgid(gid) != 0
                        || libc::setuid(uid) != 0)
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        // Spawn and register for reaping under one lock: if the child exits
        // immediately, the reaper blocks on the registry lock until the insert
        // below completes, so its exit code is never lost as an "orphan".
        let (exit_tx, exit_rx) = mpsc::channel::<WaitOutcome>();
        let mut child = {
            let mut registry = reap_registry().lock().unwrap();
            match cmd.spawn() {
                Ok(c) => {
                    register_child(&mut registry, as_pid(c.id()), exit_tx);
                    c
                }
                Err(e) => {
                    drop(registry);
                    eprintln!("agent: spawn {:?}: {e}", start.cmd);
                    report_start_failure(&mut conn, 127, &format!("spawn {:?}: {e}", start.cmd));
                    return;
                }
            }
        };
        let child_pid = as_pid(child.id());

        let child_stdin = child.stdin.take().unwrap();
        let child_stdout = child.stdout.take().unwrap();
        let child_stderr = child.stderr.take().unwrap();

        // Shared writer so the stdout and stderr threads don't interleave frames.
        let writer: Arc<Mutex<VsockStream>> = Arc::new(Mutex::new(conn));

        let w1 = Arc::clone(&writer);
        let t_stdout = thread::spawn(move || {
            let mut buf = [0u8; 4096];
            let mut out = child_stdout;
            loop {
                match out.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let _ = write_frame(&mut *w1.lock().unwrap(), MSG_STDOUT, &buf[..n]);
                    }
                }
            }
        });

        let w2 = Arc::clone(&writer);
        let t_stderr = thread::spawn(move || {
            let mut buf = [0u8; 4096];
            let mut err = child_stderr;
            loop {
                match err.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let _ = write_frame(&mut *w2.lock().unwrap(), MSG_STDERR, &buf[..n]);
                    }
                }
            }
        });

        if start.timeout_seconds > 0 {
            spawn_timeout_killer(child_pid, start.timeout_seconds);
        }

        // Input loop on its own thread, mirroring the TTY path: the exit
        // report below must never be gated on host input, and the session must
        // keep accepting MSG_SIGNAL after a clean stdin EOF. Reporting the exit
        // from the input loop (the old shape) deadlocked any session whose
        // process exited while the host was still holding stdin open.
        // SAFETY: dup gives us a second fd for reading while the Arc owns the write fd.
        let read_fd = unsafe { libc::dup(writer.lock().unwrap().fd) };
        let exited = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let exited_in_loop = Arc::clone(&exited);
        let t_input = thread::spawn(move || {
            // SAFETY: read_fd is a fresh dup owned by this thread.
            let mut reader = unsafe { VsockStream::from_raw_fd(read_fd) };
            let mut stdin = Some(child_stdin);
            loop {
                match read_frame(&mut reader) {
                    Ok((MSG_STDIN, data)) => {
                        if let Some(ref mut s) = stdin
                            && s.write_all(&data).is_err()
                        {
                            stdin = None;
                        }
                    }
                    Ok((MSG_EOF, _)) => {
                        // Clean stdin EOF: close the child's stdin but keep the
                        // loop alive for signal frames.
                        stdin = None;
                    }
                    Ok((MSG_SIGNAL, data)) => deliver_signal(child_pid, &data),
                    Err(_) => {
                        // Read shutdown after exit is routine teardown; a real
                        // host disconnect must not leave the workload headless.
                        if !exited_in_loop.load(Ordering::Relaxed) {
                            kill_if_alive(child_pid);
                        }
                        return;
                    }
                    Ok(_) => {}
                }
            }
        });

        let _ = t_stdout.join();
        let _ = t_stderr.join();
        // The reaper owns waitpid; block on the routed exit outcome.
        let outcome = exit_rx.recv().unwrap_or(WaitOutcome::Exited(-1));
        let _ = write_frame(
            &mut *writer.lock().unwrap(),
            MSG_EXIT,
            &exit_payload(outcome),
        );
        exited.store(true, Ordering::Relaxed);
        // Unblock the input thread's read so the session tears down without
        // depending on the host noticing first.
        // SAFETY: read_fd stays open until t_input drops its VsockStream;
        // shutting down the read half only wakes the blocked read.
        unsafe { libc::shutdown(read_fd, libc::SHUT_RD) };
        let _ = t_input.join();
    }

    /// SIGKILL `pid` after `timeout_seconds`, if it is still alive.
    fn spawn_timeout_killer(pid: libc::pid_t, timeout_seconds: u32) {
        thread::spawn(move || {
            thread::sleep(std::time::Duration::from_secs(u64::from(timeout_seconds)));
            kill_if_alive(pid);
        });
    }

    /// SIGKILL the workload's process group if its leader is still alive.
    ///
    /// Both exec paths `setsid` the child, so its pgid equals its pid; killing
    /// the group (`-pid`) takes down descendants a plain child-pid SIGKILL would
    /// orphan. The signal-0 probe on the leader avoids killing a recycled pid.
    /// The reaper collects the terminated children.
    fn kill_if_alive(pid: libc::pid_t) {
        // SAFETY: kill with a valid pid; signal 0 only probes for existence,
        // and a negative pid targets the process group led by `pid`.
        unsafe {
            if libc::kill(pid, 0) == 0 {
                let _ = libc::kill(-pid, libc::SIGKILL);
            }
        }
    }

    // -------------------------------------------------------------------------
    // Interactive execution (pseudo-TTY)
    // -------------------------------------------------------------------------

    fn handle_tty(mut conn: VsockStream, start: StartCommand) {
        use nix::pty::OpenptyResult;
        use nix::unistd::{ForkResult, fork, setsid};
        use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd};

        // Resolve the user before forking so failures are reportable.
        let user = match resolve_start_user(&start.user) {
            Ok(u) => u,
            Err(msg) => {
                report_start_failure(&mut conn, 126, &msg);
                return;
            }
        };

        let OpenptyResult { master, slave } = match nix::pty::openpty(None, None) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("agent: openpty: {e}");
                report_start_failure(&mut conn, 126, &format!("openpty: {e}"));
                return;
            }
        };

        if start.tty_width > 0 && start.tty_height > 0 {
            let winsize = libc::winsize {
                ws_col: start.tty_width,
                ws_row: start.tty_height,
                ws_xpixel: 0,
                ws_ypixel: 0,
            };
            // SAFETY: master is a valid PTY master fd.
            unsafe { libc::ioctl(master.as_raw_fd(), libc::TIOCSWINSZ, &winsize) };
        }

        // Transfer ownership so only one entity (File at line 608) closes master_fd.
        let master_fd: RawFd = master.into_raw_fd();
        let slave_fd: RawFd = slave.as_raw_fd();

        // Hold the reap registry lock across fork + register so the single
        // reaper thread can't route (and discard) the child's exit status
        // before it is registered below.
        let (exit_tx, exit_rx) = mpsc::channel::<WaitOutcome>();
        let mut registry = reap_registry().lock().unwrap();
        match unsafe { fork() } {
            Err(e) => {
                drop(registry);
                // SAFETY: fork failed; close the unowned master fd to prevent leak.
                unsafe { libc::close(master_fd) };
                eprintln!("agent: fork: {e}");
            }

            Ok(ForkResult::Child) => {
                // The child never touches `registry` (a COW guard copy); it
                // execs or _exits below.
                // SAFETY: close the inherited master fd in the child process.
                unsafe { libc::close(master_fd) };
                let _ = setsid();
                // SAFETY: all fds are valid in the child process.
                unsafe {
                    libc::ioctl(slave_fd, libc::TIOCSCTTY, 0);
                    libc::dup2(slave_fd, libc::STDIN_FILENO);
                    libc::dup2(slave_fd, libc::STDOUT_FILENO);
                    libc::dup2(slave_fd, libc::STDERR_FILENO);
                    if slave_fd > libc::STDERR_FILENO {
                        libc::close(slave_fd);
                    }
                }

                let cstrings: Vec<std::ffi::CString> = start
                    .cmd
                    .iter()
                    .filter_map(|s| std::ffi::CString::new(s.as_str()).ok())
                    .collect();
                let mut argv: Vec<*const libc::c_char> =
                    cstrings.iter().map(|s| s.as_ptr()).collect();
                argv.push(std::ptr::null());

                for (k, v) in &start.env {
                    if let (Ok(ck), Ok(cv)) = (
                        std::ffi::CString::new(k.as_str()),
                        std::ffi::CString::new(v.as_str()),
                    ) {
                        // SAFETY: setenv is safe with valid C strings.
                        unsafe { libc::setenv(ck.as_ptr(), cv.as_ptr(), 1) };
                    }
                }
                if !start.working_dir.is_empty()
                    && let Ok(cwd) = std::ffi::CString::new(start.working_dir.as_str())
                {
                    // SAFETY: cwd is a valid C string.
                    unsafe { libc::chdir(cwd.as_ptr()) };
                }

                if let Some(u) = user {
                    // Drop privileges: supplementary groups, then gid, then
                    // uid — the reverse order would lose the right to setgid.
                    let gid = u.gid as libc::gid_t;
                    // SAFETY: plain syscalls on the just-forked child; on any
                    // failure we abort the exec with 126 rather than run the
                    // workload with the wrong identity.
                    unsafe {
                        if libc::setgroups(1, &raw const gid) != 0
                            || libc::setgid(gid) != 0
                            || libc::setuid(u.uid as libc::uid_t) != 0
                        {
                            libc::_exit(126);
                        }
                    }
                }

                // SAFETY: exec replaces the process image; argv is null-terminated.
                unsafe { libc::execvp(argv[0], argv.as_ptr()) };
                unsafe { libc::_exit(127) };
            }

            Ok(ForkResult::Parent { child }) => {
                let child_pid = child.as_raw();
                register_child(&mut registry, child_pid, exit_tx);
                drop(registry); // release before the (long-lived) session loop

                if start.timeout_seconds > 0 {
                    spawn_timeout_killer(child_pid, start.timeout_seconds);
                }

                drop(slave);
                let writer: Arc<Mutex<VsockStream>> = Arc::new(Mutex::new(conn));

                let read_fd = unsafe { libc::dup(writer.lock().unwrap().fd) };
                let mut reader = unsafe { VsockStream::from_raw_fd(read_fd) };

                let w_read = Arc::clone(&writer);
                let t_pty = thread::spawn(move || {
                    let mut buf = [0u8; 4096];
                    // SAFETY: dup of master_fd owned by this thread.
                    let mut r = unsafe { VsockStream::from_raw_fd(libc::dup(master_fd)) };
                    loop {
                        match r.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                let _ = write_frame(
                                    &mut *w_read.lock().unwrap(),
                                    MSG_STDOUT,
                                    &buf[..n],
                                );
                            }
                        }
                    }

                    // The master read only ends when every slave fd is closed,
                    // i.e. the session's processes are gone. Report the status
                    // here rather than after the input loop: that loop is parked
                    // in read_frame waiting for host frames, and the host is
                    // waiting for this status, so leaving it until then
                    // deadlocked every interactive session that exited on its
                    // own (^D at a shell, an agent quitting on ^C) until the
                    // client gave up or was killed.
                    let outcome = exit_rx.recv().unwrap_or(WaitOutcome::Exited(-1));
                    let _ = write_frame(
                        &mut *w_read.lock().unwrap(),
                        MSG_EXIT,
                        &exit_payload(outcome),
                    );

                    // Unblock the input loop so the session tears down without
                    // depending on the client noticing first.
                    // SAFETY: read_fd is a live dup of the connection owned by
                    // the input loop; shutting down its read half makes a
                    // blocked read return instead of waiting for host input.
                    unsafe { libc::shutdown(read_fd, libc::SHUT_RD) };
                });
                // SAFETY: master_fd is valid; File takes ownership for writes.
                let mut master_writer = unsafe { std::fs::File::from_raw_fd(master_fd) };

                loop {
                    match read_frame(&mut reader) {
                        Ok((MSG_STDIN, data)) => {
                            let _ = master_writer.write_all(&data);
                        }
                        Ok((MSG_RESIZE, data)) if data.len() >= 4 => {
                            let winsize = libc::winsize {
                                ws_col: u16::from_le_bytes([data[0], data[1]]),
                                ws_row: u16::from_le_bytes([data[2], data[3]]),
                                ws_xpixel: 0,
                                ws_ypixel: 0,
                            };
                            // SAFETY: master_fd is valid.
                            unsafe { libc::ioctl(master_fd, libc::TIOCSWINSZ, &winsize) };
                        }
                        Ok((MSG_SIGNAL, data)) => deliver_signal(child_pid, &data),
                        Ok((MSG_EOF, _)) => break,
                        Err(_) => {
                            // Host gone: kill the session's process group leader
                            // rather than leave the interactive shell running.
                            kill_if_alive(child_pid);
                            break;
                        }
                        Ok(_) => {}
                    }
                }

                // The PTY thread owns reporting the exit status (see above), so
                // joining it is all that is left.
                let _ = t_pty.join();
            }
        }
    }

    // -------------------------------------------------------------------------
    // vsock listener
    // -------------------------------------------------------------------------

    /// Mount essential virtual filesystems for an init process.
    fn mount_filesystems() {
        use std::ffi::CString;

        let mounts: &[(&str, &str, &str, libc::c_ulong, &str)] = &[
            (
                "/proc",
                "proc",
                "proc",
                libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                "",
            ),
            (
                "/sys",
                "sysfs",
                "sysfs",
                libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                "",
            ),
            ("/dev", "devtmpfs", "devtmpfs", libc::MS_NOSUID, "mode=0755"),
            (
                "/dev/pts",
                "devpts",
                "devpts",
                libc::MS_NOSUID | libc::MS_NOEXEC,
                "newinstance,ptmxmode=0666",
            ),
            // /etc/resolv.conf is a symlink into /run so DNS rewrites (boot
            // setup_dns, post-restore net reconfig) stay off the CoW block
            // device — a first ext4 write costs a ~30 ms synchronous
            // dm-snapshot exception through the nested I/O stack (CORE-75).
            (
                "/run",
                "tmpfs",
                "tmpfs",
                libc::MS_NOSUID | libc::MS_NODEV,
                "mode=0755",
            ),
        ];

        for (target, source, fstype, flags, data) in mounts {
            let _ = std::fs::create_dir_all(target);
            let c_source = CString::new(*source).unwrap();
            let c_target = CString::new(*target).unwrap();
            let c_fstype = CString::new(*fstype).unwrap();
            let c_data = CString::new(*data).unwrap();
            // SAFETY: all pointers are valid C strings.
            let ret = unsafe {
                libc::mount(
                    c_source.as_ptr(),
                    c_target.as_ptr(),
                    c_fstype.as_ptr(),
                    *flags,
                    c_data.as_ptr().cast(),
                )
            };
            if ret != 0 {
                eprintln!("mount {target}: {}", std::io::Error::last_os_error());
            }
        }

        // Symlink /dev/ptmx → /dev/pts/ptmx so openpty() works.
        let _ = std::os::unix::fs::symlink("/dev/pts/ptmx", "/dev/ptmx");
    }

    /// Find a whitespace-delimited token in `/proc/cmdline` that starts
    /// with the given prefix (e.g. `"ip="` matches `ip=172.20.0.2::...`).
    fn cmdline_token(prefix: &str) -> Option<String> {
        let cmdline = std::fs::read_to_string("/proc/cmdline").ok()?;
        cmdline
            .split_whitespace()
            .find(|t| t.starts_with(prefix))
            .map(str::to_string)
    }

    /// Write `/etc/resolv.conf` pointing at the sandbox gateway so that
    /// glibc DNS resolution works.  The gateway address hosts the guest
    /// DNS server (`0.0.0.0:53`) which handles container/sandbox name
    /// resolution before forwarding upstream.
    ///
    /// Skipped when the `ip=` parameter is absent (e.g. `network: none`
    /// sandboxes or custom rootfs with their own resolver config).
    fn setup_dns() {
        let Some(token) = cmdline_token("ip=") else {
            eprintln!("vm-agent: no ip= parameter in cmdline, skipping DNS setup");
            return;
        };
        let ip_param = match token.parse::<KernelIpParam>() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("vm-agent: invalid ip= parameter: {e}");
                return;
            }
        };

        let content = format!("nameserver {}\n", ip_param.gateway);
        match std::fs::write("/etc/resolv.conf", &content) {
            Ok(()) => eprintln!(
                "vm-agent: wrote /etc/resolv.conf (nameserver {})",
                ip_param.gateway
            ),
            Err(e) => eprintln!("vm-agent: failed to write /etc/resolv.conf: {e}"),
        }
    }

    /// Spawn a thread with a reduced stack size and a semaphore-style concurrency
    /// limit.  If the limit is already reached the connection fd is closed and a
    /// warning is logged — this is preferable to OOM-killing the guest.
    fn spawn_bounded(active: &Arc<AtomicUsize>, name: &str, conn_fd: RawFd, handler: fn(RawFd)) {
        let current = active.fetch_add(1, Ordering::Relaxed);
        if current >= MAX_ACTIVE_CONNECTIONS {
            active.fetch_sub(1, Ordering::Relaxed);
            eprintln!(
                "agent: {name}: connection limit reached ({MAX_ACTIVE_CONNECTIONS}), dropping fd {conn_fd}"
            );
            // SAFETY: conn_fd is a valid, freshly accepted socket fd that nobody
            // else owns yet.
            unsafe { libc::close(conn_fd) };
            return;
        }

        let active_clone = Arc::clone(active);
        let thread_name = format!("{name}-{conn_fd}");
        let builder = thread::Builder::new()
            .name(thread_name)
            .stack_size(THREAD_STACK_SIZE);

        if let Err(e) = builder.spawn(move || {
            handler(conn_fd);
            active_clone.fetch_sub(1, Ordering::Relaxed);
        }) {
            // The closure was consumed but never executed — release the slot
            // using the original reference and close the fd.
            active.fetch_sub(1, Ordering::Relaxed);
            eprintln!("agent: {name}: failed to spawn thread: {e}");
            // SAFETY: conn_fd is still valid; the closure never ran.
            unsafe { libc::close(conn_fd) };
        }
    }

    pub fn run() {
        mount_filesystems();
        setup_dns();
        // Set the wall clock from the hypervisor before anything can care:
        // /dev/ptp0 needs no host RPC, so a guest whose kernel lacks
        // RTC_HCTOSYS still boots with correct time. Verbose on purpose —
        // once per boot, and the offset line is the hardware-validation
        // signal for the ptp path.
        match crate::ptp::sync_clock_from_ptp() {
            Ok(crate::ptp::SyncOutcome::Stepped { offset_ns }) => eprintln!(
                "vm-agent: ptp clock sync: stepped CLOCK_REALTIME by {} ms at startup",
                offset_ns / 1_000_000
            ),
            Ok(crate::ptp::SyncOutcome::InSync { offset_ns }) => eprintln!(
                "vm-agent: ptp clock sync: in sync at startup (offset {} us)",
                offset_ns / 1_000
            ),
            Err(e) => eprintln!("vm-agent: ptp clock sync at startup: {e}"),
        }
        // This process is guest PID 1: start the reaper so exiting workloads and
        // reparented double-fork orphans are collected instead of zombifying.
        start_reaper();
        eprintln!("vm-agent: listening on vsock ports {AGENT_PORT} (exec), {FILE_PORT} (file I/O)");
        let exec_fd = create_vsock_listener(AGENT_PORT);
        let file_fd = create_vsock_listener(FILE_PORT);

        // Both listeners are bound and mounts/DNS are done: tell the host.
        // The dial-out is the cold-boot readiness event the host gates on.
        signal_ready();

        // Shared counters for bounding active connection threads.
        let file_active: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
        let exec_active: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));

        // File I/O listener thread.
        let file_active_clone = Arc::clone(&file_active);
        thread::spawn(move || {
            loop {
                let conn_fd = accept_connection(file_fd);
                spawn_bounded(&file_active_clone, "file", conn_fd, handle_file_connection);
            }
        });

        // Exec listener (main thread).
        loop {
            let conn_fd = accept_connection(exec_fd);
            // A restored guest wakes with CLOCK_REALTIME still at its
            // snapshot value, and the first post-resume interaction is
            // always an accepted connection: re-check the clock before the
            // handler can spawn a workload (rate-limited, µs when in sync).
            crate::ptp::sync_rate_limited();
            spawn_bounded(&exec_active, "exec", conn_fd, handle_connection);
        }
    }

    /// Dial the host's readiness listener: connect `AF_VSOCK` to the host
    /// (CID 2) on `READY_PORT`, write one byte, close. Firecracker forwards
    /// the connect to the Unix socket the host pre-bound before starting
    /// this VM — the accept there is the boot readiness event.
    ///
    /// Best-effort by design: under an OLD host without the listener,
    /// Firecracker resets the connect (`ECONNRESET`-class error), and the
    /// agent must keep serving — readiness detection then falls back to
    /// that host's own connect polling.
    fn signal_ready() {
        // SAFETY: plain socket(2) call; result checked below.
        let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) };
        if fd < 0 {
            eprintln!(
                "vm-agent: ready dial-out: socket: {}",
                std::io::Error::last_os_error()
            );
            return;
        }
        // SAFETY: fd is a freshly opened, owned socket fd.
        let mut stream = unsafe { VsockStream::from_raw_fd(fd) };

        let addr = libc::sockaddr_vm {
            svm_family: libc::AF_VSOCK as libc::sa_family_t,
            svm_reserved1: 0,
            svm_port: READY_PORT,
            svm_cid: libc::VMADDR_CID_HOST,
            ..unsafe { std::mem::zeroed() }
        };
        // SAFETY: addr is a fully initialized sockaddr_vm; fd is a live socket.
        let ret = unsafe {
            libc::connect(
                fd,
                (&raw const addr).cast::<libc::sockaddr>(),
                std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
            )
        };
        if ret != 0 {
            eprintln!(
                "vm-agent: ready dial-out failed (old host without a listener?): {}",
                std::io::Error::last_os_error()
            );
            return;
        }
        if let Err(e) = stream.write_all(&[0u8]) {
            eprintln!("vm-agent: ready dial-out write: {e}");
        }
    }

    fn create_vsock_listener(port: u32) -> RawFd {
        // SAFETY: socket(2) with valid AF_VSOCK constants.
        let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) };
        assert!(
            fd >= 0,
            "socket(AF_VSOCK): {}",
            std::io::Error::last_os_error()
        );

        let addr = libc::sockaddr_vm {
            svm_family: libc::AF_VSOCK as libc::sa_family_t,
            svm_reserved1: 0,
            svm_port: port,
            svm_cid: libc::VMADDR_CID_ANY,
            ..unsafe { std::mem::zeroed() }
        };
        // SAFETY: addr is valid; fd is a live socket.
        let ret = unsafe {
            libc::bind(
                fd,
                (&raw const addr).cast::<libc::sockaddr>(),
                std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
            )
        };
        assert!(
            ret == 0,
            "bind vsock port {port}: {}",
            std::io::Error::last_os_error()
        );
        // SAFETY: fd is a bound socket.
        unsafe { libc::listen(fd, 128) };
        fd
    }

    fn accept_connection(server_fd: RawFd) -> RawFd {
        loop {
            // SAFETY: server_fd is a listening vsock socket.
            let conn_fd =
                unsafe { libc::accept(server_fd, std::ptr::null_mut(), std::ptr::null_mut()) };
            if conn_fd >= 0 {
                return conn_fd;
            }
            let err = std::io::Error::last_os_error();
            assert!(
                err.kind() == std::io::ErrorKind::Interrupted,
                "accept: {err}"
            );
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn normal_exit_decodes_to_its_code() {
            // Linux wait status encodes a normal exit as `code << 8`.
            assert_eq!(wait_status_to_outcome(0), Some(WaitOutcome::Exited(0)));
            assert_eq!(
                wait_status_to_outcome(42 << 8),
                Some(WaitOutcome::Exited(42))
            );
            assert_eq!(
                wait_status_to_outcome(127 << 8),
                Some(WaitOutcome::Exited(127))
            );
        }

        #[test]
        fn signal_death_keeps_the_signal() {
            // A process killed by signal N has N in the low 7 status bits.
            assert_eq!(
                wait_status_to_outcome(libc::SIGKILL),
                Some(WaitOutcome::Signaled(libc::SIGKILL))
            );
            assert_eq!(
                wait_status_to_outcome(libc::SIGTERM),
                Some(WaitOutcome::Signaled(libc::SIGTERM))
            );
        }

        #[test]
        fn exit_payload_encodes_code_and_signal_slots() {
            let normal = exit_payload(WaitOutcome::Exited(42));
            assert_eq!(i32::from_le_bytes(normal[..4].try_into().unwrap()), 42);
            assert_eq!(i32::from_le_bytes(normal[4..].try_into().unwrap()), 0);

            // Signal deaths keep the shell convention in the code slot so a
            // 4-byte legacy reader sees the value the old protocol carried.
            let killed = exit_payload(WaitOutcome::Signaled(9));
            assert_eq!(i32::from_le_bytes(killed[..4].try_into().unwrap()), 137);
            assert_eq!(i32::from_le_bytes(killed[4..].try_into().unwrap()), 9);
        }
    }
}

// =============================================================================
// Entry point
// =============================================================================

fn main() {
    #[cfg(target_os = "linux")]
    agent::run();

    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("vm-agent requires Linux (AF_VSOCK)");
        std::process::exit(1);
    }
}
