use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::sync::Arc;

use crate::error::{Result, VmmError};

use super::*;

impl Vmm {
    /// Duplicates a daemon-facing socketpair fd into a monotonically increasing
    /// descriptor range derived from the connection's host port.
    ///
    /// During guest boot, the daemon opens and drops several short-lived vsock
    /// probe connections in quick succession. On macOS the low socketpair fd
    /// number was being recycled immediately (`20`, `20`, `20`, ...), which in
    /// turn let Tokio/kqueue reuse the same registration slot across retries.
    /// When a previous registration had not been fully torn down yet, later
    /// attempts could miss both EOF and timeout wakeups. Rebinding the daemon
    /// end to the per-connection host port avoids that fd-number reuse while
    /// keeping the actual socket semantics unchanged.
    pub(super) fn duplicate_client_vsock_fd(fd: OwnedFd, min_fd: RawFd) -> Result<OwnedFd> {
        // Clamp `min_fd` below the current RLIMIT_NOFILE soft limit. Port
        // numbers passed in as `min_fd` can legitimately reach ~65 k, but on
        // macOS CI runners the soft limit defaults to ~2560, making a raw
        // F_DUPFD_CLOEXEC return EINVAL. The caller only needs an fd number
        // that avoids the recycled low range — any value well above the
        // socketpair/tokio-registration churn band (say, fd > 1024) works.
        let clamped_min = {
            let mut rl = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            // SAFETY: `getrlimit` writes a single `rlimit` struct; the raw
            // pointer is valid for the duration of the call.
            let rc = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, std::ptr::from_mut(&mut rl)) };
            if rc == 0 && (rl.rlim_cur as RawFd) > 128 {
                // Reserve ~64 fds for the rest of the process; clamp min_fd
                // to whichever is smaller.
                let ceiling = (rl.rlim_cur as RawFd).saturating_sub(64);
                min_fd.min(ceiling)
            } else {
                min_fd
            }
        };

        // SAFETY: `fd` is a live OwnedFd; fcntl(F_DUPFD_CLOEXEC) is a
        // read-only operation on the open file table and cannot cause UB.
        let dup_fd = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, clamped_min) };
        if dup_fd < 0 {
            return Err(VmmError::Device(format!(
                "vsock client fd dup failed: {} (clamped_min={clamped_min})",
                std::io::Error::last_os_error()
            )));
        }

        // SAFETY: `dup_fd` is a fresh fd produced by the kernel on success;
        // no other owner exists, so `OwnedFd` takes sole ownership.
        Ok(unsafe { OwnedFd::from_raw_fd(dup_fd) })
    }

    /// Creates the vsock doorbell pipe, installs the ring callback into the
    /// connection manager, and spawns the vsock-io worker thread.
    ///
    /// The worker owns host→guest vsock injection from here on; the vCPU
    /// loop no longer polls vsock. Joined in `stop_darwin_hv` before guest
    /// memory is released.
    pub(super) fn spawn_vsock_rx_worker(
        &mut self,
        device_manager: &Arc<DeviceManager>,
    ) -> Result<()> {
        // Spawn once per VMM lifecycle; `stop_darwin_hv` joins and clears.
        if self.hv_vsock_worker.is_some() {
            return Ok(());
        }

        let mut pipe_fds: [libc::c_int; 2] = [0; 2];
        // SAFETY: `pipe_fds` is a valid 2-element array; pipe writes two
        // fds into it on success.
        let ret = unsafe { libc::pipe(pipe_fds.as_mut_ptr()) };
        if ret != 0 {
            return Err(VmmError::Device(format!(
                "vsock doorbell pipe failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        // SAFETY: both fds are fresh from pipe above with sole ownership.
        let doorbell_rd = unsafe { OwnedFd::from_raw_fd(pipe_fds[0]) };
        // SAFETY: same as above for the write end.
        let doorbell_wr = unsafe { OwnedFd::from_raw_fd(pipe_fds[1]) };

        // Both ends non-blocking + cloexec. The write end must never block
        // a producer (a full pipe already guarantees a pending wakeup); the
        // worker drains the read end with a non-blocking loop.
        for fd in [doorbell_rd.as_raw_fd(), doorbell_wr.as_raw_fd()] {
            // SAFETY: `fd` is a live fd owned by the OwnedFds above.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            // SAFETY: same fd; setting O_NONBLOCK is side-effect-only.
            if flags == -1
                || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1
            {
                return Err(VmmError::Device(format!(
                    "vsock doorbell O_NONBLOCK failed: {}",
                    std::io::Error::last_os_error()
                )));
            }
            // SAFETY: same fd; FD_CLOEXEC is side-effect-only.
            let fd_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            if fd_flags != -1 {
                // SAFETY: same fd as above.
                let _ = unsafe { libc::fcntl(fd, libc::F_SETFD, fd_flags | libc::FD_CLOEXEC) };
            }
        }

        let doorbell: crate::vsock_manager::VsockDoorbell = Arc::new(move || {
            let byte = [1u8];
            // SAFETY: the write end is owned by this closure and stays open
            // for its lifetime. EAGAIN on a full pipe is fine — a wakeup is
            // already pending.
            let _ = unsafe {
                libc::write(
                    doorbell_wr.as_raw_fd(),
                    byte.as_ptr().cast::<libc::c_void>(),
                    1,
                )
            };
        });
        device_manager
            .vsock_connections()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .set_doorbell(doorbell);

        let ctx = crate::vsock_rx_worker::VsockRxWorkerContext {
            device_manager: Arc::clone(device_manager),
            doorbell_rd,
            running: self.running.clone(),
            exit_vcpus: make_exit_vcpus_fn(
                self.hv_vcpu_ids
                    .clone()
                    .expect("hv_vcpu_ids asserted Some above"),
                self.hv_kick_broadcasts.clone(),
            ),
        };
        let handle = std::thread::Builder::new()
            .name("vsock-io".to_string())
            .spawn(move || crate::vsock_rx_worker::vsock_rx_worker_loop(ctx))
            .map_err(|e| VmmError::Device(format!("spawn vsock-io worker: {e}")))?;
        self.hv_vsock_worker = Some(handle);
        Ok(())
    }

    /// Connects to a vsock port on the guest VM (HV backend).
    ///
    /// Creates a Unix `SOCK_STREAM` socketpair; one end is returned to the
    /// caller for host-side I/O, the other is registered with
    /// `VsockConnectionManager` so the VirtIO vsock device can relay data
    /// between the socketpair and the guest's RX/TX queues.
    ///
    /// Returns immediately after allocating and enqueueing the connection —
    /// `allocate` rings the vsock-io worker's doorbell, which injects the
    /// OP_REQUEST into the guest RX queue right away. The returned fd is
    /// usable immediately; the guest responds with OP_RESPONSE or OP_RST
    /// as soon as it services the interrupt.
    #[allow(clippy::unnecessary_wraps)]
    pub(in crate::vmm) fn connect_vsock_hv(&self, port: u32) -> Result<std::os::unix::io::RawFd> {
        // Create a Unix SOCK_STREAM socketpair for bidirectional data.
        let mut fds: [libc::c_int; 2] = [0; 2];
        // SAFETY: `fds` is a valid 2-element array; socketpair writes two
        // fds into it on success.
        let ret =
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
        if ret != 0 {
            return Err(VmmError::Device(format!(
                "vsock socketpair failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        // Set non-blocking + cloexec on internal fd (for poll_vsock_rx peek).
        // The daemon-side fd (fds[0]) stays BLOCKING with a receive timeout —
        // tokio's AsyncFd will set O_NONBLOCK when it wraps the fd.
        // SAFETY: `fds[0]` and `fds[1]` are live kernel fds from the
        // socketpair above. fcntl is side-effect-only; none of the branches
        // escape the fds outside this function.
        unsafe {
            // fds[1]: internal end — needs O_NONBLOCK for poll_vsock_rx libc::read.
            let flags = libc::fcntl(fds[1], libc::F_GETFL);
            if flags == -1 {
                return Err(VmmError::Device(format!(
                    "vsock fcntl F_GETFL failed: {}",
                    std::io::Error::last_os_error()
                )));
            }
            if libc::fcntl(fds[1], libc::F_SETFL, flags | libc::O_NONBLOCK) == -1 {
                return Err(VmmError::Device(format!(
                    "vsock fcntl F_SETFL O_NONBLOCK failed: {}",
                    std::io::Error::last_os_error()
                )));
            }
            // Both ends: FD_CLOEXEC.
            for &fd in &fds {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags == -1 {
                    tracing::warn!(
                        "vsock fcntl F_GETFD failed on fd {fd}: {}",
                        std::io::Error::last_os_error()
                    );
                    continue;
                }
                if libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) == -1 {
                    tracing::warn!(
                        "vsock fcntl F_SETFD FD_CLOEXEC failed on fd {fd}: {}",
                        std::io::Error::last_os_error()
                    );
                }
            }

            // Bump socketpair send/receive buffers so large RPC responses
            // don't hit SO_SNDBUF backpressure on the vsock device's
            // write path. macOS defaults are typically ~8 KiB, which
            // caused silent truncation of DAX read responses > 8 KiB
            // (ABX-365). 1 MiB fits anything the agent currently emits.
            let bufsize: libc::c_int = 1 << 20;
            for &fd in &fds {
                for opt in [libc::SO_SNDBUF, libc::SO_RCVBUF] {
                    if libc::setsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        opt,
                        (&raw const bufsize).cast::<libc::c_void>(),
                        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                    ) == -1
                    {
                        tracing::debug!(
                            "vsock setsockopt(opt={opt}, 1MiB) on fd {fd} failed: {}",
                            std::io::Error::last_os_error()
                        );
                    }
                }
            }
        }

        // fds[0] = returned to caller (daemon agent client)
        // fds[1] = internal, owned by VsockConnectionManager
        // SAFETY: Both fds are fresh from socketpair above with sole
        // ownership; wrapping them in OwnedFd is the standard transfer
        // pattern, and OwnedFd's Drop closes them on error paths.
        let host_fd = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        // SAFETY: Same as above for the peer fd.
        let internal_fd = unsafe { OwnedFd::from_raw_fd(fds[1]) };

        let dm = self
            .hv_device_manager
            .as_ref()
            .ok_or_else(|| VmmError::Device("DeviceManager not initialized".to_string()))?;

        let guest_cid = self.config.guest_cid.unwrap_or(3) as u64;

        let conns = dm.vsock_connections();
        let (conn_id, connect_rx) = {
            let mut mgr = conns
                .lock()
                .map_err(|e| VmmError::Device(format!("vsock manager lock failed: {e}")))?;
            mgr.allocate(port, guest_cid, internal_fd)
        };

        let min_fd = RawFd::try_from(conn_id.host_port).map_err(|_| {
            VmmError::Device(format!(
                "vsock host_port {} exceeds RawFd range",
                conn_id.host_port
            ))
        })?;
        let host_fd = Self::duplicate_client_vsock_fd(host_fd, min_fd).inspect_err(|_| {
            if let Ok(mut mgr) = conns.lock() {
                mgr.remove(&conn_id);
            }
        })?;

        tracing::info!(
            "HV vsock connect: guest_port={}, host_port={}, host_fd={}",
            port,
            conn_id.host_port,
            host_fd.as_raw_fd(),
        );

        // OP_REQUEST is in backend_rxq and the vsock-io worker's doorbell
        // has been rung; it injects and fires injected_notify. We do NOT
        // block here — the daemon's ping().await handles the timing:
        // - If REQUEST not yet injected: ping timeout (2s) → retry
        // - If injected + RST: read returns EOF → retry
        // - If injected + RESPONSE: read returns data → success
        //
        // The injected_notify channel is kept alive via the VsockConnection's
        // OwnedFd lifetime. When the connection is removed (RST), the sender
        // is dropped, which is fine — we don't read it.
        let _ = connect_rx; // Drop receiver — we don't wait on it.

        Ok(host_fd.into_raw_fd())
    }
}
