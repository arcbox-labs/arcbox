//! Dedicated vsock-io worker thread for VirtIO-vsock RX injection.
//!
//! Decouples host→guest vsock delivery from the BSP vCPU run loop. The BSP
//! previously drove `poll_vsock_rx` only when it took a VM exit; with an
//! idle guest parked inside `hv_vcpu_run`, exits are ~100 ms apart, so every
//! host→guest leg (OP_REQUEST, request data, credit grants) stalled for that
//! long. Three sequential connects per proxied Docker request turned into a
//! 0.5–1.5 s command stall.
//!
//! The worker blocks in `kevent` on two wakeup sources:
//! - the doorbell pipe, rung by `VsockConnectionManager` when producer paths
//!   enqueue RX work (new connection, handshake completion, credit grants);
//! - readability of every connected socketpair fd (daemon→guest data).
//!
//! On wakeup it runs the existing injection path (`poll_vsock_rx`), raises
//! `INT_VRING`, and force-exits vCPUs via `hv_vcpus_exit` so a WFI-idle
//! guest services the interrupt immediately — the same delivery scheme the
//! net-rx worker uses (ABX-367).

use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::device::{DeviceManager, DeviceType};

/// kevent backstop timeout — bounds shutdown detection and recovers wakeups
/// lost to connection-set races (snapshot vs. concurrent close).
const BACKSTOP_TIMEOUT: Duration = Duration::from_millis(10);

/// Backoff when fds are readable but injection made no progress (guest RX
/// descriptors exhausted or peer credit depleted). Level-triggered kevent
/// would otherwise return immediately and spin until the guest catches up.
const NO_PROGRESS_BACKOFF: Duration = Duration::from_millis(1);

/// VirtIO MMIO interrupt status bit for "used ring updated".
const INT_VRING: u32 = 1;

/// Resources for the vsock-io worker thread.
pub struct VsockRxWorkerContext {
    /// Device manager owning the vsock device and connection manager.
    pub device_manager: Arc<DeviceManager>,
    /// Non-blocking read end of the doorbell pipe.
    pub doorbell_rd: OwnedFd,
    /// VM shutdown flag.
    pub running: Arc<AtomicBool>,
    /// Force-exit all vCPUs from `hv_vcpu_run` (thread-safe).
    pub exit_vcpus: Arc<dyn Fn() + Send + Sync>,
}

/// Main loop for the vsock-io worker thread.
pub fn vsock_rx_worker_loop(ctx: VsockRxWorkerContext) {
    // SAFETY: kqueue() takes no arguments and returns a new fd or -1.
    let kq = unsafe { libc::kqueue() };
    if kq < 0 {
        tracing::error!(
            "vsock-io: kqueue creation failed: {}",
            std::io::Error::last_os_error()
        );
        return;
    }

    tracing::info!(
        "vsock-io worker started (doorbell fd={})",
        ctx.doorbell_rd.as_raw_fd()
    );

    let doorbell_fd = ctx.doorbell_rd.as_raw_fd();
    let conns = ctx.device_manager.vsock_connections();

    let timeout = libc::timespec {
        tv_sec: 0,
        #[allow(clippy::cast_possible_truncation)]
        tv_nsec: BACKSTOP_TIMEOUT.as_nanos() as i64,
    };

    loop {
        if !ctx.running.load(Ordering::Relaxed) {
            break;
        }

        // Register the doorbell plus a snapshot of every connected fd.
        // EV_ADD is an idempotent upsert and closed fds auto-deregister, so
        // re-submitting the snapshot each iteration is self-healing against
        // connection churn (including fd-number reuse).
        let mut changes: Vec<libc::kevent> = Vec::with_capacity(8);
        changes.push(read_event(doorbell_fd));
        {
            let snapshot = conns
                .lock()
                .map(|mgr| mgr.connected_fds())
                .unwrap_or_default();
            for (_, fd) in snapshot {
                changes.push(read_event(fd));
            }
        }

        // One syscall: submit registrations and wait for events. Stale fds
        // in the changelist surface as EV_ERROR entries, not call failures.
        let mut events: Vec<libc::kevent> = Vec::with_capacity(changes.len() + 8);
        let nchanges =
            libc::c_int::try_from(changes.len()).expect("change list bounded by open fd count");
        let nevents =
            libc::c_int::try_from(events.capacity()).expect("event list bounded by open fd count");
        // SAFETY: `changes` and `events` are live Vecs; lengths passed match
        // their allocated capacities; `timeout` outlives the call.
        let nev = unsafe {
            libc::kevent(
                kq,
                changes.as_ptr(),
                nchanges,
                events.as_mut_ptr(),
                nevents,
                &raw const timeout,
            )
        };
        if nev < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            tracing::error!("vsock-io: kevent wait failed: {err}");
            break;
        }
        // SAFETY: kevent wrote `nev` initialized entries into `events`.
        unsafe { events.set_len(nev as usize) };

        if !ctx.running.load(Ordering::Relaxed) {
            break;
        }

        // Classify events: drain the doorbell, note real fd readability.
        let mut had_fd_data = false;
        for ev in &events {
            if ev.flags & libc::EV_ERROR != 0 {
                continue; // Stale fd from a racing close — snapshot heals.
            }
            if ev.ident == doorbell_fd as usize {
                drain_doorbell(doorbell_fd);
            } else {
                had_fd_data = true;
            }
        }

        let injected = ctx.device_manager.poll_vsock_rx();
        if injected {
            ctx.device_manager
                .raise_interrupt_for(DeviceType::VirtioVsock, INT_VRING);
            (ctx.exit_vcpus)();
        } else if had_fd_data {
            // Data is buffered but the guest must free descriptors or grant
            // credit first; back off so level-triggered kevent doesn't spin.
            std::thread::sleep(NO_PROGRESS_BACKOFF);
        }
    }

    // SAFETY: `kq` is a live fd owned exclusively by this function.
    unsafe { libc::close(kq) };
    tracing::info!("vsock-io worker stopped");
}

/// Builds an `EV_ADD` read-filter registration for `fd`.
fn read_event(fd: RawFd) -> libc::kevent {
    libc::kevent {
        ident: fd as usize,
        filter: libc::EVFILT_READ,
        flags: libc::EV_ADD | libc::EV_ENABLE,
        fflags: 0,
        data: 0,
        udata: std::ptr::null_mut(),
    }
}

/// Drains all pending doorbell bytes (non-blocking read until EAGAIN).
fn drain_doorbell(fd: RawFd) {
    let mut buf = [0u8; 64];
    loop {
        // SAFETY: `fd` is the worker-owned non-blocking doorbell read end;
        // `buf` is a valid mutable buffer of the stated length.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
        if n <= 0 {
            break;
        }
    }
}
