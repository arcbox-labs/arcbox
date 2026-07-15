use super::*;
use crate::VsockHostConnections;
use std::os::unix::io::FromRawFd;

fn make_socketpair() -> (OwnedFd, OwnedFd) {
    let mut fds: [libc::c_int; 2] = [0; 2];
    let ret = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
    assert_eq!(ret, 0);
    unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
}

#[test]
fn rx_ops_priority_order() {
    let mut ops = RxOps::default();
    ops.enqueue(RxOps::RESET);
    ops.enqueue(RxOps::REQUEST);
    ops.enqueue(RxOps::RW);
    ops.enqueue(RxOps::CREDIT_UPDATE);

    // Dequeue in priority order: Request → Rw → CreditUpdate → Reset
    assert_eq!(ops.dequeue(), RxOps::REQUEST);
    assert_eq!(ops.dequeue(), RxOps::RW);
    assert_eq!(ops.dequeue(), RxOps::CREDIT_UPDATE);
    assert_eq!(ops.dequeue(), RxOps::RESET);
    assert_eq!(ops.dequeue(), 0);
}

#[test]
fn rx_ops_dedup() {
    let mut ops = RxOps::default();
    ops.enqueue(RxOps::RW);
    ops.enqueue(RxOps::RW);
    ops.enqueue(RxOps::RW);

    assert_eq!(ops.dequeue(), RxOps::RW);
    assert_eq!(ops.dequeue(), 0); // Only one dequeue despite 3 enqueues.
}

#[test]
fn allocate_unique_host_ports() {
    let mut mgr = VsockConnectionManager::new();
    let (_, internal1) = make_socketpair();
    let (_, internal2) = make_socketpair();

    let (id1, _rx1) = mgr.allocate(1024, 3, internal1);
    let (id2, _rx2) = mgr.allocate(1024, 3, internal2);

    assert_ne!(id1.host_port, id2.host_port);
    assert_eq!(id1.guest_port, 1024);
    assert_eq!(id2.guest_port, 1024);
    assert_eq!(mgr.len(), 2);
}

#[test]
fn allocate_enqueues_request() {
    let mut mgr = VsockConnectionManager::new();
    let (_, internal) = make_socketpair();
    let (id, _rx) = mgr.allocate(1024, 3, internal);

    // Should be in backend_rxq.
    assert_eq!(mgr.backend_rxq.len(), 1);
    assert_eq!(mgr.backend_rxq[0], id);

    // Connection should have Request pending.
    let conn = mgr.get(&id).unwrap();
    assert_eq!(conn.rx_queue.peek(), RxOps::REQUEST);
    assert!(!conn.connect);
}

#[test]
fn connected_fds_only_returns_connected() {
    let mut mgr = VsockConnectionManager::new();
    let (_, internal1) = make_socketpair();
    let (_, internal2) = make_socketpair();

    let (id1, _rx1) = mgr.allocate(1024, 3, internal1);
    let (_id2, _rx2) = mgr.allocate(1024, 3, internal2);

    assert!(mgr.connected_fds().is_empty());

    mgr.mark_connected(id1.guest_port, id1.host_port);
    let fds = mgr.connected_fds();
    assert_eq!(fds.len(), 1);
    assert_eq!(fds[0].0, id1);
}

#[test]
fn remove_closes_fd() {
    let mut mgr = VsockConnectionManager::new();
    let (peer, internal) = make_socketpair();
    let peer_raw = peer.as_raw_fd();
    let (id, _rx) = mgr.allocate(1024, 3, internal);

    mgr.mark_connected(id.guest_port, id.host_port);
    assert!(mgr.fd_for(1024, id.host_port).is_some());

    mgr.remove_connection(id.guest_port, id.host_port);
    assert!(mgr.fd_for(1024, id.host_port).is_none());
    assert_eq!(mgr.len(), 0);

    // Removal drops the manager's `internal_fd`, closing that end of the
    // socketpair; the peer end we still hold then reads EOF. Observing the
    // close through the peer (rather than probing the raw fd number, which a
    // parallel test can reuse the instant it closes) keeps this deterministic.
    let mut buf = [0u8; 1];
    let n = unsafe { libc::read(peer_raw, buf.as_mut_ptr().cast(), buf.len()) };
    assert_eq!(n, 0);
}

#[test]
fn credit_flow_control() {
    let mut mgr = VsockConnectionManager::new();
    let (_, internal) = make_socketpair();
    let (id, _rx) = mgr.allocate(1024, 3, internal);

    // Simulate guest advertising 128KB buffer.
    let conn = mgr.get_mut(&id).unwrap();
    conn.update_peer_credit(128 * 1024, 0);
    assert_eq!(conn.peer_avail_credit(), 128 * 1024);

    // After sending 64KB to guest, available credit drops.
    conn.record_rx(64 * 1024);
    assert_eq!(conn.peer_avail_credit(), 64 * 1024);

    // Guest forwards 32KB.
    conn.update_peer_credit(128 * 1024, 32 * 1024);
    assert_eq!(conn.peer_avail_credit(), 96 * 1024);
}

#[test]
fn fwd_cnt_triggers_credit_update() {
    let mut mgr = VsockConnectionManager::new();
    let (_, internal) = make_socketpair();
    let (id, _rx) = mgr.allocate(1024, 3, internal);

    // Drain the initial REQUEST from rx_queue.
    let conn = mgr.get_mut(&id).unwrap();
    conn.rx_queue.dequeue();

    // Write past CREDIT_UPDATE_THRESHOLD (4 KB) → should trigger CreditUpdate.
    conn.advance_fwd_cnt(CREDIT_UPDATE_THRESHOLD);
    assert_eq!(conn.rx_queue.peek(), RxOps::CREDIT_UPDATE);
}

#[test]
fn fwd_cnt_below_threshold_does_not_trigger_credit_update() {
    let mut mgr = VsockConnectionManager::new();
    let (_, internal) = make_socketpair();
    let (id, _rx) = mgr.allocate(1024, 3, internal);
    let conn = mgr.get_mut(&id).unwrap();
    conn.rx_queue.dequeue();

    // One byte below threshold must NOT enqueue an update.
    conn.advance_fwd_cnt(CREDIT_UPDATE_THRESHOLD - 1);
    assert!(!conn.rx_queue.pending());
}

#[test]
fn maybe_request_credit_fires_below_half_window() {
    let mut mgr = VsockConnectionManager::new();
    let (_, internal) = make_socketpair();
    let (id, _rx) = mgr.allocate(1024, 3, internal);
    let conn = mgr.get_mut(&id).unwrap();
    conn.rx_queue.dequeue(); // drain REQUEST

    conn.update_peer_credit(8192, 0);
    conn.record_rx(5000); // avail = 8192 - 5000 = 3192, below half (4096)
    conn.maybe_request_credit();

    assert_eq!(conn.rx_queue.peek(), RxOps::CREDIT_REQUEST);
    assert!(conn.credit_request_pending());
}

#[test]
fn maybe_request_credit_noop_above_half_window() {
    let mut mgr = VsockConnectionManager::new();
    let (_, internal) = make_socketpair();
    let (id, _rx) = mgr.allocate(1024, 3, internal);
    let conn = mgr.get_mut(&id).unwrap();
    conn.rx_queue.dequeue();

    conn.update_peer_credit(8192, 0);
    conn.record_rx(3000); // avail = 5192, above half (4096)
    conn.maybe_request_credit();

    assert!(!conn.rx_queue.pending());
    assert!(!conn.credit_request_pending());
}

#[test]
fn maybe_request_credit_dedupes_while_pending() {
    let mut mgr = VsockConnectionManager::new();
    let (_, internal) = make_socketpair();
    let (id, _rx) = mgr.allocate(1024, 3, internal);
    let conn = mgr.get_mut(&id).unwrap();
    conn.rx_queue.dequeue();

    conn.update_peer_credit(8192, 0);
    conn.record_rx(5000);
    conn.maybe_request_credit();
    // Dequeue the first request so we can see if a duplicate fires.
    conn.rx_queue.dequeue();

    conn.record_rx(100); // still below half, still pending
    conn.maybe_request_credit();

    assert!(!conn.rx_queue.pending(), "second request would be a dup");
}

#[test]
fn update_peer_credit_clears_pending_flag() {
    let mut mgr = VsockConnectionManager::new();
    let (_, internal) = make_socketpair();
    let (id, _rx) = mgr.allocate(1024, 3, internal);
    let conn = mgr.get_mut(&id).unwrap();
    conn.rx_queue.dequeue();

    conn.update_peer_credit(8192, 0);
    conn.record_rx(5000);
    conn.maybe_request_credit();
    assert!(conn.credit_request_pending());

    // Peer answers with a fresh fwd_cnt; pending should clear. The
    // already-enqueued CREDIT_REQUEST op stays in rx_queue — sending it
    // is harmless (peer just replies with another CREDIT_UPDATE) and not
    // worth a bit-clearing helper on RxOps.
    conn.update_peer_credit(8192, 5000);
    assert!(!conn.credit_request_pending());

    // Drain the stale CREDIT_REQUEST to simulate the next RX tick.
    assert_eq!(conn.rx_queue.dequeue(), RxOps::CREDIT_REQUEST);

    // Now that we're at full credit, maybe_request_credit stays quiet.
    conn.maybe_request_credit();
    assert!(!conn.rx_queue.pending());
    assert!(!conn.credit_request_pending());
}

#[test]
fn shutdown_both_bits_removes_connection() {
    let mut mgr = VsockConnectionManager::new();
    let (_, internal) = make_socketpair();
    let (id, _rx) = mgr.allocate(1024, 3, internal);
    assert!(mgr.get(&id).is_some());

    mgr.handle_shutdown(id.guest_port, id.host_port, VSOCK_SHUTDOWN_F_BOTH);
    assert!(mgr.get(&id).is_none());
}

#[test]
fn shutdown_receive_bit_marks_half_close() {
    let mut mgr = VsockConnectionManager::new();
    let (_, internal) = make_socketpair();
    let (id, _rx) = mgr.allocate(1024, 3, internal);

    mgr.handle_shutdown(id.guest_port, id.host_port, VSOCK_SHUTDOWN_F_RECEIVE);
    let conn = mgr.get(&id).expect("conn must survive half-close");
    assert!(conn.peer_no_recv());
    assert!(!conn.accepts_data() || !conn.connect); // connect=false initially
}

#[test]
fn shutdown_send_bit_only_is_informational() {
    let mut mgr = VsockConnectionManager::new();
    let (_, internal) = make_socketpair();
    let (id, _rx) = mgr.allocate(1024, 3, internal);

    mgr.handle_shutdown(id.guest_port, id.host_port, VSOCK_SHUTDOWN_F_SEND);
    let conn = mgr.get(&id).expect("conn must survive");
    assert!(
        !conn.peer_no_recv(),
        "F_SEND alone does not block host→peer RW"
    );
}

#[test]
fn shutdown_send_bit_propagates_eof_to_daemon_fd() {
    // Regression for ABX-372: F_SEND half-close must translate into a
    // SHUT_WR on the internal socketpair end so the daemon-side fd reads
    // EOF. Without this, the Docker attach bridge (`copy_bidirectional`)
    // stalls forever after the container exits.
    use std::io::Read;
    use std::os::fd::IntoRawFd;

    let mut mgr = VsockConnectionManager::new();
    let (daemon_end, internal) = make_socketpair();
    let (id, _rx) = mgr.allocate(1024, 3, internal);

    // Wrap the daemon end in a blocking `UnixStream` for `read`.
    let mut daemon_stream =
        unsafe { std::os::unix::net::UnixStream::from_raw_fd(daemon_end.into_raw_fd()) };
    // Bound the read so a regression doesn't hang the test runner.
    daemon_stream
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .unwrap();

    // Before the half-close, the daemon's read blocks. After F_SEND
    // handling, it must return 0 (EOF).
    mgr.handle_shutdown(id.guest_port, id.host_port, VSOCK_SHUTDOWN_F_SEND);

    let mut buf = [0u8; 8];
    let n = daemon_stream
        .read(&mut buf)
        .expect("read on daemon fd should not error");
    assert_eq!(n, 0, "daemon fd must read EOF after F_SEND propagation");

    // Reverse direction stays open: daemon can still write to the peer.
    use std::io::Write;
    daemon_stream
        .write_all(b"still-alive")
        .expect("daemon→internal write should still succeed");
}

#[test]
fn doorbell_rings_on_producer_paths() {
    use std::sync::atomic::AtomicUsize;

    let rings = Arc::new(AtomicUsize::new(0));
    let mut mgr = VsockConnectionManager::new();
    let rings_cb = Arc::clone(&rings);
    mgr.set_doorbell(Arc::new(move || {
        rings_cb.fetch_add(1, Ordering::SeqCst);
    }));

    let (_, internal) = make_socketpair();
    let (id, _rx) = mgr.allocate(1024, 3, internal);
    assert_eq!(rings.load(Ordering::SeqCst), 1, "allocate rings");

    mgr.mark_connected(id.guest_port, id.host_port);
    assert_eq!(rings.load(Ordering::SeqCst), 2, "mark_connected rings");

    mgr.enqueue_credit_update(id.guest_port, id.host_port);
    assert_eq!(
        rings.load(Ordering::SeqCst),
        3,
        "enqueue_credit_update rings"
    );

    // advance_fwd_cnt rings only when it actually enqueues RX work.
    assert!(mgr.advance_fwd_cnt(id.guest_port, id.host_port, CREDIT_UPDATE_THRESHOLD));
    assert_eq!(
        rings.load(Ordering::SeqCst),
        4,
        "advance_fwd_cnt rings on push"
    );
}

#[test]
fn doorbell_silent_on_injection_driver_paths() {
    use std::sync::atomic::AtomicUsize;

    let rings = Arc::new(AtomicUsize::new(0));
    let mut mgr = VsockConnectionManager::new();

    let (_, internal) = make_socketpair();
    let (id, _rx) = mgr.allocate(1024, 3, internal);
    // Drain the initial REQUEST so rx_queue is empty for the checks below.
    mgr.get_mut(&id).unwrap().rx_queue.dequeue();

    // Install the doorbell after allocate so only the calls below count.
    let rings_cb = Arc::clone(&rings);
    mgr.set_doorbell(Arc::new(move || {
        rings_cb.fetch_add(1, Ordering::SeqCst);
    }));

    // Sub-threshold fwd_cnt advance enqueues nothing → no ring.
    assert!(!mgr.advance_fwd_cnt(id.guest_port, id.host_port, 1));
    assert_eq!(rings.load(Ordering::SeqCst), 0);

    // Phase-1 enqueues come from the injection driver itself — it is
    // already awake, so these must not self-wake it.
    mgr.enqueue_rw(id);
    mgr.enqueue_reset(id);
    assert_eq!(rings.load(Ordering::SeqCst), 0);
}

#[test]
fn shutdown_flags_zero_removes_connection_conservatively() {
    // flags=0 is spec-invalid; worst-case interpretation is full close.
    let mut mgr = VsockConnectionManager::new();
    let (_, internal) = make_socketpair();
    let (id, _rx) = mgr.allocate(1024, 3, internal);

    mgr.handle_shutdown(id.guest_port, id.host_port, 0);
    assert!(mgr.get(&id).is_none());
}
