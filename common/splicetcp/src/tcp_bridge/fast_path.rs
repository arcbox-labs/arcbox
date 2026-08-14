use super::{FastPathConn, GSO_SEGMENT_MSS, SynFlowKey, TCP_MIN_MSS, TcpBridge};
use crate::ethernet::ETH_HEADER_LEN;
use std::net::Ipv4Addr;

/// Frame-construction context shared by the first-transmission and
/// retransmission paths of `poll_fast_path`.
struct FrameCtx {
    large_frames: bool,
    guest_mss: usize,
    gw_mac: [u8; 6],
    guest_mac: [u8; 6],
}

/// Builds guest-bound TCP data frames for `data` starting at `seq_start`:
/// one GSO-style frame when enabled and the peer accepts 1460-byte
/// segments, MSS-clamped segmentation otherwise (each emitted IP packet
/// must fit every link on the path — e.g. a 1500-MTU docker bridge behind
/// a 4000-MTU eth0). Does NOT advance `conn.our_seq` — retransmissions
/// re-emit already-consumed sequence space.
fn emit_data_frames(
    ctx: &FrameCtx,
    conn: &FastPathConn,
    seq_start: u32,
    data: &[u8],
    frames: &mut Vec<Vec<u8>>,
) {
    if ctx.large_frames && conn.peer_mss >= GSO_SEGMENT_MSS {
        let large = ETH_HEADER_LEN + 40 + data.len() > 1500;
        let params = crate::ethernet::TcpFrameParams {
            src_ip: conn.remote_ip,
            dst_ip: conn.guest_ip,
            src_port: conn.remote_port,
            dst_port: conn.guest_port,
            seq: seq_start,
            ack: conn.last_ack,
            window: 65535,
            src_mac: ctx.gw_mac,
            dst_mac: ctx.guest_mac,
        };
        frames.push(if large {
            crate::ethernet::build_tcp_data_frame_partial_csum(&params, data)
        } else {
            crate::ethernet::build_tcp_data_frame(&params, data)
        });
        return;
    }
    let seg = ctx
        .guest_mss
        .min(usize::from(conn.peer_mss.max(TCP_MIN_MSS)));
    let mut offset = 0;
    while offset < data.len() {
        let chunk_end = (offset + seg).min(data.len());
        frames.push(crate::ethernet::build_tcp_data_frame(
            &crate::ethernet::TcpFrameParams {
                src_ip: conn.remote_ip,
                dst_ip: conn.guest_ip,
                src_port: conn.remote_port,
                dst_port: conn.guest_port,
                seq: seq_start.wrapping_add(offset as u32),
                ack: conn.last_ack,
                window: 65535,
                src_mac: ctx.gw_mac,
                dst_mac: ctx.guest_mac,
            },
            &data[offset..chunk_end],
        ));
        offset = chunk_end;
    }
}

impl TcpBridge {
    /// Checks if a TCP frame matches a fast-path connection.
    ///
    /// Called from the classifier's `drain_fast_path`. Returns
    /// `Some(ack_frame)` if the frame was handled (payload written to
    /// host stream, ACK generated), or `None` if not a fast-path match.
    pub fn try_fast_path_intercept(&mut self, frame: &[u8]) -> Option<Vec<u8>> {
        if frame.len() < ETH_HEADER_LEN + 40 {
            return None; // Too short for ETH + IP + TCP minimum
        }

        let ip_start = ETH_HEADER_LEN;
        let protocol = frame[ip_start + 9];
        if protocol != 6 {
            return None; // Not TCP
        }

        let ihl = ((frame[ip_start] & 0x0F) as usize) * 4;
        let l4_start = ip_start + ihl;
        // IHL < 20 would collapse l4_start into the IP header, so every TCP
        // field below (ports, seq/ack, flags) would be read from IP bytes.
        if ihl < 20 || frame.len() < l4_start + 20 {
            return None;
        }

        let src_ip = Ipv4Addr::new(
            frame[ip_start + 12],
            frame[ip_start + 13],
            frame[ip_start + 14],
            frame[ip_start + 15],
        );
        let dst_ip = Ipv4Addr::new(
            frame[ip_start + 16],
            frame[ip_start + 17],
            frame[ip_start + 18],
            frame[ip_start + 19],
        );
        let src_port = u16::from_be_bytes([frame[l4_start], frame[l4_start + 1]]);
        let dst_port = u16::from_be_bytes([frame[l4_start + 2], frame[l4_start + 3]]);
        let flags = frame[l4_start + 13];

        let key = SynFlowKey {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
        };

        let conn = self.fast_path_conns.get_mut(&key)?;
        // Any guest frame for the flow — data, ACK, dup-ACK, even a bare
        // window probe — is its sign of life for the dead-flow reaper.
        conn.last_guest_activity = std::time::Instant::now();

        let guest_seq = u32::from_be_bytes([
            frame[l4_start + 4],
            frame[l4_start + 5],
            frame[l4_start + 6],
            frame[l4_start + 7],
        ]);

        // FIN or RST → handle teardown ourselves.
        if flags & 0x04 != 0 {
            // RST: close host stream immediately, no response needed.
            tracing::debug!("Fast path: RST from guest {src_ip}:{src_port}→{dst_ip}:{dst_port}");
            self.close_fast_path(&key);
            return Some(Vec::new()); // Intercepted, no reply frame.
        }

        // Extract payload using IPv4 total_length to exclude Ethernet padding.
        // NOTE: FIN check is deferred until after payload write — RFC 793
        // allows FIN segments to carry data.
        let ip_total_len = u16::from_be_bytes([frame[ip_start + 2], frame[ip_start + 3]]) as usize;
        let ip_end = ip_start + ip_total_len;
        let tcp_data_offset = ((frame[l4_start + 12] >> 4) as usize) * 4;
        // The data offset must cover the 20-byte TCP header; a smaller value
        // would splice TCP header bytes into the payload written to the host.
        if tcp_data_offset < 20 || l4_start + tcp_data_offset > frame.len() {
            return None;
        }
        let payload_start = l4_start + tcp_data_offset;
        let payload_end = ip_end.min(frame.len());
        let payload_len = payload_end.saturating_sub(payload_start);

        // Download flow control: every guest frame carrying ACK updates our
        // view of how much of OUR stream it received and how much receive
        // window it advertises. Monotonic on the ack (a reordered frame
        // must not regress it); the window rides along with the newest ack,
        // and an equal ack still applies it (pure window updates). A pure
        // ACK repeating the same ack AND window while our data is in flight
        // is a duplicate ACK — three of them mean the guest is missing a
        // frame and triggers fast retransmit in `poll_fast_path`.
        if flags & 0x10 != 0 {
            let guest_ack = u32::from_be_bytes([
                frame[l4_start + 8],
                frame[l4_start + 9],
                frame[l4_start + 10],
                frame[l4_start + 11],
            ]);
            let current = conn.guest_acked.load(std::sync::atomic::Ordering::Relaxed);
            let advance = guest_ack.wrapping_sub(current);
            // Reject an ACK beyond what we actually sent (RFC 793: an ACK
            // must not cover data past SND.NXT). Accepting one would let
            // poll_fast_path drain retransmit_buf past real in-flight bytes
            // and move retransmit_seq beyond our_seq, so those bytes could
            // never be retransmitted — the flow would truncate or wedge.
            let sent = conn.our_seq.load(std::sync::atomic::Ordering::Relaxed);
            let beyond_sent =
                guest_ack.wrapping_sub(sent) != 0 && guest_ack.wrapping_sub(sent) < 0x8000_0000;
            if advance < 0x8000_0000 && !beyond_sent {
                let scaled_win = u32::from(u16::from_be_bytes([
                    frame[l4_start + 14],
                    frame[l4_start + 15],
                ])) << conn.guest_wscale;
                // FIN|SYN|RST all clear — `trailing_zeros` (clippy's
                // suggestion) would obscure that this is a flag test.
                let plain_ack = flags & (0x01 | 0x02 | 0x04) == 0;
                if advance == 0
                    && payload_len == 0
                    && plain_ack
                    && scaled_win == conn.guest_window.load(std::sync::atomic::Ordering::Relaxed)
                {
                    let in_flight = sent.wrapping_sub(guest_ack);
                    if in_flight > 0 && in_flight < 0x8000_0000 {
                        conn.dup_acks = conn.dup_acks.saturating_add(1);
                        if conn.dup_acks >= 3 {
                            conn.fast_retransmit = true;
                        }
                    }
                } else if advance > 0 {
                    conn.dup_acks = 0;
                }
                conn.guest_acked
                    .store(guest_ack, std::sync::atomic::Ordering::Relaxed);
                conn.guest_window
                    .store(scaled_win, std::sync::atomic::Ordering::Relaxed);
            }
        }

        // Write payload to host stream (if any). The invariant that keeps
        // uploads lossless: `last_ack` advances ONLY over bytes actually
        // written, in order, to the host socket. Everything else
        // (WouldBlock, the unwritten tail of a short write) stays un-ACKed,
        // so the guest's own fast-retransmit/RTO machinery repairs the
        // stream — dup-ACKs from the fall-through below are the recovery
        // signal. ACKing past unwritten bytes is how uploads silently lost
        // data (2026-07-19). Out-of-order segments are parked un-ACKed in
        // `ooo_segs` and written once the hole before them fills — parking
        // (vs the old drop) is what keeps one lost frame from forcing the
        // guest to retransmit the entire in-flight window.
        let mut in_order_advanced = false;
        if payload_len > 0 {
            use std::io::Write;
            let seq_end = guest_seq.wrapping_add(payload_len as u32);
            // Bytes this segment extends past our contiguous cursor.
            let extends = seq_end.wrapping_sub(conn.last_ack);
            if extends == 0 || extends >= 0x8000_0000 {
                // Entirely at or behind the cursor — a retransmit of data
                // we already ACKed. Skip the write, fall through to re-ACK.
                tracing::trace!(
                    "Fast path TX: {src_ip}:{src_port}→{dst_ip}:{dst_port} retransmit (guest_seq={guest_seq}, last_ack={}, payload={payload_len})",
                    conn.last_ack
                );
            } else {
                // Leading bytes already ACKed (partial retransmit overlap).
                let overlap = conn.last_ack.wrapping_sub(guest_seq);
                if overlap >= 0x8000_0000 {
                    // guest_seq is ahead of the cursor: a hole precedes this
                    // segment. Writing it now would corrupt the byte stream
                    // and ACKing it would bury the hole forever. Park it
                    // (bounded) for delivery once the hole fills; leave
                    // last_ack alone — the ACK below is a dup-ACK, which is
                    // exactly what makes the guest fast-retransmit the gap.
                    conn.up_out_of_order += 1;
                    conn.buffer_ooo_segment(guest_seq, &frame[payload_start..payload_end]);
                } else {
                    let fresh = &frame[payload_start + overlap as usize..payload_end];
                    match conn.stream.write(fresh) {
                        Ok(n) => {
                            conn.up_bytes += n as u64;
                            conn.set_last_ack(conn.last_ack.wrapping_add(n as u32));
                            in_order_advanced = true;
                            if n < fresh.len() {
                                // Host socket buffer filled mid-segment: ACK
                                // covers only what was written; the guest
                                // retransmits the tail.
                                conn.up_short_writes += 1;
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            // Nothing written, nothing ACKed. Fall through to
                            // the dup-ACK so the guest fast-retransmits once
                            // the socket drains, instead of waiting out RTO.
                            conn.up_would_block += 1;
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {
                            // Peer closed; inject already relayed FIN. ACK at
                            // TCP layer so the guest stops retransmitting.
                            conn.set_last_ack(seq_end);
                            in_order_advanced = true;
                            tracing::debug!(
                                "Fast path TX: {src_ip}:{src_port}→{dst_ip}:{dst_port} Broken pipe, draining {payload_len} bytes"
                            );
                        }
                        Err(e) => {
                            tracing::warn!("Fast path TX write error, RST to guest: {e}");
                            // Mirror the RX-error path: the host stream is dead,
                            // so tear the guest side down with RST instead of
                            // leaving it ESTABLISHED forever (ABX-431).
                            let rst = crate::ethernet::build_tcp_rst_frame(
                                &crate::ethernet::TcpFrameParams {
                                    src_ip: conn.remote_ip,
                                    dst_ip: conn.guest_ip,
                                    src_port: conn.remote_port,
                                    dst_port: conn.guest_port,
                                    seq: conn.our_seq.load(std::sync::atomic::Ordering::Relaxed),
                                    ack: conn.last_ack,
                                    window: 0,
                                    src_mac: self.fast_path_gateway_mac,
                                    dst_mac: self.fast_path_guest_mac.unwrap_or([0xFF; 6]),
                                },
                            );
                            self.close_fast_path(&key);
                            return Some(rst);
                        }
                    }
                }
            }
        }

        // A cursor advance may have landed right behind parked out-of-order
        // segments — flush them now so the ACK below leaps over everything
        // contiguous instead of forcing the guest to retransmit data that
        // already arrived.
        if in_order_advanced
            && !conn.ooo_segs.is_empty()
            && let Err(e) = conn.drain_parked_segments()
        {
            tracing::warn!("Fast path TX drain error, RST to guest: {e}");
            let rst = crate::ethernet::build_tcp_rst_frame(&crate::ethernet::TcpFrameParams {
                src_ip: conn.remote_ip,
                dst_ip: conn.guest_ip,
                src_port: conn.remote_port,
                dst_port: conn.guest_port,
                seq: conn.our_seq.load(std::sync::atomic::Ordering::Relaxed),
                ack: conn.last_ack,
                window: 0,
                src_mac: self.fast_path_gateway_mac,
                dst_mac: self.fast_path_guest_mac.unwrap_or([0xFF; 6]),
            });
            self.close_fast_path(&key);
            return Some(rst);
        }

        // FIN handling — only once every byte before it has been written and
        // ACKed. A FIN whose sequence position is beyond `last_ack` (data
        // still missing, or its own payload only partially written) must not
        // tear anything down: closing here would cut off the retransmissions
        // that repair the gap, truncating the upload. The guest re-sends the
        // gap and the FIN; until then it gets the dup-ACK below.
        if flags & 0x01 != 0 {
            let fin_seq = guest_seq.wrapping_add(payload_len as u32);
            if fin_seq == conn.last_ack {
                // FIN consumes 1 sequence number (in addition to any data
                // bytes already accounted for above).
                conn.set_last_ack(conn.last_ack.wrapping_add(1));
                let guest_mac = self.fast_path_guest_mac.unwrap_or([0xFF; 6]);
                // Non-inline flow whose host side is still open: a genuine
                // half-close. Shut only the upstream's receive side (the guest
                // will send no more), keep relaying host→guest until the host
                // EOFs on its own (poll then emits OUR FIN), and just ACK the
                // FIN here — reaping happens in poll once both sides are closed.
                // A full close here would truncate the still-in-flight response
                // and, with unread bytes buffered, RST the real upstream.
                // Inline flows (whose reader owns host→guest) and flows where
                // the host already closed fall through to the full teardown.
                if !conn.host_eof && !conn.inline_owned {
                    tracing::debug!(
                        "Fast path: guest half-close {src_ip}:{src_port}→{dst_ip}:{dst_port}"
                    );
                    let _ = conn.stream.shutdown(std::net::Shutdown::Write);
                    conn.guest_fin_at = Some(std::time::Instant::now());
                    let ack =
                        crate::ethernet::build_tcp_ack_frame(&crate::ethernet::TcpFrameParams {
                            src_ip: conn.remote_ip,
                            dst_ip: conn.guest_ip,
                            src_port: conn.remote_port,
                            dst_port: conn.guest_port,
                            seq: conn.our_seq.load(std::sync::atomic::Ordering::Relaxed),
                            ack: conn.last_ack,
                            window: 65535,
                            src_mac: self.fast_path_gateway_mac,
                            dst_mac: guest_mac,
                        });
                    return Some(ack);
                }
                tracing::debug!(
                    "Fast path: FIN from guest {src_ip}:{src_port}→{dst_ip}:{dst_port}"
                );
                let fin_ack =
                    crate::ethernet::build_tcp_fin_frame(&crate::ethernet::TcpFrameParams {
                        src_ip: conn.remote_ip,
                        dst_ip: conn.guest_ip,
                        src_port: conn.remote_port,
                        dst_port: conn.guest_port,
                        seq: conn.our_seq.load(std::sync::atomic::Ordering::Relaxed),
                        ack: conn.last_ack,
                        window: 65535,
                        src_mac: self.fast_path_gateway_mac,
                        dst_mac: guest_mac,
                    });
                self.close_fast_path(&key);
                return Some(fin_ack);
            }
            tracing::debug!(
                "Fast path: FIN from guest {src_ip}:{src_port}→{dst_ip}:{dst_port} deferred (fin_seq={fin_seq}, last_ack={})",
                conn.last_ack
            );
        }

        // Only ACK frames that carried payload, a deferred FIN, or a SYN.
        // Replying to a pure ACK would create a dup-ACK loop that triggers
        // fast retransmits on the peer and tanks host→VM throughput. A
        // retransmitted SYN-ACK (the guest never saw our completing ACK, common
        // on the inbound ActiveOpen path) is the one no-payload-no-FIN frame we
        // must still ACK, or the guest retransmits until it times out — any
        // data or FIN it carried was already handled by the paths above, so it
        // is never dropped.
        if payload_len == 0 && flags & (0x01 | 0x02) == 0 {
            return Some(Vec::new());
        }

        let guest_mac = self.fast_path_guest_mac.unwrap_or([0xFF; 6]);
        let ack = crate::ethernet::build_tcp_ack_frame(&crate::ethernet::TcpFrameParams {
            src_ip: conn.remote_ip,
            dst_ip: conn.guest_ip,
            src_port: conn.remote_port,
            dst_port: conn.guest_port,
            seq: conn.our_seq.load(std::sync::atomic::Ordering::Relaxed),
            ack: conn.last_ack,
            window: 65535,
            src_mac: self.fast_path_gateway_mac,
            dst_mac: guest_mac,
        });

        Some(ack)
    }

    /// Polls fast-path host streams for readable data and generates frames
    /// to inject into the guest.
    ///
    /// Returns frames to be written to the guest FD via `enqueue_or_write`.
    pub fn poll_fast_path(&mut self) -> Vec<Vec<u8>> {
        let mut frames = Vec::new();
        let mut to_remove = Vec::new();
        let guest_mac = self.fast_path_guest_mac.unwrap_or([0xFF; 6]);
        let gw_mac = self.fast_path_gateway_mac;
        let ctx = FrameCtx {
            large_frames: self.large_frames_enabled,
            guest_mss: self.fast_path_guest_mss,
            gw_mac,
            guest_mac,
        };
        let now = std::time::Instant::now();
        let dead_flow_timeout = self.dead_flow_timeout;

        for (key, conn) in &mut self.fast_path_conns {
            if conn.inline_owned {
                // The inline inject thread owns the socket. It marks the
                // flow dead only after RST-terminating the guest on an
                // upstream ERROR — reap the entry here, since the guest
                // sends no further frames for it (ABX-431). After a clean
                // EOF the flag stays unset and the entry survives so the
                // guest's ACK/FIN and half-close writes still reach
                // try_fast_path_intercept (parity with the non-inline
                // path's host_eof handling).
                if conn
                    .dead
                    .as_ref()
                    .is_some_and(|d| d.load(std::sync::atomic::Ordering::Relaxed))
                {
                    to_remove.push(*key);
                    continue;
                }

                // Zero-window persist for the inline path. The inject thread /
                // direct_rx reader stops reading at a zero send budget and can't
                // probe on its own, so a lost guest window-update ACK would
                // deadlock the download forever. Emit a keepalive-style probe —
                // one byte at `our_seq - 1`, an old duplicate — which a
                // zero-window guest must answer with a window-bearing ACK
                // (RFC 793 §3.9). It consumes no sequence space and touches no
                // shared state, so a lost probe is harmlessly re-sent next
                // interval with no stream gap (the inline path has no
                // retransmit). Gated on nothing-in-flight: the guest has ACKed
                // up to `our_seq`, so `our_seq - 1` is always an old byte, and
                // any in-flight data would elicit its own window-bearing ACKs.
                let sent = conn.our_seq.load(std::sync::atomic::Ordering::Relaxed);
                let acked = conn.guest_acked.load(std::sync::atomic::Ordering::Relaxed);
                let window = conn
                    .guest_window
                    .load(std::sync::atomic::Ordering::Relaxed)
                    .min(super::HONORED_WINDOW_CAP);
                let in_flight = sent.wrapping_sub(acked);
                let nothing_in_flight = in_flight == 0 || in_flight >= 0x8000_0000;
                // Dead-flow give-up: the inline path has no RTO, so a guest
                // that vanished with data in flight freezes the send budget
                // and would hold the entry, host fd, and owner task forever
                // (the persist probe below never fires while bytes are
                // outstanding). Soliciting = unACKed data outstanding or a
                // closed window under persist; either demands a guest reply,
                // so prolonged unanswered soliciting means the endpoint is
                // gone. Both clocks must be stale — the soliciting clock
                // starts fresh when a long-idle flow's owner resumes sending,
                // so its guest gets the full deadline to answer.
                let soliciting = !nothing_in_flight || conn.window_stalled_at.is_some();
                if !soliciting {
                    conn.soliciting_since = None;
                } else if conn.soliciting_since.is_none() {
                    conn.soliciting_since = Some(now);
                }
                if conn
                    .soliciting_since
                    .is_some_and(|since| now.duration_since(since) >= dead_flow_timeout)
                    && now.duration_since(conn.last_guest_activity) >= dead_flow_timeout
                {
                    tracing::warn!(
                        "Fast path: guest silent {:?} on soliciting inline flow {}:{} → {}:{}, RST + reap",
                        dead_flow_timeout,
                        key.src_ip,
                        key.src_port,
                        key.dst_ip,
                        key.dst_port,
                    );
                    frames.push(crate::ethernet::build_tcp_rst_frame(
                        &crate::ethernet::TcpFrameParams {
                            src_ip: conn.remote_ip,
                            dst_ip: conn.guest_ip,
                            src_port: conn.remote_port,
                            dst_port: conn.guest_port,
                            seq: sent,
                            ack: conn.last_ack,
                            window: 0,
                            src_mac: gw_mac,
                            dst_mac: guest_mac,
                        },
                    ));
                    to_remove.push(*key);
                    continue;
                }
                if super::send_budget(sent, acked, window) == 0 && nothing_in_flight {
                    match conn.window_stalled_at {
                        None => conn.window_stalled_at = Some(now),
                        Some(at)
                            if now.duration_since(at) >= super::ZERO_WINDOW_PERSIST_INTERVAL =>
                        {
                            conn.window_stalled_at = Some(now);
                            frames.push(crate::ethernet::build_tcp_data_frame(
                                &crate::ethernet::TcpFrameParams {
                                    src_ip: conn.remote_ip,
                                    dst_ip: conn.guest_ip,
                                    src_port: conn.remote_port,
                                    dst_port: conn.guest_port,
                                    seq: sent.wrapping_sub(1),
                                    ack: conn.last_ack,
                                    window: 65535,
                                    src_mac: gw_mac,
                                    dst_mac: guest_mac,
                                },
                                &[0u8],
                            ));
                        }
                        Some(_) => {}
                    }
                } else {
                    conn.window_stalled_at = None;
                }
                continue;
            }
            // A half-closed non-inline flow is fully done once the host has
            // also EOF'd (our FIN was sent) and the guest ACKed that FIN.
            if let Some(fin_at) = conn.guest_fin_at {
                if conn.host_eof {
                    if let Some(fin_seq) = conn.fin_seq {
                        let acked_past_fin = conn
                            .guest_acked
                            .load(std::sync::atomic::Ordering::Relaxed)
                            .wrapping_sub(fin_seq);
                        if (1..0x8000_0000).contains(&acked_past_fin) {
                            to_remove.push(*key);
                            continue;
                        }
                    }
                }
                // FIN_WAIT2 leak guard: the guest finished sending but the
                // upstream keeps its write side open (or the guest silently
                // dropped its FIN_WAIT2 state). The clock is refreshed on every
                // host→guest byte below, so this only fires on a truly idle
                // half-open — reap it instead of holding the entry + fd forever.
                if now.duration_since(fin_at) >= super::HALF_CLOSE_TIMEOUT {
                    tracing::debug!(
                        "Fast path: half-close idle timeout, reaping {}:{} → {}:{}",
                        key.src_ip,
                        key.src_port,
                        key.dst_ip,
                        key.dst_port,
                    );
                    to_remove.push(*key);
                    continue;
                }
            }
            // ---- Sender-side loss recovery (runs for host_eof flows too:
            // in-flight data and the FIN itself still need repair) ----
            let acked = conn.guest_acked.load(std::sync::atomic::Ordering::Relaxed);
            let drained = acked.wrapping_sub(conn.retransmit_seq);
            if drained > 0 && drained < 0x8000_0000 {
                // The guest ACKed more of our stream — release the buffered
                // prefix and reset the loss-recovery clocks.
                let n = (drained as usize).min(conn.retransmit_buf.len());
                conn.retransmit_buf.drain(..n);
                conn.retransmit_seq = acked;
                conn.last_progress = now;
                conn.rto = super::INITIAL_RTO;
                conn.dup_acks = 0;
            }
            let sent = conn.our_seq.load(std::sync::atomic::Ordering::Relaxed);
            let in_flight = sent.wrapping_sub(acked);
            // Dead-flow give-up: while soliciting (unACKed data or FIN being
            // RTO-retransmitted, or a closed window under persist probes) a
            // live guest always answers — with at least a dup-ACK or a
            // window-bearing ACK. Prolonged unanswered soliciting means the
            // guest endpoint is gone; without this the RTO path retransmits
            // forever and the entry leaks its fd and retransmission buffer.
            // Both clocks must be stale: a long-idle flow whose upstream just
            // woke up starts the soliciting clock here and now, so its guest
            // gets the full deadline to answer despite an ancient last frame.
            let soliciting =
                (in_flight > 0 && in_flight < 0x8000_0000) || conn.window_stalled_at.is_some();
            if !soliciting {
                conn.soliciting_since = None;
            } else if conn.soliciting_since.is_none() {
                conn.soliciting_since = Some(now);
            }
            if conn
                .soliciting_since
                .is_some_and(|since| now.duration_since(since) >= dead_flow_timeout)
                && now.duration_since(conn.last_guest_activity) >= dead_flow_timeout
            {
                tracing::warn!(
                    "Fast path: guest silent {:?} on soliciting flow {}:{} → {}:{}, RST + reap",
                    dead_flow_timeout,
                    key.src_ip,
                    key.src_port,
                    key.dst_ip,
                    key.dst_port,
                );
                frames.push(crate::ethernet::build_tcp_rst_frame(
                    &crate::ethernet::TcpFrameParams {
                        src_ip: conn.remote_ip,
                        dst_ip: conn.guest_ip,
                        src_port: conn.remote_port,
                        dst_port: conn.guest_port,
                        seq: sent,
                        ack: conn.last_ack,
                        window: 0,
                        src_mac: gw_mac,
                        dst_mac: guest_mac,
                    },
                ));
                to_remove.push(*key);
                continue;
            }
            if in_flight > 0 && in_flight < 0x8000_0000 {
                let timed_out = now.duration_since(conn.last_progress) >= conn.rto;
                if conn.fast_retransmit || timed_out {
                    // Resend everything from the guest's ack point: buffered
                    // data first, then the FIN if it is still unACKed. The
                    // path beyond guest eth0 (bridge → veth → container
                    // backlog) drops under burst; without this a single
                    // dropped frame wedges the flow forever.
                    let offset = acked.wrapping_sub(conn.retransmit_seq) as usize;
                    if offset < conn.retransmit_buf.len() {
                        let data: Vec<u8> =
                            conn.retransmit_buf.iter().skip(offset).copied().collect();
                        emit_data_frames(&ctx, conn, acked, &data, &mut frames);
                    }
                    if let Some(fin_seq) = conn.fin_seq
                        && sent.wrapping_sub(fin_seq) < 0x8000_0000
                        && fin_seq.wrapping_sub(acked) < 0x8000_0000
                    {
                        frames.push(crate::ethernet::build_tcp_fin_frame(
                            &crate::ethernet::TcpFrameParams {
                                src_ip: conn.remote_ip,
                                dst_ip: conn.guest_ip,
                                src_port: conn.remote_port,
                                dst_port: conn.guest_port,
                                seq: fin_seq,
                                ack: conn.last_ack,
                                window: 65535,
                                src_mac: gw_mac,
                                dst_mac: guest_mac,
                            },
                        ));
                    }
                    tracing::debug!(
                        "Fast path retransmit {}:{} → {}:{} ({} bytes from seq={acked}, cause={}, rto={:?})",
                        conn.remote_ip,
                        conn.remote_port,
                        conn.guest_ip,
                        conn.guest_port,
                        in_flight,
                        if conn.fast_retransmit {
                            "dup-acks"
                        } else {
                            "rto"
                        },
                        conn.rto,
                    );
                    conn.fast_retransmit = false;
                    conn.dup_acks = 0;
                    conn.retransmits += 1;
                    conn.last_progress = now;
                    conn.rto = (conn.rto * 2).min(super::MAX_RTO);
                }
            } else {
                // Nothing in flight — keep the RTO clock parked so the next
                // send starts a fresh timeout window.
                conn.last_progress = now;
                conn.fast_retransmit = false;
            }

            if conn.host_eof {
                continue;
            }

            // Never read (hence send) beyond the guest's advertised receive
            // window (capped: the cap bounds both the retransmission buffer
            // and the burst a flow can throw at the guest's bridge/veth
            // backlog). Unread bytes stay in the host socket buffer —
            // kernel-level backpressure toward the upstream.
            let window = conn
                .guest_window
                .load(std::sync::atomic::Ordering::Relaxed)
                .min(super::HONORED_WINDOW_CAP);
            let budget = super::send_budget(sent, acked, window) as usize;
            let cap = if budget == 0 {
                if !conn.window_stalled {
                    conn.window_stalled = true;
                    conn.window_stalled_at = Some(now);
                    tracing::debug!(
                        "Fast path window stall {}:{} → {}:{} (sent={sent}, acked={acked}, window={window})",
                        conn.remote_ip,
                        conn.remote_port,
                        conn.guest_ip,
                        conn.guest_port,
                    );
                }
                // Zero-window persist: a window closed with nothing in flight is
                // reopened only by a guest window-update ACK; if that ACK is
                // lost the flow deadlocks. Probe with a single byte past the
                // window on a timer to force the guest to re-advertise it. Once
                // the probe byte is in flight, the RTO retransmit path above
                // keeps probing on its own, so this only kicks the first byte.
                let in_flight = sent.wrapping_sub(acked);
                let nothing_in_flight = in_flight == 0 || in_flight >= 0x8000_0000;
                let probe_due = conn.window_stalled_at.is_some_and(|at| {
                    now.duration_since(at) >= super::ZERO_WINDOW_PERSIST_INTERVAL
                });
                if nothing_in_flight && probe_due {
                    conn.window_stalled_at = Some(now);
                    1 // one byte beyond the closed window
                } else {
                    continue;
                }
            } else {
                if conn.window_stalled {
                    conn.window_stalled = false;
                    conn.window_stalled_at = None;
                    tracing::debug!(
                        "Fast path window reopened {}:{} → {}:{} (sent={sent}, acked={acked}, window={window})",
                        conn.remote_ip,
                        conn.remote_port,
                        conn.guest_ip,
                        conn.guest_port,
                    );
                }
                budget.min(conn.read_buf.len())
            };

            use std::io::Read;
            match conn.stream.read(&mut conn.read_buf[..cap]) {
                Ok(0) => {
                    // Host EOF — send FIN to guest.
                    conn.host_eof = true;
                    let seq_now = conn.our_seq.load(std::sync::atomic::Ordering::Relaxed);
                    let fin =
                        crate::ethernet::build_tcp_fin_frame(&crate::ethernet::TcpFrameParams {
                            src_ip: conn.remote_ip,
                            dst_ip: conn.guest_ip,
                            src_port: conn.remote_port,
                            dst_port: conn.guest_port,
                            seq: seq_now,
                            ack: conn.last_ack,
                            window: 65535,
                            src_mac: gw_mac,
                            dst_mac: guest_mac,
                        });
                    // FIN consumes 1 SEQ; remember its position so a lost
                    // FIN is retransmitted like any other in-flight byte.
                    conn.fin_seq = Some(seq_now);
                    conn.our_seq
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    frames.push(fin);
                    // Don't remove yet — keep the entry so the guest's FIN-ACK
                    // response is handled by try_fast_path_intercept (which will
                    // see the FIN flag and clean up).
                }
                Ok(n) => {
                    conn.down_bytes += n as u64;
                    // Host→guest progress refreshes the half-close idle clock so
                    // a slow but live streamed response is never reaped.
                    if conn.guest_fin_at.is_some() {
                        conn.guest_fin_at = Some(now);
                    }
                    let seq_now = conn.our_seq.load(std::sync::atomic::Ordering::Relaxed);
                    conn.retransmit_buf.extend(&conn.read_buf[..n]);
                    emit_data_frames(&ctx, conn, seq_now, &conn.read_buf[..n], &mut frames);
                    conn.our_seq
                        .fetch_add(n as u32, std::sync::atomic::Ordering::Relaxed);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // No data available — expected for non-blocking.
                }
                Err(e) => {
                    tracing::warn!(
                        "Fast path RX error {}:{} → {}:{}, RST to guest: {e}",
                        conn.remote_ip,
                        conn.remote_port,
                        conn.guest_ip,
                        conn.guest_port
                    );
                    // Upstream died mid-stream — propagate as RST. Data may
                    // be lost, so a FIN would let the guest mistake a
                    // truncated stream for a complete one, and no frame at
                    // all leaves the guest ESTABLISHED forever (ABX-431).
                    let rst =
                        crate::ethernet::build_tcp_rst_frame(&crate::ethernet::TcpFrameParams {
                            src_ip: conn.remote_ip,
                            dst_ip: conn.guest_ip,
                            src_port: conn.remote_port,
                            dst_port: conn.guest_port,
                            seq: conn.our_seq.load(std::sync::atomic::Ordering::Relaxed),
                            ack: conn.last_ack,
                            window: 0,
                            src_mac: gw_mac,
                            dst_mac: guest_mac,
                        });
                    frames.push(rst);
                    to_remove.push(*key);
                }
            }
        }

        for key in to_remove {
            self.close_fast_path(&key);
        }

        frames
    }

    /// Removes a fast-path flow and reports its byte totals to the observer
    /// (exactly once). The single choke point for fast-path teardown.
    fn close_fast_path(&mut self, key: &SynFlowKey) {
        let Some(conn) = self.fast_path_conns.remove(key) else {
            return;
        };
        // An inline flow shares its host socket with an independent reader (the
        // inject thread / direct_rx task) holding a cloned fd. Dropping only our
        // clone leaves that reader running on the sibling fd — spinning forever
        // once its send window freezes. Signal its cancel flag and shut the
        // socket so it exits and releases the fd (guest-initiated FIN/RST, and
        // the host-error paths, all funnel through here).
        if conn.inline_owned {
            if let Some(dead) = &conn.dead {
                dead.store(true, std::sync::atomic::Ordering::Relaxed);
            }
            let _ = conn.stream.shutdown(std::net::Shutdown::Both);
        }
        if conn.up_would_block + conn.up_short_writes + conn.up_out_of_order + conn.retransmits > 0
        {
            tracing::debug!(
                "Fast path close {}:{} → {}:{}: loss recovery (up: would_block={}, short_writes={}, out_of_order={}, ooo_dropped={}; down: retransmits={})",
                key.src_ip,
                key.src_port,
                key.dst_ip,
                key.dst_port,
                conn.up_would_block,
                conn.up_short_writes,
                conn.up_out_of_order,
                conn.up_ooo_dropped,
                conn.retransmits,
            );
        }
        if let Some(ref obs) = self.observer {
            let down = conn.down_bytes
                + conn
                    .down_shared
                    .as_ref()
                    .map_or(0, |a| a.load(std::sync::atomic::Ordering::Relaxed));
            obs.on_flow_close(
                crate::egress::FlowKey {
                    src_ip: key.src_ip,
                    src_port: key.src_port,
                    dst_ip: key.dst_ip,
                    dst_port: key.dst_port,
                },
                conn.up_bytes,
                down,
            );
        }
    }

    /// Promotes a connection to the fast path.
    ///
    /// Called when a shim handshake reaches ESTABLISHED and has a
    /// pre-connected host stream. The connection is moved into
    /// `fast_path_conns` and subsequent data bypasses handshake bookkeeping.
    pub fn promote_to_fast_path(
        &mut self,
        key: SynFlowKey,
        stream: std::net::TcpStream,
        our_seq: u32,
        last_ack: u32,
        peer_mss: u16,
        peer_wscale: Option<u8>,
    ) {
        // Set non-blocking for polling in the event loop.
        stream.set_nonblocking(true).ok();
        stream.set_nodelay(true).ok();
        // Keepalive on the upstream leg: a silently dead upstream (route
        // flap, crashed proxy) otherwise never errors, leaving the guest leg
        // ESTABLISHED forever. Applies to the underlying socket, so inline
        // owners reading a cloned fd inherit it. See UPSTREAM_KEEPALIVE_*.
        let keepalive = socket2::TcpKeepalive::new()
            .with_time(super::UPSTREAM_KEEPALIVE_IDLE)
            .with_interval(super::UPSTREAM_KEEPALIVE_INTERVAL)
            .with_retries(super::UPSTREAM_KEEPALIVE_RETRIES);
        if let Err(e) = socket2::SockRef::from(&stream).set_tcp_keepalive(&keepalive) {
            tracing::warn!("Fast path: keepalive setup failed for {key:?}: {e}");
        }

        let last_ack_atomic = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(last_ack));
        let our_seq_atomic = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(our_seq));
        // Download flow-control state: nothing of ours is unACKed yet, and
        // until the guest's first post-handshake ACK arrives we assume one
        // unscaled window (SYN windows are unscaled per RFC 7323) — the
        // first real ACK replaces it within a round trip.
        let guest_acked = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(our_seq));
        let guest_window = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(65535));
        // Shared host→guest byte counter — allocated ONLY when a flow observer is
        // installed, so an un-observed consumer (e.g. the VMM datapath) pays no
        // per-connection allocation or atomic. The inline inject thread increments
        // it; the bridge reads it at teardown.
        let down_shared = self
            .observer
            .is_some()
            .then(|| std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)));

        // Shim-synthesized handshakes know exact SEQ/ACK at promotion
        // time, so hand the cloned stream to the inject thread
        // immediately for zero-copy host→guest reads.
        let mut inline_owned = false;

        // Only hand a flow to the inline/GSO inject path when its peer can accept
        // the fixed 1460-byte GSO segments that path emits. A smaller-MSS peer
        // (e.g. a sub-1500 overlay bridge behind eth0) stays on the clamped
        // polling path below, where each segment matches its advertised MSS.
        let inline_eligible = peer_mss >= GSO_SEGMENT_MSS;
        let mut dead: Option<std::sync::Arc<std::sync::atomic::AtomicBool>> = None;
        if let Some(sink) = self.conn_sink.as_ref().filter(|_| inline_eligible) {
            match stream.try_clone() {
                Ok(cloned) => {
                    let gw_mac = self.fast_path_gateway_mac;
                    let guest_mac = self.fast_path_guest_mac.unwrap_or([0xFF; 6]);
                    let dead_flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                    let promoted = crate::direct_rx::PromotedConn {
                        stream: cloned,
                        remote_ip: key.dst_ip,
                        guest_ip: key.src_ip,
                        remote_port: key.dst_port,
                        guest_port: key.src_port,
                        peer_mss,
                        our_seq: std::sync::Arc::clone(&our_seq_atomic),
                        last_ack: std::sync::Arc::clone(&last_ack_atomic),
                        guest_acked: std::sync::Arc::clone(&guest_acked),
                        guest_window: std::sync::Arc::clone(&guest_window),
                        down_bytes: down_shared.clone(),
                        gw_mac,
                        guest_mac,
                        dead: std::sync::Arc::clone(&dead_flag),
                    };
                    if sink.send_conn(promoted) {
                        inline_owned = true;
                        dead = Some(dead_flag);
                        tracing::info!(
                            "Fast path: promoted INLINE {}:{} → {}:{} (seq={our_seq}, ack={last_ack})",
                            key.src_ip,
                            key.src_port,
                            key.dst_ip,
                            key.dst_port,
                        );
                    } else {
                        tracing::warn!("Fast path: inline sink full, falling back to channel path");
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "Fast path: try_clone failed ({e}), falling back to channel path"
                    );
                }
            }
        } else {
            tracing::info!(
                "Fast path: promoted {}:{} → {}:{} (seq={our_seq}, ack={last_ack})",
                key.src_ip,
                key.src_port,
                key.dst_ip,
                key.dst_port,
            );
        }

        self.fast_path_conns.insert(
            key,
            FastPathConn {
                stream,
                our_seq: our_seq_atomic,
                last_ack,
                last_ack_shared: Some(std::sync::Arc::clone(&last_ack_atomic)),
                remote_ip: key.dst_ip,
                guest_ip: key.src_ip,
                remote_port: key.dst_port,
                guest_port: key.src_port,
                peer_mss,
                guest_wscale: peer_wscale.unwrap_or(0),
                guest_acked,
                guest_window,
                up_would_block: 0,
                up_short_writes: 0,
                up_out_of_order: 0,
                ooo_segs: std::collections::VecDeque::new(),
                ooo_bytes: 0,
                up_ooo_dropped: 0,
                window_stalled: false,
                window_stalled_at: None,
                retransmit_buf: std::collections::VecDeque::new(),
                retransmit_seq: our_seq,
                last_progress: std::time::Instant::now(),
                rto: super::INITIAL_RTO,
                dup_acks: 0,
                fast_retransmit: false,
                fin_seq: None,
                retransmits: 0,
                read_buf: if inline_owned {
                    Vec::new()
                } else {
                    vec![0u8; 32768]
                },
                host_eof: false,
                guest_fin_at: None,
                inline_owned,
                up_bytes: 0,
                down_bytes: 0,
                down_shared: if inline_owned { down_shared } else { None },
                dead,
                last_guest_activity: std::time::Instant::now(),
                soliciting_since: None,
            },
        );
    }

    /// Returns the number of active fast-path connections.
    #[must_use]
    pub fn fast_path_count(&self) -> usize {
        self.fast_path_conns.len()
    }

    /// Returns the number of in-progress handshakes.
    #[must_use]
    pub fn handshake_count(&self) -> usize {
        self.handshake_conns.len()
    }
}
