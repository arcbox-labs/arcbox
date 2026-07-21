use super::{
    HANDSHAKE_MAX_RETRANSMITS, HANDSHAKE_TOTAL_TTL, HandshakeConn, HandshakeRole, MAX_PENDING_SYNS,
    SHIM_MSS, SHIM_WSCALE, SynFlowKey, TcpBridge, build_rst_from_syn, next_isn, should_retransmit,
};
use crate::ethernet::ETH_HEADER_LEN;
use std::net::Ipv4Addr;
use std::time::Instant as StdInstant;
use tokio::sync::oneshot;

impl TcpBridge {
    /// Parses a TCP SYN frame and registers an in-shim `PassiveOpen`
    /// handshake: captures the guest ISN and options, generates our ISN,
    /// and spawns an async host connect. The SYN-ACK is emitted later by
    /// `poll_handshakes` once the connect resolves.
    ///
    /// Returns an RST frame if the SYN is rejected (capacity, malformed).
    /// Returns `None` on success — the handshake is now tracked.
    ///
    /// `gateway_mac` and `guest_mac` are the MAC addresses used on the
    /// guest's Ethernet link. The guest MAC is learned from the source MAC
    /// of inbound frames; if `guest_mac` is `None`, we use broadcast as a
    /// temporary fallback (first guest frame will correct it).
    pub fn handle_outbound_syn(
        &mut self,
        syn_frame: &[u8],
        gateway_mac: [u8; 6],
        guest_mac: [u8; 6],
    ) -> Option<Vec<u8>> {
        // Parse the SYN frame: ETH(14) + IP(var) + TCP(var).
        let ip_start = ETH_HEADER_LEN;
        if syn_frame.len() < ip_start + 40 {
            return None;
        }
        let ihl = ((syn_frame[ip_start] & 0x0F) as usize) * 4;
        let l4_start = ip_start + ihl;
        if ihl < 20 || l4_start + 20 > syn_frame.len() {
            return None;
        }

        let src_ip = Ipv4Addr::new(
            syn_frame[ip_start + 12],
            syn_frame[ip_start + 13],
            syn_frame[ip_start + 14],
            syn_frame[ip_start + 15],
        );
        let dst_ip = Ipv4Addr::new(
            syn_frame[ip_start + 16],
            syn_frame[ip_start + 17],
            syn_frame[ip_start + 18],
            syn_frame[ip_start + 19],
        );
        let src_port = u16::from_be_bytes([syn_frame[l4_start], syn_frame[l4_start + 1]]);
        let dst_port = u16::from_be_bytes([syn_frame[l4_start + 2], syn_frame[l4_start + 3]]);
        let flags = syn_frame[l4_start + 13];
        // Require SYN set, ACK clear.
        if flags & 0x12 != 0x02 {
            return None;
        }
        let guest_isn = u32::from_be_bytes([
            syn_frame[l4_start + 4],
            syn_frame[l4_start + 5],
            syn_frame[l4_start + 6],
            syn_frame[l4_start + 7],
        ]);

        let key = SynFlowKey {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
        };

        // Retransmit of an existing handshake — same ISN means the guest
        // is re-sending the SYN because our SYN-ACK was lost. Drop
        // silently; poll_handshakes will handle the re-send.
        if let Some(existing) = self.handshake_conns.get(&key) {
            if existing.role == HandshakeRole::PassiveOpen && existing.peer_isn == guest_isn {
                tracing::debug!("Handshake shim: SYN retransmit dropped for {key:?}");
                return None;
            }
            // Different ISN = new connection attempt, evict stale entry.
            tracing::debug!("Handshake shim: ISN changed for {key:?}, replacing");
            self.handshake_conns.remove(&key);
        }

        // Capacity guard — send RST instead of silent drop.
        if self.handshake_conns.len() >= MAX_PENDING_SYNS {
            tracing::warn!("Handshake shim: capacity reached, RST for {key:?}");
            return build_rst_from_syn(syn_frame, gateway_mac);
        }

        // Parse peer options (MSS / WScale / SACK-perm).
        let opts = crate::ethernet::parse_tcp_syn_options(&syn_frame[l4_start..]);
        let peer_wscale = opts.wscale;
        let peer_sack = opts.sack_permitted;
        let peer_mss = opts.mss.unwrap_or(536);

        // Decide + dial egress via the injected resolver. The default
        // reproduces the historical inline behavior: route via the configured
        // upstream proxy (connecting by hostname, so Fake-IP destinations
        // resolve on the proxy's side) or a direct connect, with the
        // gateway→loopback translation and a connect timeout. The hostname is
        // recovered from the destination IP via the DNS resolution log.
        let domain = self.dns_log.as_ref().and_then(|log| log.lookup(dst_ip));
        let result_rx = self.egress.resolve(crate::egress::FlowMeta {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            domain,
        });
        // Wake the datapath loop the moment the connect resolves: on an
        // idle loop nothing else fires until the next guest frame or the
        // 1 s timer tick, and that tick otherwise dominates every fresh
        // connection's latency (sequential fetches ran at ~2 s/request).
        let result_rx = if let Some(waker) = &self.handshake_waker {
            let waker = std::sync::Arc::clone(waker);
            let (tx, rx) = oneshot::channel();
            tokio::spawn(async move {
                let value = result_rx.await.unwrap_or(None);
                let _ = tx.send(value);
                waker.notify_one();
            });
            rx
        } else {
            result_rx
        };

        let our_isn = next_isn();
        self.handshake_conns.insert(
            key,
            HandshakeConn {
                flow_key: key,
                role: HandshakeRole::PassiveOpen,
                our_isn,
                peer_isn: guest_isn,
                host_stream: None,
                connect_rx: Some(result_rx),
                peer_wscale,
                peer_sack,
                peer_mss,
                gw_mac: gateway_mac,
                guest_mac,
                retransmit_count: 0,
                last_sent: None,
                saved_frame: None,
                created: StdInstant::now(),
            },
        );

        tracing::debug!(
            "Handshake shim: passive-open registered {key:?} our_isn={our_isn:08x} guest_isn={guest_isn:08x}"
        );
        None
    }

    /// Registers an inbound port-forward `ActiveOpen` handshake. We will
    /// emit a SYN toward the guest on the next `poll_handshakes`, then
    /// wait for the guest's SYN-ACK.
    ///
    /// Called from the datapath when `InboundListenerManager` accepts a
    /// new host connection.
    pub fn initiate_active_handshake(
        &mut self,
        flow_key: SynFlowKey,
        host_stream: std::net::TcpStream,
        gateway_mac: [u8; 6],
        guest_mac: [u8; 6],
    ) {
        host_stream.set_nonblocking(true).ok();
        host_stream.set_nodelay(true).ok();

        let our_isn = next_isn();
        // Evict any stale entry for the same four-tuple.
        self.handshake_conns.remove(&flow_key);

        self.handshake_conns.insert(
            flow_key,
            HandshakeConn {
                flow_key,
                role: HandshakeRole::ActiveOpen,
                our_isn,
                peer_isn: 0, // filled in when SYN-ACK arrives
                host_stream: Some(host_stream),
                connect_rx: None,
                peer_wscale: Some(SHIM_WSCALE),
                peer_sack: true,
                peer_mss: SHIM_MSS,
                gw_mac: gateway_mac,
                guest_mac,
                retransmit_count: 0,
                last_sent: None,
                saved_frame: None,
                created: StdInstant::now(),
            },
        );

        tracing::debug!(
            "Handshake shim: active-open registered {flow_key:?} our_isn={our_isn:08x}"
        );
    }

    /// Drives all in-progress handshakes: polls host connects, emits
    /// initial frames (SYN-ACK for passive, SYN for active), retransmits,
    /// and aborts after the TTL / retransmit limit.
    ///
    /// Returns frames to inject to the guest.
    pub fn poll_handshakes(&mut self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut to_abort: Vec<SynFlowKey> = Vec::new();
        let now = StdInstant::now();

        for (key, conn) in &mut self.handshake_conns {
            // Global TTL — abort stuck handshakes, telling the guest: without
            // the RST it retries SYNs against a flow we already gave up on
            // and its socket only dies by its own (much longer) timeout.
            if now.duration_since(conn.created) > HANDSHAKE_TOTAL_TTL {
                tracing::warn!("Handshake shim: TTL exceeded for {key:?}, aborting with RST");
                out.push(handshake_abort_rst(key, conn));
                to_abort.push(*key);
                continue;
            }

            match conn.role {
                HandshakeRole::PassiveOpen => {
                    // If host connect hasn't resolved, try to pick up the result.
                    if conn.host_stream.is_none() {
                        let Some(rx) = conn.connect_rx.as_mut() else {
                            // No stream, no pending connect — aborted.
                            out.push(handshake_abort_rst(key, conn));
                            to_abort.push(*key);
                            continue;
                        };
                        match rx.try_recv() {
                            Ok(Some(crate::egress::EgressConn::Tcp(tokio_stream))) => {
                                match tokio_stream.into_std() {
                                    Ok(std_stream) => {
                                        std_stream.set_nonblocking(true).ok();
                                        std_stream.set_nodelay(true).ok();
                                        conn.host_stream = Some(std_stream);
                                        conn.connect_rx = None;
                                    }
                                    Err(e) => {
                                        tracing::debug!(
                                            "Handshake shim: into_std failed for {key:?}: {e}"
                                        );
                                        out.push(handshake_abort_rst(key, conn));
                                        to_abort.push(*key);
                                        continue;
                                    }
                                }
                            }
                            Ok(None) => {
                                // Host connect refused / timed out. Emit
                                // RST|ACK toward the guest so the originating
                                // socket sees an immediate ECONNREFUSED
                                // instead of waiting for SYN retransmits.
                                tracing::debug!("Handshake shim: host connect failed for {key:?}");
                                out.push(handshake_abort_rst(key, conn));
                                to_abort.push(*key);
                                continue;
                            }
                            Err(oneshot::error::TryRecvError::Empty) => {
                                continue; // still connecting
                            }
                            Err(oneshot::error::TryRecvError::Closed) => {
                                out.push(handshake_abort_rst(key, conn));
                                to_abort.push(*key);
                                continue;
                            }
                        }
                    }

                    // Host stream is ready. Emit SYN-ACK (first time) or
                    // retransmit based on timer.
                    if conn.saved_frame.is_none() {
                        let frame = crate::ethernet::build_tcp_syn_ack_frame(
                            &crate::ethernet::SynAckParams {
                                src_ip: key.dst_ip,
                                dst_ip: key.src_ip,
                                src_port: key.dst_port,
                                dst_port: key.src_port,
                                seq: conn.our_isn,
                                ack: conn.peer_isn.wrapping_add(1),
                                src_mac: conn.gw_mac,
                                dst_mac: conn.guest_mac,
                                mss: SHIM_MSS,
                                wscale: conn.peer_wscale.map(|_| SHIM_WSCALE),
                                sack_permitted: conn.peer_sack,
                            },
                        );
                        conn.saved_frame = Some(frame.clone());
                        conn.last_sent = Some(now);
                        out.push(frame);
                    } else if should_retransmit(conn, now) {
                        if conn.retransmit_count >= HANDSHAKE_MAX_RETRANSMITS {
                            to_abort.push(*key);
                            continue;
                        }
                        if let Some(ref frame) = conn.saved_frame {
                            out.push(frame.clone());
                            conn.retransmit_count += 1;
                            conn.last_sent = Some(now);
                        }
                    }
                }
                HandshakeRole::ActiveOpen => {
                    // Stop driving the guest-side handshake if the host client
                    // that opened this inbound connection already disconnected
                    // (peek on the non-blocking stream: EOF or a hard error) —
                    // otherwise we retransmit the SYN toward the guest for the
                    // full TTL for a connection the peer has abandoned.
                    let host_dead = conn.host_stream.as_ref().is_some_and(|s| {
                        let mut probe = [0u8; 1];
                        match s.peek(&mut probe) {
                            Ok(0) => true, // clean EOF from the host peer
                            Ok(_) => false,
                            Err(e) => e.kind() != std::io::ErrorKind::WouldBlock,
                        }
                    });
                    if host_dead {
                        to_abort.push(*key);
                        continue;
                    }
                    if conn.saved_frame.is_none() {
                        let frame =
                            crate::ethernet::build_tcp_syn_frame(&crate::ethernet::SynParams {
                                // We're sending from gateway → guest.
                                src_ip: key.dst_ip,
                                dst_ip: key.src_ip,
                                src_port: key.dst_port,
                                dst_port: key.src_port,
                                seq: conn.our_isn,
                                src_mac: conn.gw_mac,
                                dst_mac: conn.guest_mac,
                                mss: SHIM_MSS,
                                wscale: Some(SHIM_WSCALE),
                            });
                        conn.saved_frame = Some(frame.clone());
                        conn.last_sent = Some(now);
                        out.push(frame);
                    } else if should_retransmit(conn, now) {
                        if conn.retransmit_count >= HANDSHAKE_MAX_RETRANSMITS {
                            to_abort.push(*key);
                            continue;
                        }
                        if let Some(ref frame) = conn.saved_frame {
                            out.push(frame.clone());
                            conn.retransmit_count += 1;
                            conn.last_sent = Some(now);
                        }
                    }
                }
            }
        }

        for key in to_abort {
            self.handshake_conns.remove(&key);
        }

        out
    }

    /// Called when a TCP frame arrives that matches a pending handshake
    /// (keyed on `SynFlowKey`). For PassiveOpen: consumes the guest's ACK
    /// and promotes to `FastPathConn`. For ActiveOpen: consumes the
    /// guest's SYN-ACK, emits our final ACK, and promotes.
    ///
    /// Returns `Some(Vec<frame>)` if the frame was consumed by the shim
    /// (possibly emitting reply frames). Returns `None` if no matching
    /// handshake exists or the frame doesn't match the expected phase.
    pub fn try_complete_handshake(&mut self, frame: &[u8]) -> Option<Vec<Vec<u8>>> {
        let ip_start = ETH_HEADER_LEN;
        if frame.len() < ip_start + 40 {
            return None;
        }
        if frame[ip_start + 9] != 6 {
            return None;
        }
        let ihl = ((frame[ip_start] & 0x0F) as usize) * 4;
        let l4_start = ip_start + ihl;
        if ihl < 20 || l4_start + 20 > frame.len() {
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
        let seq = u32::from_be_bytes([
            frame[l4_start + 4],
            frame[l4_start + 5],
            frame[l4_start + 6],
            frame[l4_start + 7],
        ]);
        let ack = u32::from_be_bytes([
            frame[l4_start + 8],
            frame[l4_start + 9],
            frame[l4_start + 10],
            frame[l4_start + 11],
        ]);

        let key = SynFlowKey {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
        };
        let conn = self.handshake_conns.get(&key)?;

        match conn.role {
            HandshakeRole::PassiveOpen => {
                // Expect ACK set, SYN clear, and RST/FIN both clear. Without
                // the RST/FIN check, RST|ACK (0x14) and FIN|ACK (0x11) would
                // pass the old `flags & 0x12 != 0x10` test and incorrectly
                // promote an already-aborted guest flow into the fast path.
                const SYN: u8 = 0x02;
                const ACK: u8 = 0x10;
                const RST: u8 = 0x04;
                const FIN: u8 = 0x01;
                if flags & (SYN | ACK) != ACK || flags & (RST | FIN) != 0 {
                    if flags & RST != 0 {
                        tracing::debug!("Handshake shim: RST during PassiveOpen for {key:?}");
                        self.handshake_conns.remove(&key);
                    }
                    return None;
                }
                // Guest is ACKing our SYN-ACK: ack should be our_isn + 1.
                if ack != conn.our_isn.wrapping_add(1) {
                    tracing::debug!(
                        "Handshake shim: passive ACK mismatch for {key:?} got ack={ack:08x} want={:08x}",
                        conn.our_isn.wrapping_add(1)
                    );
                    return None;
                }
                let conn = self.handshake_conns.remove(&key)?;
                let our_seq = conn.our_isn.wrapping_add(1);
                let last_ack = conn.peer_isn.wrapping_add(1);
                let peer_mss = conn.peer_mss;
                let peer_wscale = conn.peer_wscale;
                let Some(stream) = conn.host_stream else {
                    return Some(Vec::new());
                };
                self.promote_to_fast_path(key, stream, our_seq, last_ack, peer_mss, peer_wscale);
                Some(Vec::new())
            }
            HandshakeRole::ActiveOpen => {
                // Expect SYN + ACK.
                if flags & 0x12 != 0x12 {
                    return None;
                }
                if ack != conn.our_isn.wrapping_add(1) {
                    tracing::debug!(
                        "Handshake shim: active SYN-ACK ack mismatch for {key:?} got ack={ack:08x} want={:08x}",
                        conn.our_isn.wrapping_add(1)
                    );
                    return None;
                }
                // Capture guest ISN from their SYN-ACK.
                let guest_isn = seq;
                // Mirror their options back so we can promote with sane state.
                let peer_opts = crate::ethernet::parse_tcp_syn_options(&frame[l4_start..]);

                let mut conn = self.handshake_conns.remove(&key)?;
                conn.peer_isn = guest_isn;
                if peer_opts.wscale.is_some() {
                    conn.peer_wscale = peer_opts.wscale;
                }
                if peer_opts.sack_permitted {
                    conn.peer_sack = true;
                }
                // Record the guest endpoint's real MSS so host→guest segments
                // are sized to what it can forward (a bridged container behind
                // eth0 advertises its own, smaller, veth MSS here).
                if let Some(mss) = peer_opts.mss {
                    conn.peer_mss = mss;
                }

                // Build ACK completing the handshake.
                let our_seq = conn.our_isn.wrapping_add(1);
                let last_ack = guest_isn.wrapping_add(1);
                let ack_frame =
                    crate::ethernet::build_tcp_ack_frame(&crate::ethernet::TcpFrameParams {
                        // Direction: gateway → guest.
                        src_ip: key.dst_ip,
                        dst_ip: key.src_ip,
                        src_port: key.dst_port,
                        dst_port: key.src_port,
                        seq: our_seq,
                        ack: last_ack,
                        window: 65535,
                        src_mac: conn.gw_mac,
                        dst_mac: conn.guest_mac,
                    });

                let peer_mss = conn.peer_mss;
                let peer_wscale = conn.peer_wscale;
                let Some(stream) = conn.host_stream else {
                    return Some(vec![ack_frame]);
                };
                self.promote_to_fast_path(key, stream, our_seq, last_ack, peer_mss, peer_wscale);
                Some(vec![ack_frame])
            }
        }
    }
}

/// Builds the RST|ACK toward the guest for a handshake that will never
/// complete — connect failure, TTL expiry, or a dropped egress channel.
/// `seq` is 0 because our SYN-ACK may not have been sent yet; acknowledging
/// the guest's ISN keeps the RST acceptable in SYN-SENT (RFC 793). Without
/// this frame the guest's socket outlives the aborted flow (ABX-431).
fn handshake_abort_rst(key: &SynFlowKey, conn: &HandshakeConn) -> Vec<u8> {
    crate::ethernet::build_tcp_rst_frame(&crate::ethernet::TcpFrameParams {
        src_ip: key.dst_ip,
        dst_ip: key.src_ip,
        src_port: key.dst_port,
        dst_port: key.src_port,
        seq: 0,
        ack: conn.peer_isn.wrapping_add(1),
        window: 0,
        src_mac: conn.gw_mac,
        dst_mac: conn.guest_mac,
    })
}
