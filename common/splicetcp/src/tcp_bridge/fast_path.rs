use super::{FastPathConn, SynFlowKey, TcpBridge};
use crate::ethernet::ETH_HEADER_LEN;
use std::net::Ipv4Addr;

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
        if frame.len() < l4_start + 20 {
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
        let payload_start = l4_start + tcp_data_offset;
        let payload_end = ip_end.min(frame.len());
        let payload_len = payload_end.saturating_sub(payload_start);

        // Write payload to host stream (if any). Handle retransmits by
        // only advancing `last_ack` when the segment extends previously
        // acknowledged data; re-writing already-ACKed bytes to the host
        // would corrupt the TLS stream on the peer side.
        if payload_len > 0 {
            use std::io::Write;
            let seq_end = guest_seq.wrapping_add(payload_len as u32);
            // seq_end > conn.last_ack (wrap-safe) means "segment carries
            // at least one new byte". Otherwise the entire segment is a
            // retransmit of data we already ACKed.
            let is_new_data = seq_end.wrapping_sub(conn.last_ack) > 0
                && seq_end.wrapping_sub(conn.last_ack) < 0x8000_0000;
            if is_new_data {
                let payload = &frame[payload_start..payload_start + payload_len];
                match conn.stream.write(payload) {
                    Ok(_n) => {
                        conn.up_bytes += payload_len as u64;
                        conn.set_last_ack(seq_end);
                        tracing::trace!(
                            "Fast path TX: {src_ip}:{src_port}→{dst_ip}:{dst_port} wrote {payload_len} bytes"
                        );
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        tracing::trace!(
                            "Fast path TX: {src_ip}:{src_port}→{dst_ip}:{dst_port} WouldBlock"
                        );
                        return Some(Vec::new());
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {
                        // Peer closed; inject already relayed FIN. ACK at
                        // TCP layer so the guest stops retransmitting.
                        conn.set_last_ack(seq_end);
                        tracing::debug!(
                            "Fast path TX: {src_ip}:{src_port}→{dst_ip}:{dst_port} Broken pipe, draining {payload_len} bytes"
                        );
                    }
                    Err(e) => {
                        tracing::warn!("Fast path TX write error: {e}");
                        self.close_fast_path(&key);
                        return None;
                    }
                }
            } else {
                // Duplicate/already-ACKed segment — skip write, re-ACK.
                tracing::trace!(
                    "Fast path TX: {src_ip}:{src_port}→{dst_ip}:{dst_port} retransmit (guest_seq={guest_seq}, last_ack={}, payload={payload_len})",
                    conn.last_ack
                );
            }
        }

        // FIN handling — after payload has been forwarded to host.
        if flags & 0x01 != 0 {
            tracing::debug!("Fast path: FIN from guest {src_ip}:{src_port}→{dst_ip}:{dst_port}");
            // FIN consumes 1 sequence number (in addition to any data bytes
            // already accounted for above).
            conn.set_last_ack(conn.last_ack.wrapping_add(1));
            let guest_mac = self.fast_path_guest_mac.unwrap_or([0xFF; 6]);
            let fin_ack = crate::ethernet::build_tcp_fin_frame(&crate::ethernet::TcpFrameParams {
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

        // Only ACK if the guest sent data — replying to a pure ACK
        // would create a dup-ACK loop that triggers fast retransmits on
        // the peer and tanks host→VM throughput.
        if payload_len == 0 {
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

        for (key, conn) in &mut self.fast_path_conns {
            if conn.host_eof || conn.inline_owned {
                continue;
            }

            use std::io::Read;
            match conn.stream.read(&mut conn.read_buf) {
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
                    // FIN consumes 1 SEQ.
                    conn.our_seq
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    frames.push(fin);
                    // Don't remove yet — keep the entry so the guest's FIN-ACK
                    // response is handled by try_fast_path_intercept (which will
                    // see the FIN flag and clean up).
                }
                Ok(n) => {
                    conn.down_bytes += n as u64;
                    // Channel/inject path: send the entire read as one large
                    // frame (the inject thread's GSO hint lets the guest
                    // re-segment at MSS).
                    let data = &conn.read_buf[..n];
                    if self.large_frames_enabled {
                        let large = ETH_HEADER_LEN + 40 + data.len() > 1500;
                        let seq_now = conn.our_seq.load(std::sync::atomic::Ordering::Relaxed);
                        let params = crate::ethernet::TcpFrameParams {
                            src_ip: conn.remote_ip,
                            dst_ip: conn.guest_ip,
                            src_port: conn.remote_port,
                            dst_port: conn.guest_port,
                            seq: seq_now,
                            ack: conn.last_ack,
                            window: 65535,
                            src_mac: gw_mac,
                            dst_mac: guest_mac,
                        };
                        let data_frame = if large {
                            crate::ethernet::build_tcp_data_frame_partial_csum(&params, data)
                        } else {
                            crate::ethernet::build_tcp_data_frame(&params, data)
                        };
                        conn.our_seq
                            .fetch_add(data.len() as u32, std::sync::atomic::Ordering::Relaxed);
                        frames.push(data_frame);
                    } else {
                        // Non-GSO path: segment at the configured guest MSS so
                        // each emitted IP packet fits the consumer's MTU.
                        let mut offset = 0;
                        while offset < data.len() {
                            let chunk_end = (offset + self.fast_path_guest_mss).min(data.len());
                            let chunk = &data[offset..chunk_end];
                            let seq_now = conn.our_seq.load(std::sync::atomic::Ordering::Relaxed);
                            let data_frame = crate::ethernet::build_tcp_data_frame(
                                &crate::ethernet::TcpFrameParams {
                                    src_ip: conn.remote_ip,
                                    dst_ip: conn.guest_ip,
                                    src_port: conn.remote_port,
                                    dst_port: conn.guest_port,
                                    seq: seq_now,
                                    ack: conn.last_ack,
                                    window: 65535,
                                    src_mac: gw_mac,
                                    dst_mac: guest_mac,
                                },
                                chunk,
                            );
                            conn.our_seq.fetch_add(
                                chunk.len() as u32,
                                std::sync::atomic::Ordering::Relaxed,
                            );
                            frames.push(data_frame);
                            offset = chunk_end;
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // No data available — expected for non-blocking.
                }
                Err(e) => {
                    tracing::warn!(
                        "Fast path RX error {}:{} → {}:{}: {e}",
                        conn.remote_ip,
                        conn.remote_port,
                        conn.guest_ip,
                        conn.guest_port
                    );
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
    ) {
        // Set non-blocking for polling in the event loop.
        stream.set_nonblocking(true).ok();
        stream.set_nodelay(true).ok();

        let last_ack_atomic = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(last_ack));
        let our_seq_atomic = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(our_seq));
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

        if let Some(ref sink) = self.conn_sink {
            match stream.try_clone() {
                Ok(cloned) => {
                    let gw_mac = self.fast_path_gateway_mac;
                    let guest_mac = self.fast_path_guest_mac.unwrap_or([0xFF; 6]);
                    let promoted = crate::direct_rx::PromotedConn {
                        stream: cloned,
                        remote_ip: key.dst_ip,
                        guest_ip: key.src_ip,
                        remote_port: key.dst_port,
                        guest_port: key.src_port,
                        our_seq: std::sync::Arc::clone(&our_seq_atomic),
                        last_ack: std::sync::Arc::clone(&last_ack_atomic),
                        down_bytes: down_shared.clone(),
                        gw_mac,
                        guest_mac,
                    };
                    if sink.send_conn(promoted) {
                        inline_owned = true;
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
                read_buf: if inline_owned {
                    Vec::new()
                } else {
                    vec![0u8; 32768]
                },
                host_eof: false,
                inline_owned,
                up_bytes: 0,
                down_bytes: 0,
                down_shared: if inline_owned { down_shared } else { None },
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
