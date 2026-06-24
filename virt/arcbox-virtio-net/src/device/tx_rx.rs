use arcbox_virtio_core::error::{Result, VirtioError};
use arcbox_virtio_core::queue::Descriptor;

use crate::header::{NetPacket, VirtioNetHeader};

use super::VirtioNet;

impl VirtioNet {
    /// Handles TX from guest.
    pub(super) fn handle_tx(&mut self, data: &[u8]) -> Result<()> {
        if data.len() < VirtioNetHeader::SIZE {
            return Err(VirtioError::InvalidOperation("Packet too small".into()));
        }

        let header = VirtioNetHeader::from_bytes(data)
            .ok_or_else(|| VirtioError::InvalidOperation("Invalid header".into()))?;

        let packet = NetPacket {
            header,
            data: data[VirtioNetHeader::SIZE..].to_vec(),
        };

        self.tx_packets += 1;
        self.tx_bytes += packet.data.len() as u64;

        if let Some(backend) = &self.backend {
            let mut backend = backend
                .lock()
                .map_err(|e| VirtioError::Io(format!("Failed to lock backend: {e}")))?;

            let is_tso = header.gso_type != VirtioNetHeader::GSO_NONE && header.gso_size > 0;
            if is_tso {
                tracing::trace!(
                    "Net TX TSO: {} bytes, gso_type={}, gso_size={}",
                    packet.data.len(),
                    header.gso_type,
                    header.gso_size
                );
                backend
                    .send_tso(&packet)
                    .map_err(|e| VirtioError::Io(format!("TSO send failed: {e}")))?;
            } else {
                backend
                    .send(&packet)
                    .map_err(|e| VirtioError::Io(format!("Send failed: {e}")))?;
            }
        }

        tracing::trace!("Net TX: {} bytes", packet.data.len());
        Ok(())
    }

    /// Processes the TX queue.
    ///
    /// Collects all pending TX descriptors and sends them. Returns completions
    /// for batch notification via `push_used_batch()`.
    ///
    /// # Errors
    ///
    /// Returns an error if processing fails.
    pub fn process_tx_queue(&mut self, memory: &[u8]) -> Result<Vec<(u16, u32)>> {
        let mut tx_data: Vec<(u16, Vec<u8>)> = Vec::new();

        {
            let queue = self
                .tx_queue
                .as_mut()
                .ok_or_else(|| VirtioError::NotReady("TX queue not ready".into()))?;

            while let Some((head_idx, chain)) = queue.pop_avail() {
                let mut data = Vec::new();

                for desc in chain {
                    if !desc.is_write_only() {
                        let start = desc.addr as usize;
                        let end = start + desc.len as usize;
                        if end <= memory.len() {
                            data.extend_from_slice(&memory[start..end]);
                        }
                    }
                }

                tx_data.push((head_idx, data));
            }
        }

        let mut completed = Vec::new();
        for (head_idx, data) in tx_data {
            let len = data.len() as u32;
            self.handle_tx(&data)?;
            completed.push((head_idx, len));
        }

        Ok(completed)
    }

    /// Returns the number of packets in the RX buffer.
    #[must_use]
    pub fn rx_pending(&self) -> usize {
        self.rx_buffer.len()
    }

    /// Polls the backend for incoming packets.
    ///
    /// # Errors
    ///
    /// Returns an error if polling fails.
    pub fn poll_backend(&mut self) -> Result<()> {
        self.poll_backend_batch(usize::MAX).map(|_| ())
    }

    /// Polls the backend for up to `max_batch` incoming packets.
    ///
    /// Returns the number of packets received. Use this instead of
    /// `poll_backend()` to limit per-iteration work and ensure fairness
    /// with other select! arms.
    ///
    /// # Errors
    ///
    /// Returns an error if polling fails.
    pub fn poll_backend_batch(&mut self, max_batch: usize) -> Result<usize> {
        let mut received = 0;

        let Some(backend) = self.backend.clone() else {
            return Ok(0);
        };
        let mut backend = backend
            .lock()
            .map_err(|e| VirtioError::Io(format!("Failed to lock backend: {e}")))?;

        while received < max_batch && backend.has_data() {
            // Reuse the per-device scratch buffer instead of allocating a
            // fresh 64 KiB `Vec` per packet — that alloc+dealloc pair was
            // the dominant CPU cost at sustained RX rates. The Vec we push
            // into `rx_buffer` still holds an owned copy (sized to the
            // actual frame length), which is unavoidable while we stage
            // through `rx_buffer`; true readv-to-guest zero-copy is the
            // job of the dedicated net-io worker, not this path.
            let n = backend
                .recv(&mut self.rx_scratch[..])
                .map_err(|e| VirtioError::Io(format!("Recv failed: {e}")))?;

            if n == 0 {
                break;
            }
            let packet = NetPacket::new(self.rx_scratch[..n].to_vec());
            self.rx_packets += 1;
            self.rx_bytes += n as u64;
            self.rx_buffer.push_back(packet);
            received += 1;
        }

        Ok(received)
    }

    /// Inject packets from `rx_buffer` into the guest RX virtqueue.
    ///
    /// Drains as many packets as possible from the buffer into guest-provided
    /// descriptors. Returns completions for batch notification.
    /// TODO(ABX-208): Caller should use `push_used_batch()` for single interrupt.
    ///
    /// When `HOST_TSO4/6` was negotiated and a packet exceeds the MTU, the
    /// header is stamped with GSO metadata so the guest kernel can handle
    /// segmentation — a single virtqueue push replaces ~45 small pushes.
    ///
    /// # Errors
    ///
    /// Returns an error if the RX queue is not ready.
    pub fn inject_rx_batch(&mut self, memory: &mut [u8]) -> Result<Vec<(u16, u32)>> {
        let host_tso4 = self.acked_features & Self::FEATURE_HOST_TSO4 != 0;
        let host_tso6 = self.acked_features & Self::FEATURE_HOST_TSO6 != 0;
        let mrg_rxbuf = self.acked_features & Self::FEATURE_MRG_RXBUF != 0;
        let mtu = self.config.mtu as usize;

        let queue = self
            .rx_queue
            .as_mut()
            .ok_or_else(|| VirtioError::NotReady("RX queue not ready".into()))?;

        let mut completions = Vec::new();

        while let Some(mut packet) = self.rx_buffer.pop_front() {
            // If the packet is larger than MTU and TSO was negotiated, stamp
            // the virtio-net header so the guest kernel segments it.
            if packet.data.len() > mtu && packet.header.gso_type == VirtioNetHeader::GSO_NONE {
                if host_tso4 {
                    packet.header.gso_type = VirtioNetHeader::GSO_TCPV4;
                    packet.header.gso_size = Self::DEFAULT_TSO_MSS;
                    packet.header.hdr_len = Self::ETH_IP_TCP_HDR_LEN;
                } else if host_tso6 {
                    packet.header.gso_type = VirtioNetHeader::GSO_TCPV6;
                    packet.header.gso_size = Self::DEFAULT_TSO_MSS;
                    packet.header.hdr_len = Self::ETH_IP_TCP_HDR_LEN;
                }
            }

            let header_bytes = packet.header.to_bytes();
            let full_frame_len = header_bytes.len() + packet.data.len();
            let mut frame = Vec::with_capacity(full_frame_len);
            frame.extend_from_slice(&header_bytes);
            frame.extend_from_slice(&packet.data);

            // Collect chains until we either have enough capacity for the
            // whole frame or the guest runs out of posted buffers. When
            // MRG_RXBUF wasn't negotiated we stop at one chain — the guest
            // driver won't accept multi-buffer delivery.
            let mut chains: Vec<(u16, Vec<Descriptor>)> = Vec::new();
            let mut capacity = 0usize;
            while capacity < frame.len() {
                match queue.pop_avail() {
                    Some((head_idx, chain)) => {
                        let descs: Vec<Descriptor> = chain.copied().collect();
                        capacity += descs
                            .iter()
                            .filter(|d| d.is_write_only())
                            .map(|d| d.len as usize)
                            .sum::<usize>();
                        chains.push((head_idx, descs));
                    }
                    None => break,
                }
                if !mrg_rxbuf {
                    break;
                }
            }

            if chains.is_empty() {
                // No posted buffers at all — re-queue the packet and bail.
                self.rx_buffer.push_front(packet);
                break;
            }

            // Stamp num_buffers into the first chain's virtio_net_hdr. The
            // field is bytes 10..12 of the 12-byte header we emit with
            // VERSION_1 / MRG_RXBUF. Non-MRG_RXBUF guests ignore it.
            let num_buffers = chains.len() as u16;
            frame[10..12].copy_from_slice(&num_buffers.to_le_bytes());

            // Write the frame across every chain. Each chain's used-ring
            // entry reports how many bytes landed in that chain's buffers.
            let mut written = 0usize;
            let mut out_of_bounds = false;
            let mut per_chain: Vec<(u16, u32)> = Vec::with_capacity(chains.len());
            for (head_idx, descs) in chains {
                let mut chain_written = 0usize;
                for desc in descs {
                    if !desc.is_write_only() {
                        continue;
                    }
                    let remaining = frame.len().saturating_sub(written);
                    let to_write = remaining.min(desc.len as usize);
                    if to_write == 0 {
                        continue;
                    }
                    let start = desc.addr as usize;
                    let end = start + to_write;
                    if end > memory.len() {
                        out_of_bounds = true;
                        break;
                    }
                    memory[start..end].copy_from_slice(&frame[written..written + to_write]);
                    written += to_write;
                    chain_written += to_write;
                }
                if out_of_bounds {
                    break;
                }
                per_chain.push((head_idx, chain_written as u32));
            }

            if out_of_bounds {
                // Some descriptor pointed outside guest RAM — the packet is
                // lost for correctness, but we still have to publish the
                // consumed chains to the used ring (the guest has already
                // handed them over). Publish with len=0 so the guest
                // re-uses the buffers without surfacing garbage data.
                for (head_idx, _) in per_chain {
                    completions.push((head_idx, 0));
                }
                continue;
            }

            if written < frame.len() {
                tracing::warn!(
                    "virtio-net RX: truncated {}-byte frame to {} bytes ({} chains, mrg_rxbuf={})",
                    frame.len(),
                    written,
                    per_chain.len(),
                    mrg_rxbuf,
                );
            }

            completions.extend(per_chain);
        }

        Ok(completions)
    }
}
