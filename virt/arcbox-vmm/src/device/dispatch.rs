use super::*;

impl DeviceManager {
    /// Finds device by MMIO address.
    #[must_use]
    pub fn find_by_mmio(&self, addr: u64) -> Option<DeviceId> {
        for (base, id) in &self.mmio_map {
            if let Some(device) = self.devices.get(id) {
                if addr >= *base && addr < *base + device.info.mmio_size {
                    return Some(*id);
                }
            }
        }
        None
    }

    /// Handles MMIO read.
    ///
    /// # Errors
    ///
    /// Returns an error if the read fails.
    pub fn handle_mmio_read(&self, addr: u64, size: usize) -> Result<u64> {
        let device_id = self
            .find_by_mmio(addr)
            .ok_or_else(|| VmmError::Device(format!("No device at MMIO address {addr:#x}")))?;

        let device = self
            .devices
            .get(&device_id)
            .ok_or_else(|| VmmError::Device(format!("Device {} not found", device_id.0)))?;

        let base = device.info.mmio_base.unwrap_or(0);
        let offset = addr - base;

        if let Some(state) = &device.mmio_state {
            let state = state
                .read()
                .map_err(|e| VmmError::Device(format!("Failed to lock device state: {e}")))?;

            // Handle config space reads - forward to actual device
            if offset >= virtio_mmio::regs::CONFIG {
                let config_offset = offset - virtio_mmio::regs::CONFIG;
                if let Some(virtio_dev) = &device.virtio_device {
                    let dev = virtio_dev.lock().map_err(|e| {
                        VmmError::Device(format!("Failed to lock virtio device: {e}"))
                    })?;
                    let mut data = vec![0u8; size];
                    dev.read_config(config_offset, &mut data);
                    tracing::trace!(
                        "Config read: device={} offset={:#x} size={} data={:?}",
                        device_id.0,
                        config_offset,
                        size,
                        &data[..size.min(8)]
                    );
                    return Ok(match size {
                        1 => u64::from(data[0]),
                        2 => u64::from(u16::from_le_bytes([data[0], data[1]])),
                        4 => u64::from(u32::from_le_bytes([data[0], data[1], data[2], data[3]])),
                        8 => u64::from_le_bytes([
                            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
                        ]),
                        _ => 0,
                    });
                }
                return Ok(0);
            }

            let value = state.read(offset);
            let result = match size {
                1 => u64::from(value as u8),
                2 => u64::from(value as u16),
                4 => u64::from(value),
                _ => u64::from(value),
            };

            Ok(result)
        } else {
            Ok(0)
        }
    }

    /// Handles MMIO write.
    ///
    /// # Errors
    ///
    /// Returns an error if the write fails.
    pub fn handle_mmio_write(&self, addr: u64, size: usize, value: u64) -> Result<()> {
        let device_id = self
            .find_by_mmio(addr)
            .ok_or_else(|| VmmError::Device(format!("No device at MMIO address {addr:#x}")))?;

        let device = self
            .devices
            .get(&device_id)
            .ok_or_else(|| VmmError::Device(format!("Device {} not found", device_id.0)))?;

        let base = device.info.mmio_base.unwrap_or(0);
        let offset = addr - base;

        if let Some(state) = &device.mmio_state {
            let old_status = {
                let s = state
                    .read()
                    .map_err(|e| VmmError::Device(format!("Failed to lock device state: {e}")))?;
                s.status
            };

            // Handle config space writes - forward to actual device
            if offset >= virtio_mmio::regs::CONFIG {
                let config_offset = offset - virtio_mmio::regs::CONFIG;
                if let Some(virtio_dev) = &device.virtio_device {
                    let mut dev = virtio_dev.lock().map_err(|e| {
                        VmmError::Device(format!("Failed to lock virtio device: {e}"))
                    })?;
                    let data: Vec<u8> = match size {
                        1 => vec![value as u8],
                        2 => (value as u16).to_le_bytes().to_vec(),
                        4 => (value as u32).to_le_bytes().to_vec(),
                        8 => value.to_le_bytes().to_vec(),
                        _ => return Ok(()),
                    };
                    dev.write_config(config_offset, &data);
                }
                return Ok(());
            }

            let value32 = match size {
                1 => value as u32 & 0xFF,
                2 => value as u32 & 0xFFFF,
                4 | 8 => value as u32,
                _ => value as u32,
            };

            // Write to MMIO state
            {
                let mut state = state
                    .write()
                    .map_err(|e| VmmError::Device(format!("Failed to lock device state: {e}")))?;
                state.write(offset, value32);
            }

            // Handle special cases after write
            match offset {
                virtio_mmio::regs::STATUS => {
                    let new_status = value32 as u8;

                    // Handle feature acknowledgment
                    if new_status & DeviceStatus::FEATURES_OK != 0
                        && old_status & DeviceStatus::FEATURES_OK == 0
                    {
                        if let Some(virtio_dev) = &device.virtio_device {
                            let mmio_state = state.read().map_err(|e| {
                                VmmError::Device(format!("Failed to lock device state: {e}"))
                            })?;
                            let mut dev = virtio_dev.lock().map_err(|e| {
                                VmmError::Device(format!("Failed to lock virtio device: {e}"))
                            })?;
                            dev.ack_features(mmio_state.driver_features);
                            tracing::debug!(
                                "Device {} acknowledged features: {:#x}",
                                device_id.0,
                                mmio_state.driver_features
                            );
                        }
                    }

                    // Handle device activation
                    if new_status & DeviceStatus::DRIVER_OK != 0
                        && old_status & DeviceStatus::DRIVER_OK == 0
                    {
                        if let Some(virtio_dev) = &device.virtio_device {
                            let mut dev = virtio_dev.lock().map_err(|e| {
                                VmmError::Device(format!("Failed to lock virtio device: {e}"))
                            })?;
                            dev.activate().map_err(|e| {
                                VmmError::Device(format!("Failed to activate device: {e}"))
                            })?;
                            tracing::info!("Device {} activated", device_id.0);
                        }

                        // Spawn the net-io worker for the primary VirtioNet device.
                        self.maybe_spawn_net_rx_worker(device_id, state);
                    }

                    // Handle device reset
                    if new_status == 0 {
                        if let Some(virtio_dev) = &device.virtio_device {
                            let mut dev = virtio_dev.lock().map_err(|e| {
                                VmmError::Device(format!("Failed to lock virtio device: {e}"))
                            })?;
                            dev.reset();
                            tracing::info!("Device {} reset", device_id.0);
                        }
                    }
                }
                virtio_mmio::regs::QUEUE_NOTIFY => {
                    let queue_idx = value32 as u16;
                    // Log vsock TX notifications at trace level (per-kick hot path).
                    if device.info.device_type == DeviceType::VirtioVsock && queue_idx == 1 {
                        tracing::trace!("QUEUE_NOTIFY: vsock TX queue 1 kicked by guest!",);
                    }
                    tracing::trace!(
                        "QUEUE_NOTIFY: device {} ({:?}) queue {}",
                        device_id.0,
                        device.info.device_type,
                        queue_idx,
                    );

                    if let Some(virtio_dev) = &device.virtio_device {
                        // Build QueueConfig from current MMIO state for the
                        // notified queue index.
                        let qcfg = {
                            let mmio_state = state.read().map_err(|e| {
                                VmmError::Device(format!("Failed to lock state: {e}"))
                            })?;
                            let qi = queue_idx as usize;
                            if qi < 8 {
                                QueueConfig {
                                    desc_addr: mmio_state.queue_desc[qi],
                                    avail_addr: mmio_state.queue_driver[qi],
                                    used_addr: mmio_state.queue_device[qi],
                                    size: mmio_state.queue_num[qi],
                                    ready: mmio_state.queue_ready[qi],
                                    gpa_base: self.guest_ram_gpa,
                                }
                            } else {
                                QueueConfig::default()
                            }
                        };

                        if let (Some(ram_base), ram_size) =
                            (self.guest_ram_base, self.guest_ram_size)
                        {
                            // Build a guest memory slice covering the guest RAM region.
                            // The host pointer `ram_base` maps to GPA `guest_ram_gpa`.
                            // All GPA-based indices must subtract `gpa_base` to obtain
                            // the correct offset within this slice.
                            //
                            // SAFETY: `ram_base` is the host mapping returned by
                            // Virtualization.framework and is valid for `ram_size` bytes.
                            let guest_mem =
                                unsafe { std::slice::from_raw_parts_mut(ram_base, ram_size) };

                            // VirtioBlock async path: dispatch to worker thread
                            // instead of blocking the vCPU with synchronous I/O.
                            if device.info.device_type == DeviceType::VirtioBlock {
                                let workers = self
                                    .blk_workers
                                    .lock()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                                if let Some(handle) = workers.get(&device_id) {
                                    // Ring the queue's doorbell; the owning worker
                                    // drains avail, does the I/O, and completes.
                                    handle.ring(queue_idx);
                                }
                            }
                            // VirtioNet TX (queue 1): extract ethernet frames
                            // from guest memory and write to the network host fd.
                            // This bypasses the generic process_queue — the
                            // concrete `VirtioNet` owns its fd + TX cursor via
                            // `NetPort` and implements the hot path itself.
                            else if device.info.device_type == DeviceType::VirtioNet
                                && queue_idx == 1
                                && (self.primary_net.is_some() || self.bridge_net.is_some())
                            {
                                let is_bridge = self
                                    .bridge_net_device_id
                                    .is_some_and(|bid| bid == device_id);
                                let typed = if is_bridge {
                                    self.bridge_net.as_ref()
                                } else {
                                    self.primary_net.as_ref()
                                };
                                let net_notify = match typed {
                                    Some(arc) => arc.lock().is_ok_and(|d| {
                                        d.drain_tx_queue(&qcfg, finalize_virtio_net_checksum)
                                    }),
                                    None => false,
                                };
                                // `drain_tx_queue` now publishes the used ring
                                // (via SplitQueue, with the StoreLoad barrier) and
                                // avail_event itself; the VMM only raises the IRQ.
                                let _ = guest_mem;

                                if net_notify && device.info.irq.is_some() {
                                    {
                                        let mut s = state.write().map_err(|e| {
                                            VmmError::Device(format!("Failed to lock state: {e}"))
                                        })?;
                                        s.trigger_interrupt(virtio_mmio::INT_VRING);
                                    }
                                    self.sync_irq_level(device_id);
                                }
                            } else {
                                // Generic process_queue for all other devices.
                                let mut dev = virtio_dev.lock().map_err(|e| {
                                    VmmError::Device(format!("Failed to lock device: {e}"))
                                })?;
                                // Log vsock TX processing at trace level (per-kick hot path).
                                let is_vsock_tx = device.info.device_type
                                    == DeviceType::VirtioVsock
                                    && queue_idx == 1;
                                match dev.process_queue(queue_idx, guest_mem, &qcfg) {
                                    Ok(completions) if !completions.is_empty() => {
                                        if is_vsock_tx {
                                            tracing::trace!(
                                                "Vsock QUEUE_NOTIFY TX: {} completions processed!",
                                                completions.len(),
                                            );
                                        }
                                        tracing::trace!(
                                            "Device {} queue {} processed {} completions",
                                            device_id.0,
                                            queue_idx,
                                            completions.len()
                                        );
                                        // Console TX completions don't need interrupts —
                                        // the guest doesn't wait for host ACK on console output.
                                        // Skipping avoids interrupt storms with level-triggered SPIs.
                                        let skip_irq = device.info.device_type
                                            == DeviceType::VirtioConsole
                                            && queue_idx == 1;
                                        if !skip_irq {
                                            {
                                                let mut s = state.write().map_err(|e| {
                                                    VmmError::Device(format!(
                                                        "Failed to lock state: {e}"
                                                    ))
                                                })?;
                                                s.trigger_interrupt(virtio_mmio::INT_VRING);
                                            }
                                            self.sync_irq_level(device_id);
                                        }
                                    }
                                    Ok(_) => {
                                        if is_vsock_tx {
                                            tracing::trace!(
                                                "Vsock QUEUE_NOTIFY TX: kicked but 0 completions \
                                                 (last_avail_idx_tx may already be current)",
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            "Device {} queue {} error: {e}",
                                            device_id.0,
                                            queue_idx
                                        );
                                    }
                                }
                            } // end else (non-VirtioNet)
                        } else {
                            tracing::trace!(
                                "Device {} queue {} notified but no guest memory set",
                                device_id.0,
                                queue_idx
                            );
                        }
                    } else {
                        tracing::trace!(
                            "Device {} queue {} notified (no device impl)",
                            device_id.0,
                            queue_idx
                        );
                    }
                }
                virtio_mmio::regs::INTERRUPT_ACK => {
                    // Sync the GIC SPI level with the updated interrupt_status.
                    // If all bits are cleared, the SPI goes low; if bits remain
                    // (from a concurrent completion), the SPI stays high.
                    self.sync_irq_level(device_id);
                }
                _ => {}
            }
        }

        Ok(())
    }
}
