use super::*;

impl DeviceManager {
    /// Polls the bridge (vmnet) host fd for inbound frames and injects
    /// them into the bridge VirtioNet RX queue. Thin shim that reads the
    /// device's current MMIO-transport queue configuration, hands it to
    /// `VirtioNet::poll_rx`, and returns whether any frame was injected.
    /// Caller fires the used-ring interrupt on `true`.
    pub fn poll_bridge_rx(&self) -> bool {
        let Some(bridge_arc) = self.bridge_net.as_ref() else {
            return false;
        };
        let Some(bridge_id) = self.bridge_net_device_id else {
            return false;
        };
        let Some(device) = self.devices.get(&bridge_id) else {
            return false;
        };
        let Some(mmio_arc) = device.mmio_state.as_ref() else {
            return false;
        };

        // Build a snapshot of the RX queue (idx 0) from MMIO state.
        let rx_qcfg = {
            let Ok(mmio) = mmio_arc.read() else {
                return false;
            };
            let qi = 0usize;
            if !mmio.queue_ready[qi] || mmio.queue_num[qi] == 0 {
                return false;
            }
            QueueConfig {
                desc_addr: mmio.queue_desc[qi],
                avail_addr: mmio.queue_driver[qi],
                used_addr: mmio.queue_device[qi],
                size: mmio.queue_num[qi],
                ready: true,
                gpa_base: self.guest_ram_gpa,
            }
        };

        let Ok(dev) = bridge_arc.lock() else {
            return false;
        };
        dev.poll_rx(&rx_qcfg)
    }

    /// Called from the vCPU run loop during WFI (guest idle). Returns
    /// true if any data was injected (caller should trigger interrupt).
    /// Thin shim that builds RX + TX `QueueConfig` snapshots from the
    /// vsock device's MMIO state and forwards to
    /// `VirtioVsock::poll_rx_injection`. The 400-line body that was here
    /// previously now lives on the device.
    pub fn poll_vsock_rx(&self) -> bool {
        let Some(vsock_arc) = self.vsock.as_ref() else {
            return false;
        };
        let Some(device) = self
            .devices
            .values()
            .find(|d| d.info.device_type == DeviceType::VirtioVsock)
        else {
            return false;
        };
        let Some(mmio_arc) = device.mmio_state.as_ref() else {
            return false;
        };

        let (rx_qcfg, tx_qcfg) = {
            let Ok(mmio) = mmio_arc.read() else {
                return false;
            };
            let rxi = 0usize;
            if !mmio.queue_ready[rxi] || mmio.queue_num[rxi] == 0 {
                return false;
            }
            let rx = QueueConfig {
                desc_addr: mmio.queue_desc[rxi],
                avail_addr: mmio.queue_driver[rxi],
                used_addr: mmio.queue_device[rxi],
                size: mmio.queue_num[rxi],
                ready: true,
                gpa_base: self.guest_ram_gpa,
            };
            let txi = 1usize;
            let tx = if mmio.queue_ready[txi] && mmio.queue_num[txi] > 0 {
                Some(QueueConfig {
                    desc_addr: mmio.queue_desc[txi],
                    avail_addr: mmio.queue_driver[txi],
                    used_addr: mmio.queue_device[txi],
                    size: mmio.queue_num[txi],
                    ready: true,
                    gpa_base: self.guest_ram_gpa,
                })
            } else {
                None
            };
            (rx, tx)
        };

        let Ok(mut dev) = vsock_arc.lock() else {
            return false;
        };
        dev.poll_rx_injection(&rx_qcfg, tx_qcfg.as_ref())
    }

    /// Queues host operator input (`data`) onto the virtio-console and injects
    /// it into the guest RX queue (queue 0). Returns `true` if any descriptor
    /// was filled, in which case the caller raises `INT_VRING` for the console.
    ///
    /// Drives the interactive debug console: the `console_rx_worker` reads
    /// operator keystrokes from the Unix socket and forwards them here. Passing
    /// empty `data` just flushes any input buffered from a previous call.
    pub fn console_inject_input(&self, data: &[u8]) -> bool {
        let Some(console_arc) = self.console.as_ref() else {
            return false;
        };
        let Some(device) = self
            .devices
            .values()
            .find(|d| d.info.device_type == DeviceType::VirtioConsole)
        else {
            return false;
        };
        let Some(mmio_arc) = device.mmio_state.as_ref() else {
            return false;
        };

        // RX is queue 0 for virtio-console.
        let rx_qcfg = {
            let Ok(mmio) = mmio_arc.read() else {
                return false;
            };
            let rxi = 0usize;
            if !mmio.queue_ready[rxi] || mmio.queue_num[rxi] == 0 {
                if !data.is_empty() {
                    // ABX-388: operator typed before the guest set up the console
                    // RX queue — the bytes are dropped here, not buffered.
                    tracing::debug!(
                        ready = mmio.queue_ready[rxi],
                        num = mmio.queue_num[rxi],
                        dropped = data.len(),
                        "debug-console: RX queue 0 not ready, dropping operator input"
                    );
                }
                return false;
            }
            QueueConfig {
                desc_addr: mmio.queue_desc[rxi],
                avail_addr: mmio.queue_driver[rxi],
                used_addr: mmio.queue_device[rxi],
                size: mmio.queue_num[rxi],
                ready: true,
                gpa_base: self.guest_ram_gpa,
            }
        };

        let Some(ram_base) = self.guest_ram_base else {
            return false;
        };
        if self.guest_ram_size == 0 {
            return false;
        }
        // SAFETY: `ram_base` is the platform hypervisor's guest-RAM mapping,
        // valid for `guest_ram_size` bytes — same contract as the other
        // guest-memory slices built in this module.
        let guest_mem = unsafe { std::slice::from_raw_parts_mut(ram_base, self.guest_ram_size) };

        let Ok(mut dev) = console_arc.lock() else {
            return false;
        };
        if !data.is_empty() {
            let _ = dev.queue_input(data);
        }
        dev.process_rx_queue(guest_mem, &rx_qcfg).unwrap_or(false)
    }
}
