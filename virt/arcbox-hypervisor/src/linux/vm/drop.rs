use crate::traits::VirtualMachine;

use super::KvmVm;
use super::virtio::VIRTIO_MMIO_QUEUE_NOTIFY;

impl Drop for KvmVm {
    fn drop(&mut self) {
        // Stop VM if running.
        if self.is_running() {
            let _ = self.stop();
        }

        // Clean up VirtIO device resources.
        if let Ok(devices) = self.virtio_devices.read() {
            for device in devices.iter() {
                // Unregister IRQFD.
                let _ = self.unregister_irqfd(device.irq_fd, device.irq);

                // Unregister IOEVENTFD.
                let notify_addr = device.mmio_base + VIRTIO_MMIO_QUEUE_NOTIFY;
                let _ = self
                    .vm_fd
                    .unregister_ioeventfd(notify_addr, 4, device.notify_fd);

                // Close eventfds.
                unsafe {
                    libc::close(device.irq_fd);
                    libc::close(device.notify_fd);
                }
            }
        }

        tracing::debug!("Dropped VM {}", self.id);
    }
}
