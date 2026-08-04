//! The on-disk format of `virtio-debug.json`.
//!
//! Hand-written mirror of the `GetVirtioDebug` response. The forensic file
//! is a contract read by humans and scripts (`jq` over counters and ring
//! indices), so its shape is pinned here, independent of whatever codec
//! generates the wire types: a message-layer change must never silently
//! rewrite this format. Field names stay camelCase and unset ring fields
//! serialize as `null`, exactly as the file has always looked.

use arcbox_protocol::v1::{VcpuDebug, VirtioDebugInfo, VirtioDeviceDebug, VirtioQueueDebug};
use serde::Serialize;

/// Root of `virtio-debug.json`: one snapshot of the System VM's virtio
/// devices and vCPU exit counters.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    pub devices: Vec<Device>,
    pub vcpus: Vec<Vcpu>,
    pub kick_broadcasts: u64,
    pub unpark_broadcasts: u64,
}

/// Snapshot of one virtio MMIO device.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Device {
    pub id: u32,
    pub device_type: String,
    pub name: String,
    pub status: u32,
    pub interrupt_status: u32,
    pub event_idx: bool,
    pub interrupts: u64,
    pub queues: Vec<Queue>,
}

/// Snapshot of one virtqueue. Ring fields are `null` when the ring address
/// was never configured or lies outside guest RAM.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Queue {
    pub index: u32,
    pub size: u32,
    pub ready: bool,
    pub kicks: u64,
    pub avail_idx: Option<u32>,
    pub used_idx: Option<u32>,
    pub avail_flags: Option<u32>,
    pub used_flags: Option<u32>,
    pub used_event: Option<u32>,
    pub avail_event: Option<u32>,
}

/// Cumulative exit counters for one vCPU.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Vcpu {
    pub vcpu: u32,
    pub mmio_reads: u64,
    pub mmio_writes: u64,
    pub wfi: u64,
    pub hvc: u64,
    pub smc: u64,
    pub vtimer: u64,
    pub kicks_received: u64,
    pub sysreg: u64,
    pub other: u64,
}

impl From<VirtioDebugInfo> for Snapshot {
    fn from(info: VirtioDebugInfo) -> Self {
        Self {
            devices: info.devices.into_iter().map(Device::from).collect(),
            vcpus: info.vcpus.into_iter().map(Vcpu::from).collect(),
            kick_broadcasts: info.kick_broadcasts,
            unpark_broadcasts: info.unpark_broadcasts,
        }
    }
}

impl From<VirtioDeviceDebug> for Device {
    fn from(dev: VirtioDeviceDebug) -> Self {
        Self {
            id: dev.id,
            device_type: dev.device_type,
            name: dev.name,
            status: dev.status,
            interrupt_status: dev.interrupt_status,
            event_idx: dev.event_idx,
            interrupts: dev.interrupts,
            queues: dev.queues.into_iter().map(Queue::from).collect(),
        }
    }
}

impl From<VirtioQueueDebug> for Queue {
    fn from(q: VirtioQueueDebug) -> Self {
        Self {
            index: q.index,
            size: q.size,
            ready: q.ready,
            kicks: q.kicks,
            avail_idx: q.avail_idx,
            used_idx: q.used_idx,
            avail_flags: q.avail_flags,
            used_flags: q.used_flags,
            used_event: q.used_event,
            avail_event: q.avail_event,
        }
    }
}

impl From<VcpuDebug> for Vcpu {
    fn from(v: VcpuDebug) -> Self {
        Self {
            vcpu: v.vcpu,
            mmio_reads: v.mmio_reads,
            mmio_writes: v.mmio_writes,
            wfi: v.wfi,
            hvc: v.hvc,
            smc: v.smc,
            vtimer: v.vtimer,
            kicks_received: v.kicks_received,
            sysreg: v.sysreg,
            other: v.other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins the file format: camelCase keys, numeric counters as JSON
    /// numbers, unset ring fields as `null`. If this test breaks, so does
    /// every `jq` recipe over preserved forensics — change it deliberately.
    #[test]
    fn the_on_disk_shape_is_stable() {
        let info = VirtioDebugInfo {
            devices: vec![VirtioDeviceDebug {
                id: 3,
                device_type: "VirtioBlk".into(),
                name: "blk0".into(),
                status: 15,
                interrupt_status: 1,
                event_idx: true,
                interrupts: 71,
                queues: vec![VirtioQueueDebug {
                    index: 0,
                    size: 256,
                    ready: true,
                    kicks: 2301,
                    avail_idx: Some(42),
                    used_idx: Some(40),
                    avail_flags: Some(0),
                    used_flags: None,
                    used_event: None,
                    avail_event: Some(41),
                }],
            }],
            vcpus: vec![VcpuDebug {
                vcpu: 1,
                mmio_reads: 10,
                mmio_writes: 20,
                wfi: 30,
                hvc: 4,
                smc: 0,
                vtimer: 5,
                kicks_received: 6,
                sysreg: 7,
                other: 0,
            }],
            kick_broadcasts: 71,
            unpark_broadcasts: 2301,
        };

        let json = serde_json::to_value(Snapshot::from(info)).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "devices": [{
                    "id": 3,
                    "deviceType": "VirtioBlk",
                    "name": "blk0",
                    "status": 15,
                    "interruptStatus": 1,
                    "eventIdx": true,
                    "interrupts": 71,
                    "queues": [{
                        "index": 0,
                        "size": 256,
                        "ready": true,
                        "kicks": 2301,
                        "availIdx": 42,
                        "usedIdx": 40,
                        "availFlags": 0,
                        "usedFlags": null,
                        "usedEvent": null,
                        "availEvent": 41,
                    }],
                }],
                "vcpus": [{
                    "vcpu": 1,
                    "mmioReads": 10,
                    "mmioWrites": 20,
                    "wfi": 30,
                    "hvc": 4,
                    "smc": 0,
                    "vtimer": 5,
                    "kicksReceived": 6,
                    "sysreg": 7,
                    "other": 0,
                }],
                "kickBroadcasts": 71,
                "unparkBroadcasts": 2301,
            })
        );
    }
}
