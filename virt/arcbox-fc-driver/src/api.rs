//! The few Firecracker API calls a running VM needs, over the raw client.
//!
//! `fc_sdk::Vm` wraps the same calls but can only be built by a boot or a
//! restore; an adopted VM has just the socket, so the handle keeps the
//! client and calls through here.

use fc_sdk::Client;
use fc_sdk::types::{
    InstanceActionInfoActionType, SnapshotCreateParams, SnapshotCreateParamsSnapshotType, VmState,
};

use crate::error::{FcError, Result};

/// `PATCH /vm {"state": "Paused"}`.
pub async fn pause(client: &Client) -> Result<()> {
    client
        .patch_vm()
        .body_map(|b| b.state(VmState::Paused))
        .send()
        .await
        .map_err(|e| FcError::Api(e.into()))?;
    Ok(())
}

/// `PATCH /vm {"state": "Resumed"}`.
pub async fn resume(client: &Client) -> Result<()> {
    client
        .patch_vm()
        .body_map(|b| b.state(VmState::Resumed))
        .send()
        .await
        .map_err(|e| FcError::Api(e.into()))?;
    Ok(())
}

/// `PUT /actions {"action_type": "SendCtrlAltDel"}` — asks the guest to
/// reboot, which Firecracker turns into a VM exit.
pub async fn send_ctrl_alt_del(client: &Client) -> Result<()> {
    client
        .create_sync_action()
        .body_map(|b| b.action_type(InstanceActionInfoActionType::SendCtrlAltDel))
        .send()
        .await
        .map_err(|e| FcError::Api(e.into()))?;
    Ok(())
}

/// `PUT /snapshot/create` of a full snapshot; the VM must be paused.
pub async fn create_snapshot(client: &Client, vmstate: &str, mem: &str) -> Result<()> {
    client
        .create_snapshot()
        .body(SnapshotCreateParams {
            snapshot_path: vmstate.to_owned(),
            mem_file_path: mem.to_owned(),
            snapshot_type: Some(SnapshotCreateParamsSnapshotType::Full),
        })
        .send()
        .await
        .map_err(|e| FcError::Api(e.into()))?;
    Ok(())
}
