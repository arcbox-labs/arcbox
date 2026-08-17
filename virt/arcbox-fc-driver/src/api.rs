//! The few Firecracker API calls a running VM needs, over the raw client.
//!
//! `fc_sdk::Vm` wraps the same calls but can only be built by a boot or a
//! restore; an adopted VM has just the socket, so the handle keeps the
//! client and calls through here.

use fc_sdk::Client;
use fc_sdk::types::{
    FullVmConfiguration, InstanceActionInfoActionType, InstanceInfo, PartialDrive,
    SnapshotCreateParams, SnapshotCreateParamsSnapshotType, VmState,
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

/// `PATCH /drives/{id}` — point an existing drive at another host file.
///
/// Firecracker reopens the file and re-reads its capacity; the guest sees a
/// config-change interrupt. A restore uses it while the loaded VM is still
/// paused, so the guest never touches the path the checkpoint recorded.
pub async fn update_drive(client: &Client, drive_id: &str, path_on_host: &str) -> Result<()> {
    client
        .patch_guest_drive_by_id()
        .drive_id(drive_id)
        .body(PartialDrive {
            drive_id: drive_id.to_owned(),
            path_on_host: Some(path_on_host.to_owned()),
            rate_limiter: None,
        })
        .send()
        .await
        .map_err(|e| FcError::Api(e.into()))?;
    Ok(())
}

/// `GET /` — the instance's state (`Running` / `Paused`) among other things.
pub async fn describe(client: &Client) -> Result<InstanceInfo> {
    let info = client
        .describe_instance()
        .send()
        .await
        .map_err(|e| FcError::Api(e.into()))?;
    Ok(info.into_inner())
}

/// `GET /vm/config` — the full configuration, including which devices the
/// VM (booted or restored) actually has.
pub async fn vm_config(client: &Client) -> Result<FullVmConfiguration> {
    let config = client
        .get_export_vm_config()
        .send()
        .await
        .map_err(|e| FcError::Api(e.into()))?;
    Ok(config.into_inner())
}
