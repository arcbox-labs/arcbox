//! Runtime admission checks for Docker workload requests.

use crate::api::AppState;
use crate::error::{DockerError, Result};

/// Fail-closed admission for a routed runtime workload.
///
/// `linux/amd64` containers run via FEX inside the HV guest. If FEX is
/// not provisioned (`<data_dir>/runtime/bin/FEX` absent → no x86_64 `binfmt_misc`
/// handler in the guest), this returns a clear error instead of letting the
/// request silently route to VZ/Rosetta or QEMU, or fail later with a
/// cryptic `exec format error`. Native (arm64) workloads are always admitted.
pub async fn require_amd64_runtime(
    state: &AppState,
    route: crate::routing::RoutingDecision,
) -> Result<()> {
    if crate::routing::is_admissible(route, state.runtime.amd64_runtime_supported()) {
        return Ok(());
    }
    Err(DockerError::NotImplemented(format!(
        "linux/amd64 runtime requires FEX in the HV guest, which is not provisioned \
         (expected /arcbox/runtime/bin/FEX). amd64 runtime containers are served by FEX \
         inside the single HV utility VM; ArcBox does not fall back to a VZ/Rosetta runtime \
         VM. Requested platform: {:?}.",
        route.platform,
    )))
}
