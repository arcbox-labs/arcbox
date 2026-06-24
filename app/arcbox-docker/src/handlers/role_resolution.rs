//! Docker workload URI to utility VM role resolution.

use super::{ensure_role_ready, extract_container_id, extract_exec_id};
use crate::api::AppState;
use crate::error::{DockerError, Result};
use crate::routing::UtilityVmRole;
use crate::workload::WorkloadRoleLookup;
use axum::http::{HeaderMap, Method, Uri};
use bytes::Bytes;

/// Resolves the utility VM role for a `/containers/{id}/...` URI.
///
/// Lookup order:
///
/// 1. Consult the in-process [`WorkloadRoleRegistry`]. A
///    [`WorkloadRoleLookup::Found`] returns the role directly. A
///    [`WorkloadRoleLookup::Ambiguous`] short ID surfaces as a 409
///    Conflict so we never silently pick a workload.
/// 2. On [`WorkloadRoleLookup::Missing`] (e.g. after a daemon restart),
///    probe the single HV guest dockerd. A hit is recorded and returned;
///    a miss falls back to `native` so the request still reaches the HV
///    guest, which returns the appropriate `404 No such container`.
///
/// ABX-375 runs one runtime VM, so the resolved role is always
/// [`UtilityVmRole::Native`]; the registry still disambiguates short
/// IDs / names within that VM.
pub async fn resolve_container_role(state: &AppState, uri: &Uri) -> Result<UtilityVmRole> {
    let Some(id) = extract_container_id(uri) else {
        return Ok(UtilityVmRole::Native);
    };
    match state.workload_roles.lookup(&id).await {
        WorkloadRoleLookup::Found(role) => Ok(role),
        WorkloadRoleLookup::Ambiguous => Err(ambiguous_workload_error(&id)),
        WorkloadRoleLookup::Missing => match rebuild_container_role_from_guests(state, &id).await {
            WorkloadRoleLookup::Found(role) => {
                state.workload_roles.record(id.clone(), role).await;
                tracing::debug!(
                    container_id = %id,
                    utility_vm = role.as_str(),
                    "rebuilt workload role from guest dockerd",
                );
                Ok(role)
            }
            WorkloadRoleLookup::Ambiguous => Err(ambiguous_workload_error(&id)),
            WorkloadRoleLookup::Missing => Ok(UtilityVmRole::Native),
        },
    }
}

/// Resolves the utility VM role for an `/exec/{id}/...` URI.
///
/// Returns the recorded role on hit, fails closed with 409 on an
/// ambiguous short ID, and falls back to `native` only when no role is
/// known at all.
pub async fn resolve_exec_role(state: &AppState, uri: &Uri) -> Result<UtilityVmRole> {
    let Some(id) = extract_exec_id(uri) else {
        return Ok(UtilityVmRole::Native);
    };
    match state.workload_roles.lookup(&id).await {
        WorkloadRoleLookup::Found(role) => Ok(role),
        WorkloadRoleLookup::Ambiguous => Err(ambiguous_workload_error(&id)),
        WorkloadRoleLookup::Missing => Ok(UtilityVmRole::Native),
    }
}

/// Resolves the utility VM role for any Docker request URI that may carry a
/// workload identity (container or exec). Used by the catch-all proxy
/// fallback so unrouted endpoints like `/containers/{id}/archive` still
/// land on the role that owns the container.
///
/// Surfaces ambiguity as a 409 the same way the per-handler resolvers do;
/// rebuilds from guest dockerds on registry miss for container URIs.
pub async fn resolve_role_from_uri(state: &AppState, uri: &Uri) -> Result<UtilityVmRole> {
    if let Some(id) = extract_container_id(uri) {
        match state.workload_roles.lookup(&id).await {
            WorkloadRoleLookup::Found(role) => return Ok(role),
            WorkloadRoleLookup::Ambiguous => return Err(ambiguous_workload_error(&id)),
            WorkloadRoleLookup::Missing => {}
        }
        match rebuild_container_role_from_guests(state, &id).await {
            WorkloadRoleLookup::Found(role) => {
                state.workload_roles.record(id.clone(), role).await;
                return Ok(role);
            }
            WorkloadRoleLookup::Ambiguous => return Err(ambiguous_workload_error(&id)),
            WorkloadRoleLookup::Missing => {}
        }
    }
    if let Some(id) = extract_exec_id(uri) {
        match state.workload_roles.lookup(&id).await {
            WorkloadRoleLookup::Found(role) => return Ok(role),
            WorkloadRoleLookup::Ambiguous => return Err(ambiguous_workload_error(&id)),
            WorkloadRoleLookup::Missing => {}
        }
    }
    Ok(UtilityVmRole::Native)
}

/// Recovers the role for a container whose binding is missing from the
/// in-process registry (e.g. after an `arcbox-daemon` restart) by probing
/// the runtime guest dockerd.
///
/// ABX-375: runtime is single-VM, so this probes **only** the HV (Native)
/// VM. It must never probe the VZ/Rosetta build backend — doing so would
/// boot a VZ VM that the runtime path is required never to start.
async fn rebuild_container_role_from_guests(
    state: &AppState,
    container_id: &str,
) -> WorkloadRoleLookup {
    if probe_container_exists(state, UtilityVmRole::Native, container_id).await {
        WorkloadRoleLookup::Found(UtilityVmRole::Native)
    } else {
        WorkloadRoleLookup::Missing
    }
}

/// Returns a 409 Conflict describing an ambiguous workload identifier.
///
/// Surfaced when a short ID / name resolves to more than one binding in the
/// registry. Runtime is single-VM, so ambiguity comes from prefix collisions
/// within the one VM, not cross-VM.
fn ambiguous_workload_error(id: &str) -> DockerError {
    DockerError::Conflict(format!(
        "workload identifier '{id}' is ambiguous: it matches multiple workloads. \
         Use the full canonical container ID."
    ))
}

/// Returns `true` if `container_id` exists on `role`'s guest dockerd.
///
/// Uses the same vsock connector + buffered HTTP/1.1 client as the rest
/// of the proxy stack, so a probe failure surfaces the same way as any
/// other guest-side error.
async fn probe_container_exists(state: &AppState, role: UtilityVmRole, container_id: &str) -> bool {
    if ensure_role_ready(state, role).await.is_err() {
        return false;
    }
    let path = format!("/containers/{container_id}/json");
    match crate::proxy::proxy_to_guest_for_role_pooled(
        state.proxy.client(),
        role,
        Method::GET,
        &path,
        &HeaderMap::new(),
        Bytes::new(),
    )
    .await
    {
        Ok(resp) => resp.status().is_success(),
        Err(_) => false,
    }
}
