use super::{extract_container_id, proxy_to_system_vm, require_amd64_runtime};
use crate::api::AppState;
use crate::error::{DockerError, Result};
use crate::port_bindings::parse_port_bindings;
use crate::routing::{query_param, route_container_create};
use axum::body::Body;
use axum::extract::{OriginalUri, State};
use axum::http::{Request, Uri};
use axum::response::Response;
use bytes::Bytes;
use std::net::IpAddr;

/// Create a container, resolving macOS symlinks in bind-mount source paths.
///
/// On macOS, `/tmp` → `/private/tmp` and `/var` → `/private/var`. The guest
/// mounts host `/private` via VirtioFS while its `/tmp` and `/var` are
/// isolated tmpfs. This handler resolves the top-level symlink so
/// bind-mount paths land on the VirtioFS share.
///
/// ABX-375: every runtime container runs in the single HV system VM.
/// `linux/amd64` is executed via FEX inside that VM; if FEX is not
/// provisioned in the guest, the request fails closed with a clear error
/// rather than silently routing to VZ/Rosetta or QEMU. Compose projects need
/// no cross-VM scheduling — all services share the one HV VM.
///
/// On a successful response the canonical container ID (and any `--name`) is
/// recorded so follow-up lifecycle calls resolve to the same VM.
#[tracing::instrument(
    name = "docker.container.create",
    skip(state, req),
    fields(
        uri = %uri,
        utility_vm = "native",
        translator = tracing::field::Empty,
        container_id = tracing::field::Empty,
        name = tracing::field::Empty,
    ),
    err
)]
pub async fn create_container(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    req: Request<Body>,
) -> Result<Response> {
    let (parts, body) = req.into_parts();
    let body_bytes = http_body_util::BodyExt::collect(body)
        .await
        .map_err(|e| DockerError::Server(format!("failed to read body: {e}")))?
        .to_bytes();

    let body_bytes = crate::host_path::rewrite_create_body(body_bytes);
    let route = route_container_create(&uri, &body_bytes);
    let requested_name = query_param(&uri, "name").map(str::to_string);
    tracing::Span::current().record("translator", route.translator.as_str());
    if let Some(name) = requested_name.as_deref() {
        tracing::Span::current().record("name", name);
    }

    // Fail closed: amd64 runtime requires FEX in the HV guest. Never fall
    // back to a VZ/Rosetta runtime VM for a default amd64 container.
    require_amd64_runtime(&state, route).await?;

    tracing::debug!(
        backend = "hv",
        translator = route.translator.as_str(),
        platform = ?route.platform,
        name = requested_name.as_deref().unwrap_or(""),
        "routing Docker container create request"
    );
    let mut req = Request::from_parts(parts, Body::from(body_bytes));
    // Body may have changed size; remove Content-Length so the proxy
    // recomputes framing from the actual body.
    req.headers_mut().remove(axum::http::header::CONTENT_LENGTH);

    proxy_to_system_vm(&state, &uri, req).await
}

/// Start a container, then set up host-side port forwarding and DNS.
///
/// # Errors
///
/// Returns an error if VM readiness fails or proxying to guest dockerd fails.
#[tracing::instrument(
    name = "docker.container.start",
    skip(state, req),
    fields(uri = %uri, utility_vm = "native", container_id = tracing::field::Empty),
    err
)]
pub async fn start_container(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    req: Request<Body>,
) -> Result<Response> {
    let container_id = extract_container_id(&uri);
    if let Some(id) = container_id.as_deref() {
        tracing::Span::current().record("container_id", id);
    }

    // Proxy start request to guest.
    let response = proxy_to_system_vm(&state, &uri, req).await?;

    // On success, inspect the container and set up port forwarding + DNS.
    if response.status().is_success() {
        if let Some(ref id) = container_id {
            setup_container_networking(&state, id).await;
        }
    }

    Ok(response)
}

/// Stop a container and tear down its port forwarding + DNS.
///
/// # Errors
///
/// Returns an error if VM readiness fails or proxying to guest dockerd fails.
#[tracing::instrument(
    name = "docker.container.stop",
    skip(state, req),
    fields(uri = %uri, utility_vm = "native", container_id = tracing::field::Empty),
    err
)]
pub async fn stop_container(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    req: Request<Body>,
) -> Result<Response> {
    if let Some(id) = extract_container_id(&uri) {
        tracing::Span::current().record("container_id", id.as_str());
    }
    // Resolve canonical ID before proxy — the name/short-id is still valid now
    // but may become stale after stop (e.g. --rm containers).
    let canonical = resolve_or_raw_for_teardown(&state, &uri).await;

    let response = proxy_to_system_vm(&state, &uri, req).await?;

    // Tear down networking after a terminal stop response.
    // Docker returns 204 on success and 304 when already stopped.
    let status = response.status().as_u16();
    if status == 204 || status == 304 {
        if let Some(canonical) = canonical {
            state.runtime.stop_port_forwarding_by_id(&canonical).await;
            state.runtime.deregister_dns_by_id(&canonical).await;
        }
    }

    Ok(response)
}

/// Whether a `POST /containers/{id}/kill?signal=…` request terminates the
/// container, so its host networking should be torn down.
///
/// Docker returns 204 for *any* delivered signal — e.g. `SIGHUP` to reload
/// nginx or `SIGUSR1` — not just fatal ones, so teardown must key off the
/// signal, not the 204. Only the default (no `signal` = SIGKILL) and an
/// explicit SIGKILL are guaranteed to stop the container; anything else is
/// treated as non-terminating (SIGTERM may be caught; SIGHUP/SIGUSR* are
/// reload/notify signals). If such a signal does end up killing the container,
/// the death-event teardown path removes its host state instead.
fn kill_terminates_container(uri: &Uri) -> bool {
    match query_param(uri, "signal") {
        None => true, // Docker's default kill signal is SIGKILL.
        Some(signal) => {
            let signal = signal.trim();
            signal.eq_ignore_ascii_case("SIGKILL")
                || signal.eq_ignore_ascii_case("KILL")
                || signal == "9"
        }
    }
}

/// Kill a container and tear down its port forwarding + DNS.
///
/// # Errors
///
/// Returns an error if VM readiness fails or proxying to guest dockerd fails.
#[tracing::instrument(
    name = "docker.container.kill",
    skip(state, req),
    fields(uri = %uri, utility_vm = "native", container_id = tracing::field::Empty),
    err
)]
pub async fn kill_container(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    req: Request<Body>,
) -> Result<Response> {
    if let Some(id) = extract_container_id(&uri) {
        tracing::Span::current().record("container_id", id.as_str());
    }
    // Resolve canonical ID before proxy — kill with --rm triggers auto-remove.
    let canonical = resolve_or_raw_for_teardown(&state, &uri).await;

    let terminates = kill_terminates_container(&uri);
    let response = proxy_to_system_vm(&state, &uri, req).await?;

    // Docker kill returns 204 for any delivered signal; only tear down when the
    // signal actually terminates the container (see `kill_terminates_container`).
    if response.status().as_u16() == 204 && terminates {
        if let Some(canonical) = canonical {
            state.runtime.stop_port_forwarding_by_id(&canonical).await;
            state.runtime.deregister_dns_by_id(&canonical).await;
        }
    }

    Ok(response)
}

/// Restart a container and refresh its DNS entry.
///
/// # Errors
///
/// Returns an error if VM readiness fails or proxying to guest dockerd fails.
#[tracing::instrument(
    name = "docker.container.restart",
    skip(state, req),
    fields(uri = %uri, utility_vm = "native", container_id = tracing::field::Empty),
    err
)]
pub async fn restart_container(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    req: Request<Body>,
) -> Result<Response> {
    if let Some(id) = extract_container_id(&uri) {
        tracing::Span::current().record("container_id", id.as_str());
    }
    let response = proxy_to_system_vm(&state, &uri, req).await?;

    // Docker restart returns 204 on success. Refresh DNS (container may get
    // a new IP) with a single inspect call for both canonical ID and DNS info.
    // Port forwarding targets the guest VM and survives container restarts.
    if response.status().as_u16() == 204 {
        if let Some(id) = extract_container_id(&uri) {
            let _ = state.runtime.ensure_vm_ready().await;
            if let Some(body_bytes) = inspect_container_body(&state, &id).await {
                let canonical = canonical_id_or_fallback(&id, &body_bytes);
                if let Some((aliases, ip)) = extract_container_dns_info(&body_bytes) {
                    state.runtime.register_dns(&canonical, &aliases, ip).await;
                }
            }
        }
    }

    Ok(response)
}

/// Remove a container and tear down its port forwarding + DNS.
///
/// # Errors
///
/// Returns an error if VM readiness fails or proxying to guest dockerd fails.
#[tracing::instrument(
    name = "docker.container.remove",
    skip(state, req),
    fields(uri = %uri, utility_vm = "native", container_id = tracing::field::Empty),
    err
)]
pub async fn remove_container(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    req: Request<Body>,
) -> Result<Response> {
    if let Some(id) = extract_container_id(&uri) {
        tracing::Span::current().record("container_id", id.as_str());
    }
    // Resolve canonical ID before proxy — the name/short-id is still valid now.
    let canonical = resolve_or_raw_for_teardown(&state, &uri).await;

    let response = proxy_to_system_vm(&state, &uri, req).await?;

    // Only tear down networking after a successful remove.
    if response.status().is_success() {
        if let Some(canonical) = canonical {
            state.runtime.stop_port_forwarding_by_id(&canonical).await;
            state.runtime.deregister_dns_by_id(&canonical).await;
        }
    }

    Ok(response)
}

/// Inspect a started container and configure port forwarding + DNS registration.
///
/// Shares a single inspect call for both port forwarding and DNS setup.
async fn setup_container_networking(state: &AppState, container_id: &str) {
    let Some(body_bytes) = inspect_container_body(state, container_id).await else {
        tracing::warn!(
            container_id,
            "Failed to inspect container for networking setup; \
             port forwarding and DNS will not be configured"
        );
        return;
    };

    // Use the canonical full container ID from inspect (not the URI token which
    // may be a name or short ID) so that stop/remove can reliably match the key.
    let canonical_id = canonical_id_or_fallback(container_id, &body_bytes);

    // Port forwarding.
    setup_port_forwarding_from_inspect(state, &canonical_id, &body_bytes).await;

    // DNS registration.
    if let Some((aliases, ip)) = extract_container_dns_info(&body_bytes) {
        state
            .runtime
            .register_dns(&canonical_id, &aliases, ip)
            .await;
    }
}

/// Fetches the inspect JSON body for a container from guest dockerd.
async fn inspect_container_body(state: &AppState, container_id: &str) -> Option<Bytes> {
    crate::guest_query::inspect_container(state.proxy.client(), container_id).await
}

/// Configures port forwarding from pre-fetched inspect JSON.
async fn setup_port_forwarding_from_inspect(
    state: &AppState,
    canonical_id: &str,
    body_bytes: &[u8],
) {
    let bindings = parse_port_bindings(body_bytes);
    if bindings.is_empty() {
        tracing::debug!("No port bindings found for container {}", canonical_id);
        return;
    }

    tracing::info!(
        "Port forwarding: {} bindings for container {}",
        bindings.len(),
        canonical_id,
    );
    for b in &bindings {
        tracing::info!(
            "  bind {}:{} → container:{}/{}",
            b.host_ip,
            b.host_port,
            b.container_port,
            b.protocol,
        );
    }

    let rules: Vec<_> = bindings
        .iter()
        .map(|b| {
            (
                b.host_ip.clone(),
                b.host_port,
                b.container_port,
                b.protocol.clone(),
            )
        })
        .collect();

    let machine_name = state.runtime.default_machine_name();
    if let Err(e) = state
        .runtime
        .start_port_forwarding_for(machine_name, canonical_id, &rules)
        .await
    {
        tracing::warn!(
            utility_vm = "native",
            "Failed to start port forwarding for {}: {}",
            canonical_id,
            e,
        );
    }
}

/// Extracts DNS aliases and IP address from Docker inspect JSON.
///
/// For compose containers (with `com.docker.compose.project` and
/// `com.docker.compose.service` labels), returns:
/// `["service.project", "container_name"]` — a hierarchical service alias
/// plus the flat container name.
///
/// For plain containers, returns `["container_name"]`.
///
/// Falls back through `/NetworkSettings/IPAddress` → per-network IPs.
pub fn extract_container_dns_info(inspect_json: &[u8]) -> Option<(Vec<String>, IpAddr)> {
    let v: serde_json::Value = serde_json::from_slice(inspect_json).ok()?;
    let name = v.get("Name")?.as_str()?.trim_start_matches('/').to_string();

    if name.is_empty() {
        return None;
    }

    // Primary: top-level IPAddress.
    let ip_str = v
        .pointer("/NetworkSettings/IPAddress")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        // Fallback: first non-empty IP from Networks map.
        .or_else(|| {
            v.pointer("/NetworkSettings/Networks")?
                .as_object()?
                .values()
                .find_map(|net| net.get("IPAddress")?.as_str().filter(|s| !s.is_empty()))
        })?;

    // Build DNS aliases from compose labels when available.
    let aliases = match v.pointer("/Config/Labels").and_then(|l| l.as_object()) {
        Some(labels) => {
            let project = labels
                .get("com.docker.compose.project")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty());
            let service = labels
                .get("com.docker.compose.service")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty());
            match (project, service) {
                // Compose: service-level hierarchical + flat container name.
                (Some(proj), Some(svc)) => {
                    vec![format!("{svc}.{proj}"), name]
                }
                _ => vec![name],
            }
        }
        None => vec![name],
    };

    Some((aliases, ip_str.parse().ok()?))
}

/// Rename a container and update its DNS entry.
///
/// # Errors
///
/// Returns an error if VM readiness fails or proxying to guest dockerd fails.
#[tracing::instrument(
    name = "docker.container.rename",
    skip(state, req),
    fields(
        uri = %uri,
        utility_vm = "native",
        container_id = tracing::field::Empty,
        new_name = tracing::field::Empty,
    ),
    err
)]
pub async fn rename_container(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    req: Request<Body>,
) -> Result<Response> {
    if let Some(id) = extract_container_id(&uri) {
        tracing::Span::current().record("container_id", id.as_str());
    }
    // Resolve canonical ID BEFORE proxy — the old name/short-id is still valid
    // now but will be invalid after a successful rename.
    let canonical = resolve_canonical_from_uri(&state, &uri).await;
    let new_name = query_param(&uri, "name").map(str::to_string);
    if let Some(name) = new_name.as_deref() {
        tracing::Span::current().record("new_name", name);
    }

    // Proxy rename to guest.
    let response = proxy_to_system_vm(&state, &uri, req).await?;

    if response.status().is_success() {
        if let Some(ref canonical) = canonical {
            // Remove the old DNS entry, then inspect (using the canonical ID,
            // which survives rename) to get the new name + IP and re-register.
            state.runtime.deregister_dns_by_id(canonical).await;

            if let Some(body_bytes) = inspect_container_body(&state, canonical).await
                && let Some((aliases, ip)) = extract_container_dns_info(&body_bytes)
            {
                state.runtime.register_dns(canonical, &aliases, ip).await;
            }
        }
    }

    Ok(response)
}

/// Extracts the canonical full container ID from a Docker inspect JSON response.
fn extract_canonical_id_from_inspect(inspect_json: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(inspect_json).ok()?;
    value.get("Id")?.as_str().map(String::from)
}

/// Returns the canonical container ID from inspect JSON, falling back to the
/// original request token when the inspect payload does not contain a usable ID.
fn canonical_id_or_fallback(container_id: &str, inspect_json: &[u8]) -> String {
    extract_canonical_id_from_inspect(inspect_json).unwrap_or_else(|| container_id.to_string())
}

/// Extracts a container identifier from the URI and resolves it to the
/// canonical full ID via an inspect against guest dockerd.
/// Returns `None` (with a warning) when canonical resolution fails.
///
/// Teardown handlers (stop/kill/remove) layer a raw-ID fallback on top
/// of this via [`resolve_or_raw_for_teardown`] so transient inspect
/// failures don't leak port forwarding listeners and DNS entries.
/// Non-teardown callers (e.g. rename) must keep using the strict result:
/// a raw URI token that is a name becomes stale after a successful
/// rename, which would break DNS re-registration.
///
/// Best-effort wakes the VM before inspecting, since
/// [`resolve_canonical_id`] uses `proxy_to_guest_pooled` directly and
/// does not call `ensure_vm_ready` itself. Readiness failures are not
/// fatal — the subsequent inspect will surface them as a `None` resolution.
async fn resolve_canonical_from_uri(state: &AppState, uri: &Uri) -> Option<String> {
    let id = extract_container_id(uri)?;
    // Best-effort wake; if it fails, the inspect call below will too.
    let _ = state.runtime.ensure_vm_ready().await;
    match resolve_canonical_id(state, &id).await {
        Some(canonical) => Some(canonical),
        None => {
            tracing::warn!(
                container_id = %id,
                utility_vm = "native",
                "Failed to resolve canonical container ID"
            );
            None
        }
    }
}

/// Variant of [`resolve_canonical_from_uri`] for teardown handlers
/// (stop/kill/remove): on canonical-resolution failure, falls back to
/// the raw URI-extracted ID so cleanup of port forwarding + DNS still
/// runs. A non-matching key is a no-op against the canonical-keyed maps
/// — strictly better than skipping teardown entirely.
async fn resolve_or_raw_for_teardown(state: &AppState, uri: &Uri) -> Option<String> {
    if let Some(canonical) = resolve_canonical_from_uri(state, uri).await {
        return Some(canonical);
    }
    let raw = extract_container_id(uri)?;
    tracing::warn!(
        container_id = %raw,
        utility_vm = "native",
        "Using raw URI-extracted ID for networking teardown"
    );
    Some(raw)
}

/// Resolves a container name, short ID, or full ID to the canonical full ID
/// by inspecting the container on guest dockerd.
async fn resolve_canonical_id(state: &AppState, id: &str) -> Option<String> {
    let body = crate::guest_query::inspect_container(state.proxy.client(), id).await?;
    extract_canonical_id_from_inspect(&body)
}

#[cfg(test)]
mod tests;
