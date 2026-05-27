//! Docker container lifecycle event listener.
//!
//! Connects to `/var/run/docker.sock`, performs initial reconciliation of
//! running containers, then subscribes to container events (start, die,
//! destroy, rename) to keep the guest DNS server registry in sync.

use std::net::Ipv4Addr;
use std::path::Path;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio_util::sync::CancellationToken;

use crate::dns_server::GuestDnsServer;

const DOCKER_SOCK: &str = "/var/run/docker.sock";
const RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(1);

/// Runs initial reconciliation then watches Docker events indefinitely.
///
/// Retries connection with backoff until the Docker socket appears.
/// Blocks until `cancel` is triggered.
pub async fn reconcile_and_watch(dns: &GuestDnsServer, cancel: CancellationToken) {
    loop {
        // Wait for socket to exist.
        while !Path::new(DOCKER_SOCK).exists() {
            tokio::select! {
                () = cancel.cancelled() => return,
                () = tokio::time::sleep(RETRY_DELAY) => {}
            }
        }

        match run_once(dns, &cancel).await {
            Ok(()) => return, // cancelled
            Err(e) => {
                tracing::warn!(error = %e, "docker event listener disconnected, retrying");
                tokio::select! {
                    () = cancel.cancelled() => return,
                    () = tokio::time::sleep(RETRY_DELAY) => {}
                }
            }
        }
    }
}

/// Single connection lifecycle: reconcile + event stream.
async fn run_once(dns: &GuestDnsServer, cancel: &CancellationToken) -> anyhow::Result<()> {
    // Phase 1: list all running containers and register them.
    if let Err(e) = reconcile_existing(dns).await {
        tracing::warn!(error = %e, "initial container reconciliation failed");
    }

    // Phase 2: subscribe to container lifecycle events.
    let stream = UnixStream::connect(DOCKER_SOCK).await?;
    let (reader, mut writer) = tokio::io::split(stream);

    let request = "GET /events?filters=%7B%22type%22%3A%5B%22container%22%5D%7D HTTP/1.1\r\n\
                   Host: localhost\r\n\
                   Connection: keep-alive\r\n\r\n";
    writer.write_all(request.as_bytes()).await?;

    let mut lines = BufReader::new(reader).lines();

    // Skip HTTP response headers.
    loop {
        let Some(line) = read_line_or_cancel(&mut lines, cancel).await? else {
            return Ok(());
        };
        if line.is_empty() {
            break; // end of headers
        }
    }

    // Process chunked event stream.
    loop {
        let Some(line) = read_line_or_cancel(&mut lines, cancel).await? else {
            return Ok(());
        };

        // Docker chunked encoding: hex size line, then JSON line.
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
            continue;
        }

        if let Err(e) = handle_event(dns, trimmed).await {
            tracing::debug!(error = %e, "failed to process docker event");
        }
    }
}

/// Reads one line, returning `None` if cancelled.
async fn read_line_or_cancel(
    lines: &mut tokio::io::Lines<BufReader<tokio::io::ReadHalf<UnixStream>>>,
    cancel: &CancellationToken,
) -> anyhow::Result<Option<String>> {
    tokio::select! {
        () = cancel.cancelled() => Ok(None),
        result = lines.next_line() => {
            match result? {
                Some(line) => Ok(Some(line)),
                None => anyhow::bail!("event stream ended"),
            }
        }
    }
}

/// Lists running containers and registers them in the DNS server.
async fn reconcile_existing(dns: &GuestDnsServer) -> anyhow::Result<()> {
    let containers = docker_get("/containers/json").await?;
    let arr = containers
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("expected array"))?;

    for c in arr {
        let Some(id) = c["Id"].as_str() else {
            continue;
        };
        let short_id = &id[..12.min(id.len())];
        if let Err(e) = register_container_by_id(dns, short_id).await {
            tracing::debug!(id = short_id, error = %e, "failed to register container");
        }
    }

    tracing::info!(count = arr.len(), "reconciled existing containers");
    Ok(())
}

/// Handles a single Docker event JSON line.
async fn handle_event(dns: &GuestDnsServer, json_str: &str) -> anyhow::Result<()> {
    let event: serde_json::Value = serde_json::from_str(json_str)?;

    let action = event["Action"].as_str().unwrap_or_default();
    let id_full = event["Actor"]["ID"].as_str().unwrap_or_default();
    let id = &id_full[..12.min(id_full.len())];

    match action {
        "start" => {
            register_container_by_id(dns, id).await?;
        }
        "die" | "destroy" => {
            // Deregister this container's ownership of all its aliases.
            // Shared aliases (compose service names) are only removed from
            // DNS when no other replica still references them.
            let attrs = &event["Actor"]["Attributes"];
            let name = attrs["name"].as_str().unwrap_or_default();
            if !name.is_empty() {
                let compose = attrs.as_object().and_then(crate::dns::extract_compose_info);
                for alias in crate::dns::collect_aliases(name, compose.as_ref()) {
                    dns.deregister_container(&alias, name).await;
                }
            }
        }
        "rename" => {
            // Deregister old name's ownership, register under new name.
            let attrs = &event["Actor"]["Attributes"];
            let old_name = attrs["oldName"]
                .as_str()
                .unwrap_or_default()
                .trim_start_matches('/');
            if !old_name.is_empty() {
                let compose = attrs.as_object().and_then(crate::dns::extract_compose_info);
                for alias in crate::dns::collect_aliases(old_name, compose.as_ref()) {
                    dns.deregister_container(&alias, old_name).await;
                }
            }
            register_container_by_id(dns, id).await?;
        }
        _ => {}
    }

    Ok(())
}

/// Inspects a container and registers its name + IP in the DNS server.
async fn register_container_by_id(dns: &GuestDnsServer, id: &str) -> anyhow::Result<()> {
    let info = docker_get(&format!("/containers/{id}/json")).await?;

    let name = info["Name"]
        .as_str()
        .unwrap_or_default()
        .trim_start_matches('/');
    if name.is_empty() {
        return Ok(());
    }

    // Find the first network with a valid IP.
    let networks = &info["NetworkSettings"]["Networks"];
    let ip = networks
        .as_object()
        .and_then(|nets| {
            nets.values().find_map(|net| {
                let ip_str = net["IPAddress"].as_str()?;
                ip_str.parse::<Ipv4Addr>().ok()
            })
        })
        .ok_or_else(|| anyhow::anyhow!("no IP for container {name}"))?;

    // Extract compose metadata from labels for hierarchical DNS names.
    let compose = info["Config"]["Labels"]
        .as_object()
        .and_then(crate::dns::extract_compose_info);

    // Register the container name and any compose aliases.
    // The container name is the owner — shared aliases (like compose
    // service names) are ref-counted per owner in the DNS server.
    let aliases = crate::dns::collect_aliases(name, compose.as_ref());
    for alias in &aliases {
        dns.register_container(alias, name, ip).await;
    }

    tracing::debug!(name, %ip, aliases = ?aliases, "registered container DNS");
    Ok(())
}

/// Performs a GET request to the Docker Engine API via Unix socket.
async fn docker_get(path: &str) -> anyhow::Result<serde_json::Value> {
    let stream = UnixStream::connect(DOCKER_SOCK).await?;
    let (reader, mut writer) = tokio::io::split(stream);

    let request = format!("GET {path} HTTP/1.0\r\nHost: localhost\r\n\r\n");
    writer.write_all(request.as_bytes()).await?;
    writer.shutdown().await?;

    let mut buf = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut BufReader::new(reader), &mut buf).await?;

    // Split HTTP response: headers \r\n\r\n body
    let body_start = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(0, |p| p + 4);
    let body = &buf[body_start..];

    Ok(serde_json::from_slice(body)?)
}
