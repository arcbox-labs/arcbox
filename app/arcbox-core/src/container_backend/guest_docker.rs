use super::ContainerBackend;
use crate::config::ContainerRuntimeConfig;
use crate::error::{CoreError, Result};
use crate::machine::MachineManager;
use crate::vm_lifecycle::VmLifecycleManager;
use async_trait::async_trait;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const ENDPOINT_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const DOCKER_PING_REQUEST: &[u8] = b"GET /_ping HTTP/1.0\r\nHost: docker\r\n\r\n";

/// Guest Docker backend (dockerd/containerd/runc inside VM).
pub struct GuestDockerBackend {
    vm_lifecycle: Arc<VmLifecycleManager>,
    machine_manager: Arc<MachineManager>,
    machine_name: &'static str,
    config: ContainerRuntimeConfig,
    /// Set once the guest endpoint has been verified; collapses the
    /// per-request readiness check to a single vsock connect probe.
    endpoint_verified: AtomicBool,
}

impl GuestDockerBackend {
    #[must_use]
    pub const fn new(
        vm_lifecycle: Arc<VmLifecycleManager>,
        machine_manager: Arc<MachineManager>,
        machine_name: &'static str,
        config: ContainerRuntimeConfig,
    ) -> Self {
        Self {
            vm_lifecycle,
            machine_manager,
            machine_name,
            config,
            endpoint_verified: AtomicBool::new(false),
        }
    }

    /// Probes the guest dockerd endpoint with a real Docker `_ping` request.
    async fn probe_guest_endpoint(&self) -> Result<()> {
        let manager = Arc::clone(&self.machine_manager);
        let machine_name = self.machine_name;
        let port = self.config.guest_docker_vsock_port;

        let task = tokio::task::spawn_blocking(move || {
            let fd = manager.connect_vsock_port(machine_name, port)?;
            probe_docker_ping(fd)
        });

        match tokio::time::timeout(ENDPOINT_PROBE_TIMEOUT, task).await {
            Ok(join_result) => join_result.map_err(|e| {
                CoreError::Machine(format!("guest endpoint probe task failed: {e}"))
            })?,
            Err(_) => Err(CoreError::Machine(format!(
                "guest docker endpoint probe timed out after {}ms",
                ENDPOINT_PROBE_TIMEOUT.as_millis()
            ))),
        }
    }

    async fn wait_guest_endpoint_ready(&self) -> Result<()> {
        // Fast path: the endpoint was verified earlier in this VM's
        // lifetime. One blocking `_ping` probe replaces the agent RPC round
        // trips; if dockerd died (or the VM restarted underneath us), the
        // probe fails and we fall through to the full ensure-runtime loop,
        // which restarts dockerd via the agent.
        //
        // Relaxed is intentional: this flag is a pure optimization hint with
        // no associated data to synchronize. A stale read in either direction
        // is safe — we either take an unnecessary slow path or retry the probe.
        if self.endpoint_verified.load(Ordering::Relaxed) {
            match self.probe_guest_endpoint().await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    self.endpoint_verified.store(false, Ordering::Relaxed);
                    tracing::debug!(
                        "guest endpoint failed cached probe ({e}); re-running full readiness"
                    );
                }
            }
        }
        const INITIAL_DELAY_MS: u64 = 120;
        const MAX_DELAY_MS: u64 = 1200;

        let port = self.config.guest_docker_vsock_port;
        let timeout = Duration::from_millis(self.config.startup_timeout_ms);
        let deadline = Instant::now() + timeout;
        let mut delay_ms = INITIAL_DELAY_MS;
        let mut last_status_detail: Option<String> = None;

        loop {
            let mut docker_ready = false;

            if let Ok(mut agent) = self.machine_manager.connect_agent(self.machine_name) {
                match agent.ensure_runtime(true).await {
                    Ok(resp) => {
                        last_status_detail = Some(resp.message.clone());
                        if resp.ready {
                            validate_reported_vsock_endpoint(&resp.endpoint, port)?;
                            docker_ready = true;
                        }
                        tracing::debug!(
                            ready = resp.ready,
                            endpoint = resp.endpoint,
                            message = resp.message,
                            status = resp.status,
                            "requested guest runtime ensure"
                        );
                    }
                    Err(e) => {
                        tracing::trace!("failed to request guest runtime ensure: {}", e);
                    }
                }

                if !docker_ready {
                    match agent.get_runtime_status().await {
                        Ok(status) => {
                            last_status_detail = Some(status.detail.clone());
                            if status.docker_ready {
                                validate_reported_vsock_endpoint(&status.endpoint, port)?;
                                docker_ready = true;
                            }
                        }
                        Err(e) => {
                            tracing::trace!("failed to get guest runtime status: {}", e);
                        }
                    }
                }
            }

            if docker_ready {
                match self.probe_guest_endpoint().await {
                    Ok(()) => {
                        self.endpoint_verified.store(true, Ordering::Relaxed);
                        tracing::debug!(port, "guest docker endpoint is ready");
                        return Ok(());
                    }
                    Err(e) => {
                        if Instant::now() >= deadline {
                            return Err(CoreError::Machine(format!(
                                "guest docker endpoint on vsock port {} not ready within {}ms: {}",
                                port,
                                self.config.startup_timeout_ms,
                                last_status_detail.unwrap_or_else(|| e.to_string())
                            )));
                        }
                        tracing::trace!(
                            port,
                            retry_delay_ms = delay_ms,
                            "guest docker endpoint not reachable yet: {}",
                            e
                        );
                    }
                }
            } else if Instant::now() >= deadline {
                return Err(CoreError::Machine(format!(
                    "guest docker endpoint on vsock port {} not ready within {}ms: {}",
                    port,
                    self.config.startup_timeout_ms,
                    last_status_detail.unwrap_or_else(|| "runtime status unavailable".to_string())
                )));
            } else {
                tracing::trace!(
                    port,
                    retry_delay_ms = delay_ms,
                    "guest runtime not ready yet"
                );
            }

            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            delay_ms = (delay_ms * 3 / 2).min(MAX_DELAY_MS);
        }
    }
}

fn probe_docker_ping(fd: RawFd) -> Result<()> {
    // SAFETY: connect_vsock_port returns a freshly created fd owned by the
    // caller; wrapping it transfers that ownership so it closes.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    write_all_with_poll(
        owned.as_raw_fd(),
        DOCKER_PING_REQUEST,
        ENDPOINT_PROBE_TIMEOUT,
    )?;

    let mut response = [0u8; 512];
    let n = read_with_poll(owned.as_raw_fd(), &mut response, ENDPOINT_PROBE_TIMEOUT)?;
    validate_docker_ping_response(&response[..n])
}

fn write_all_with_poll(fd: RawFd, mut buf: &[u8], timeout: Duration) -> Result<()> {
    while !buf.is_empty() {
        poll_fd(fd, libc::POLLOUT, timeout)?;
        // SAFETY: fd is live for the duration of the call, and buf points to
        // readable memory of length buf.len().
        let written = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
        if written > 0 {
            buf = &buf[written as usize..];
            continue;
        }
        if written == 0 {
            return Err(CoreError::from(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "guest docker endpoint accepted zero bytes",
            )));
        }

        let err = std::io::Error::last_os_error();
        if matches!(
            err.kind(),
            std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
        ) {
            continue;
        }
        return Err(CoreError::from(err));
    }
    Ok(())
}

fn read_with_poll(fd: RawFd, buf: &mut [u8], timeout: Duration) -> Result<usize> {
    poll_fd(fd, libc::POLLIN, timeout)?;
    // SAFETY: fd is live for the duration of the call, and buf points to
    // writable memory of length buf.len().
    let read = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    if read > 0 {
        return Ok(read as usize);
    }
    if read == 0 {
        return Err(CoreError::from(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "guest docker endpoint closed before responding to _ping",
        )));
    }

    Err(CoreError::from(std::io::Error::last_os_error()))
}

fn poll_fd(fd: RawFd, events: libc::c_short, timeout: Duration) -> Result<()> {
    let timeout_ms = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
    loop {
        let mut pollfd = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        // SAFETY: pollfd points to one valid pollfd for the duration of poll.
        let result = unsafe { libc::poll(&raw mut pollfd, 1, timeout_ms) };
        if result > 0 {
            if pollfd.revents & events != 0 {
                return Ok(());
            }
            return Err(CoreError::from(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                format!(
                    "guest docker endpoint poll failed: revents={}",
                    pollfd.revents
                ),
            )));
        }
        if result == 0 {
            return Err(CoreError::from(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "guest docker endpoint probe timed out",
            )));
        }

        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        return Err(CoreError::from(err));
    }
}

fn validate_docker_ping_response(response: &[u8]) -> Result<()> {
    if response.starts_with(b"HTTP/1.0 200") || response.starts_with(b"HTTP/1.1 200") {
        return Ok(());
    }

    Err(CoreError::Machine(format!(
        "guest docker endpoint returned unexpected _ping response: {}",
        String::from_utf8_lossy(response).trim_end()
    )))
}

fn parse_vsock_endpoint_port(endpoint: &str) -> Option<u32> {
    endpoint.strip_prefix("vsock:")?.parse::<u32>().ok()
}

fn validate_reported_vsock_endpoint(endpoint: &str, expected_port: u32) -> Result<()> {
    let endpoint_port = parse_vsock_endpoint_port(endpoint).ok_or_else(|| {
        CoreError::Machine(format!(
            "guest runtime endpoint format invalid: '{endpoint}'; expected 'vsock:<port>'"
        ))
    })?;

    if endpoint_port != expected_port {
        return Err(CoreError::Machine(format!(
            "guest runtime endpoint mismatch: guest reports vsock:{endpoint_port} but host is configured for vsock:{expected_port}"
        )));
    }

    Ok(())
}

#[async_trait]
impl ContainerBackend for GuestDockerBackend {
    fn name(&self) -> &'static str {
        "guest_docker"
    }

    async fn ensure_ready(&self) -> Result<u32> {
        let cid = self.vm_lifecycle.ensure_ready().await?;
        self.wait_guest_endpoint_ready().await?;
        Ok(cid)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        parse_vsock_endpoint_port, validate_docker_ping_response, validate_reported_vsock_endpoint,
    };

    #[test]
    fn test_parse_vsock_endpoint_port_ok() {
        assert_eq!(parse_vsock_endpoint_port("vsock:2375"), Some(2375));
    }

    #[test]
    fn test_parse_vsock_endpoint_port_invalid() {
        assert_eq!(
            parse_vsock_endpoint_port("unix:///var/run/docker.sock"),
            None
        );
        assert_eq!(parse_vsock_endpoint_port("vsock:not-a-number"), None);
        assert_eq!(parse_vsock_endpoint_port("2375"), None);
    }

    #[test]
    fn test_validate_reported_vsock_endpoint_ok() {
        assert!(validate_reported_vsock_endpoint("vsock:2375", 2375).is_ok());
    }

    #[test]
    fn test_validate_reported_vsock_endpoint_mismatch() {
        let err = validate_reported_vsock_endpoint("vsock:2375", 1234).unwrap_err();
        assert!(err.to_string().contains("endpoint mismatch"));
    }

    #[test]
    fn test_validate_reported_vsock_endpoint_invalid_format() {
        let err =
            validate_reported_vsock_endpoint("unix:///var/run/docker.sock", 2375).unwrap_err();
        assert!(err.to_string().contains("format invalid"));
    }

    #[test]
    fn test_validate_docker_ping_response_accepts_http_200() {
        assert!(validate_docker_ping_response(b"HTTP/1.0 200 OK\r\n\r\nOK").is_ok());
        assert!(validate_docker_ping_response(b"HTTP/1.1 200 OK\r\n\r\nOK").is_ok());
    }

    #[test]
    fn test_validate_docker_ping_response_rejects_non_200() {
        assert!(validate_docker_ping_response(b"HTTP/1.1 503 Service Unavailable\r\n").is_err());
        assert!(validate_docker_ping_response(b"").is_err());
    }
}
