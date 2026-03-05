//! Agent main loop and request handling.
//!
//! The Agent listens on vsock port 1024 and handles RPC requests from the host.
//! It manages container lifecycle and executes commands in the guest VM.

use anyhow::Result;
use arcbox_constants::ports::AGENT_PORT;

// =============================================================================
// EnsureRuntime State Machine (platform-independent, testable)
// =============================================================================

pub mod ensure_runtime {
    use std::sync::OnceLock;

    pub use arcbox_constants::status::{
        RUNTIME_FAILED as STATUS_FAILED, RUNTIME_REUSED as STATUS_REUSED,
        RUNTIME_STARTED as STATUS_STARTED,
    };
    use arcbox_protocol::agent::RuntimeEnsureResponse;
    use tokio::sync::{Mutex, Notify};

    /// Runtime lifecycle state.
    #[derive(Debug, Clone)]
    #[allow(dead_code)]
    pub enum RuntimeState {
        /// No ensure has been attempted yet.
        NotStarted,
        /// An ensure operation is in progress (first caller drives it).
        Starting,
        /// Runtime is confirmed ready.
        Ready { endpoint: String, message: String },
        /// Last ensure attempt failed; may retry on next start_if_needed=true.
        Failed { message: String },
    }

    /// Global singleton guard that serializes EnsureRuntime attempts and caches
    /// the outcome so that repeated / concurrent calls are idempotent.
    #[allow(dead_code)]
    pub struct RuntimeGuard {
        pub state: Mutex<RuntimeState>,
        /// Notified when a Starting -> Ready/Failed transition completes so
        /// that concurrent waiters can proceed.
        pub notify: Notify,
    }

    impl RuntimeGuard {
        #[allow(dead_code)]
        pub fn new() -> Self {
            Self {
                state: Mutex::new(RuntimeState::NotStarted),
                notify: Notify::new(),
            }
        }
    }

    /// Returns the global RuntimeGuard singleton.
    #[allow(dead_code)]
    pub fn runtime_guard() -> &'static RuntimeGuard {
        static GUARD: OnceLock<RuntimeGuard> = OnceLock::new();
        GUARD.get_or_init(RuntimeGuard::new)
    }

    /// Platform-independent, idempotent EnsureRuntime handler.
    ///
    /// - First caller with `start_if_needed=true` transitions NotStarted -> Starting -> Ready/Failed.
    /// - Concurrent callers wait for the first caller to finish and share the result.
    /// - After Ready, subsequent calls return "reused" immediately.
    /// - After Failed, a new `start_if_needed=true` call retries.
    /// - `start_if_needed=false` only probes without attempting to start.
    ///
    /// `start_fn` is invoked only by the driver; it performs the actual start sequence.
    /// `probe_fn` is invoked for start_if_needed=false to report current status.
    #[allow(dead_code)]
    pub async fn ensure_runtime<F, P>(
        guard: &RuntimeGuard,
        start_if_needed: bool,
        start_fn: F,
        probe_fn: P,
    ) -> RuntimeEnsureResponse
    where
        F: std::future::Future<Output = RuntimeEnsureResponse>,
        P: std::future::Future<Output = RuntimeEnsureResponse>,
    {
        // Fast path: if already Ready, return immediately.
        {
            let state = guard.state.lock().await;
            if let RuntimeState::Ready { endpoint, message } = &*state {
                return RuntimeEnsureResponse {
                    ready: true,
                    endpoint: endpoint.clone(),
                    message: message.clone(),
                    status: STATUS_REUSED.to_string(),
                };
            }
        }

        // Probe-only mode: do not attempt to start.
        if !start_if_needed {
            return probe_fn.await;
        }

        // Attempt to become the driver of the start sequence.
        let i_am_driver = {
            let mut state = guard.state.lock().await;
            match &*state {
                RuntimeState::Ready { endpoint, message } => {
                    // Another caller finished while we waited for the lock.
                    return RuntimeEnsureResponse {
                        ready: true,
                        endpoint: endpoint.clone(),
                        message: message.clone(),
                        status: STATUS_REUSED.to_string(),
                    };
                }
                RuntimeState::Starting => false,
                RuntimeState::NotStarted | RuntimeState::Failed { .. } => {
                    *state = RuntimeState::Starting;
                    true
                }
            }
        };

        if i_am_driver {
            // We are the driver: perform the actual start sequence.
            let response = start_fn.await;

            // Publish outcome to the state machine.
            let mut state = guard.state.lock().await;
            if response.ready {
                *state = RuntimeState::Ready {
                    endpoint: response.endpoint.clone(),
                    message: response.message.clone(),
                };
            } else {
                *state = RuntimeState::Failed {
                    message: response.message.clone(),
                };
            }
            // Wake all waiters.
            guard.notify.notify_waiters();

            return response;
        }

        // We are a waiter: wait for the driver to finish.
        loop {
            // Register for notification BEFORE checking state to prevent lost
            // wakeups.  If the driver calls notify_waiters() between our state
            // check and the await, the future is already enabled and will
            // resolve immediately.
            let notified = guard.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();

            let state = guard.state.lock().await;
            match &*state {
                RuntimeState::Ready { endpoint, message } => {
                    return RuntimeEnsureResponse {
                        ready: true,
                        endpoint: endpoint.clone(),
                        message: message.clone(),
                        status: STATUS_REUSED.to_string(),
                    };
                }
                RuntimeState::Failed { message } => {
                    return RuntimeEnsureResponse {
                        ready: false,
                        endpoint: String::new(),
                        message: message.clone(),
                        status: STATUS_FAILED.to_string(),
                    };
                }
                RuntimeState::Starting => {
                    // Release lock before waiting.
                    drop(state);
                    notified.await;
                    continue;
                }
                RuntimeState::NotStarted => {
                    // Should not happen, but treat as failed.
                    return RuntimeEnsureResponse {
                        ready: false,
                        endpoint: String::new(),
                        message: "unexpected state: NotStarted after notify".to_string(),
                        status: STATUS_FAILED.to_string(),
                    };
                }
            }
        }
    }
}

// =============================================================================
// Linux Implementation
// =============================================================================

#[cfg(target_os = "linux")]
mod linux {
    use std::io::{Read as _, Seek as _, SeekFrom};
    use std::net::IpAddr;
    use std::path::{Path, PathBuf};
    use std::process::Stdio;
    use std::sync::{Arc, OnceLock};
    use std::time::Duration;

    use anyhow::{Context, Result};
    use tokio::io::{AsyncRead, AsyncWrite};
    use tokio::net::UnixStream;
    use tokio::process::Command;
    use tokio::sync::Mutex;
    use tokio_vsock::{VMADDR_CID_ANY, VsockAddr, VsockListener, VsockStream};

    use super::AGENT_PORT;
    use super::ensure_runtime;
    use crate::rpc::{
        AGENT_VERSION, ErrorResponse, MessageType, RpcRequest, RpcResponse, parse_request,
        read_message, write_message, write_response,
    };
    use crate::sandbox::SandboxService;
    use arcbox_constants::cmdline::{
        DOCKER_DATA_DEVICE_KEY as DOCKER_DATA_DEVICE_CMDLINE_KEY, GUEST_DOCKER_VSOCK_PORT_KEY,
    };
    use arcbox_constants::devices::DOCKER_DATA_BLOCK_DEVICE as DOCKER_DATA_DEVICE_DEFAULT;
    use arcbox_constants::env::GUEST_DOCKER_VSOCK_PORT as GUEST_DOCKER_VSOCK_PORT_ENV;
    use arcbox_constants::paths::{
        ARCBOX_RUNTIME_BIN_DIR, CONTAINERD_DATA_MOUNT_POINT, CONTAINERD_SOCKET,
        DOCKER_API_UNIX_SOCKET, DOCKER_DATA_MOUNT_POINT,
    };
    use arcbox_constants::ports::DOCKER_API_VSOCK_PORT;
    use arcbox_constants::status::{SERVICE_ERROR, SERVICE_NOT_READY, SERVICE_READY};

    use arcbox_protocol::agent::{
        PingResponse, RuntimeEnsureRequest, RuntimeEnsureResponse, RuntimeStatusRequest,
        RuntimeStatusResponse, SystemInfo,
    };

    // =========================================================================
    // Sandbox service singleton
    // =========================================================================

    /// Returns the global [`SandboxService`] singleton.
    ///
    /// The service is initialised lazily on the first call.  Initialisation
    /// failures are logged as warnings and `None` is stored, so sandbox
    /// operations will return a 503 error rather than crashing the agent.
    fn sandbox_service() -> Option<&'static Arc<SandboxService>> {
        static SERVICE: OnceLock<Option<Arc<SandboxService>>> = OnceLock::new();
        SERVICE
            .get_or_init(|| {
                let config = crate::config::load();
                match SandboxService::new(config) {
                    Ok(svc) => {
                        tracing::info!("sandbox service initialised");
                        Some(Arc::new(svc))
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "sandbox service unavailable");
                        None
                    }
                }
            })
            .as_ref()
    }

    /// Containerd socket candidates (primary + legacy fallback).
    const CONTAINERD_SOCKET_CANDIDATES: [&str; 2] =
        [CONTAINERD_SOCKET, "/var/run/containerd/containerd.sock"];

    fn cmdline_value(key: &str) -> Option<String> {
        let cmdline = std::fs::read_to_string("/proc/cmdline").ok()?;
        for token in cmdline.split_whitespace() {
            if let Some(value) = token.strip_prefix(key) {
                if !value.is_empty() {
                    return Some(value.to_string());
                }
            }
        }
        None
    }

    fn docker_api_vsock_port() -> u32 {
        if let Some(port) = std::env::var(GUEST_DOCKER_VSOCK_PORT_ENV)
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .filter(|port| *port > 0)
        {
            return port;
        }

        if let Some(port) = cmdline_value(GUEST_DOCKER_VSOCK_PORT_KEY)
            .and_then(|raw| raw.parse::<u32>().ok())
            .filter(|port| *port > 0)
        {
            return port;
        }

        DOCKER_API_VSOCK_PORT
    }

    fn docker_data_device() -> String {
        cmdline_value(DOCKER_DATA_DEVICE_CMDLINE_KEY)
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| DOCKER_DATA_DEVICE_DEFAULT.to_string())
    }

    /// Btrfs primary superblock magic `_BHRfS_M` at absolute disk offset
    /// `0x10040` (superblock starts at `0x10000`, magic at internal offset `0x40`).
    const BTRFS_MAGIC: [u8; 8] = [0x5f, 0x42, 0x48, 0x52, 0x66, 0x53, 0x5f, 0x4d];
    const BTRFS_MAGIC_OFFSET: u64 = 0x10040;

    /// Temporary mount point for the raw Btrfs device before subvolume bind mounts.
    ///
    /// Must live on a writable filesystem. `/run` is tmpfs (set up in PID1 init),
    /// while EROFS root is read-only and cannot host dynamic mountpoints.
    const BTRFS_TEMP_MOUNT: &str = "/run/arcbox/data";

    fn has_btrfs_superblock(device: &str) -> bool {
        let mut file = match std::fs::File::open(device) {
            Ok(file) => file,
            Err(_) => return false,
        };
        if file.seek(SeekFrom::Start(BTRFS_MAGIC_OFFSET)).is_err() {
            return false;
        }
        let mut magic = [0_u8; 8];
        if file.read_exact(&mut magic).is_err() {
            return false;
        }
        magic == BTRFS_MAGIC
    }

    /// Formats the device as Btrfs if it does not already have a Btrfs superblock.
    /// Old ext4 disks are unconditionally wiped (alpha breaking change).
    fn ensure_btrfs_format(device: &str) -> Result<String, String> {
        if has_btrfs_superblock(device) {
            return Ok("data device already Btrfs".to_string());
        }

        // /sbin/mkfs.btrfs is baked into the EROFS rootfs.
        let binary = "/sbin/mkfs.btrfs";
        if !Path::new(binary).exists() {
            return Err(format!("{} not found in EROFS rootfs", binary));
        }

        match std::process::Command::new(binary)
            .args(["-f", device])
            .status()
        {
            Ok(status) if status.success() => Ok(format!("formatted {} as Btrfs", device)),
            Ok(status) => Err(format!(
                "mkfs.btrfs failed on {} (exit={})",
                device,
                status.code().unwrap_or(-1)
            )),
            Err(e) => Err(format!("failed to execute mkfs.btrfs: {}", e)),
        }
    }

    /// Mounts the data volume (Btrfs), creates subvolumes, and bind-mounts them.
    ///
    /// Layout after this function returns:
    /// - `/run/arcbox/data` — raw Btrfs mount (internal, not used by daemons)
    /// - `/var/lib/docker` — bind mount of `@docker` subvolume
    /// - `/var/lib/containerd` — bind mount of `@containerd` subvolume
    ///
    /// Returns `Ok(notes)` on success or `Err(reason)` if the data volume
    /// could not be set up. Callers must abort runtime startup on error —
    /// running containerd/dockerd without persistent storage is unsafe.
    fn ensure_data_mount() -> Result<String, String> {
        // Already fully set up?
        if crate::mount::is_mounted(DOCKER_DATA_MOUNT_POINT)
            && crate::mount::is_mounted(CONTAINERD_DATA_MOUNT_POINT)
        {
            return Ok("data subvolumes already mounted".to_string());
        }

        let device = docker_data_device();
        if !Path::new(&device).exists() {
            return Err(format!("data device missing: {}", device));
        }

        // Step 1: Format if not Btrfs.
        match ensure_btrfs_format(&device) {
            Ok(note) => tracing::info!("{}", note),
            Err(e) => return Err(e),
        }

        // Step 2: Mount raw Btrfs to temporary writable mount point.
        if !crate::mount::is_mounted(BTRFS_TEMP_MOUNT) {
            if let Err(e) = std::fs::create_dir_all(BTRFS_TEMP_MOUNT) {
                return Err(format!("failed to create {}: {}", BTRFS_TEMP_MOUNT, e));
            }
            match std::process::Command::new("/bin/busybox")
                .args([
                    "mount",
                    "-t",
                    "btrfs",
                    "-o",
                    "compress=zstd:3",
                    &device,
                    BTRFS_TEMP_MOUNT,
                ])
                .status()
            {
                Ok(s) if s.success() => {}
                Ok(s) => {
                    return Err(format!(
                        "mount -t btrfs {} {} failed (exit={})",
                        device,
                        BTRFS_TEMP_MOUNT,
                        s.code().unwrap_or(-1)
                    ));
                }
                Err(e) => return Err(format!("mount exec failed: {}", e)),
            }
        }

        // Step 3: Create subvolumes if missing.
        for subvol in ["@docker", "@containerd"] {
            let subvol_path = format!("{}/{}", BTRFS_TEMP_MOUNT, subvol);
            if Path::new(&subvol_path).exists() {
                continue;
            }
            // EROFS only includes mkfs.btrfs, not full btrfs-progs. Use the
            // BTRFS_IOC_SUBVOL_CREATE ioctl directly to create subvolumes.
            if let Err(e) = btrfs_create_subvolume(&subvol_path) {
                return Err(format!("failed to create subvolume {}: {}", subvol, e));
            }
        }

        let mut notes = Vec::new();

        // Step 4: Bind mount subvolumes to final paths.
        for (subvol, target) in [
            ("@docker", DOCKER_DATA_MOUNT_POINT),
            ("@containerd", CONTAINERD_DATA_MOUNT_POINT),
        ] {
            if crate::mount::is_mounted(target) {
                continue;
            }
            if let Err(e) = std::fs::create_dir_all(target) {
                return Err(format!("failed to create {}: {}", target, e));
            }
            let opts = format!("compress=zstd:3,subvol={}", subvol);
            match std::process::Command::new("/bin/busybox")
                .args(["mount", "-t", "btrfs", "-o", &opts, &device, target])
                .status()
            {
                Ok(s) if s.success() => {
                    notes.push(format!("mounted {} -> {}", subvol, target));
                }
                Ok(s) => {
                    return Err(format!(
                        "mount subvol={} {} failed (exit={})",
                        subvol,
                        target,
                        s.code().unwrap_or(-1)
                    ));
                }
                Err(e) => return Err(format!("mount exec failed: {}", e)),
            }
        }

        if notes.is_empty() {
            Ok("data subvolumes already mounted".to_string())
        } else {
            Ok(notes.join("; "))
        }
    }

    // BTRFS_IOC_SUBVOL_CREATE = _IOW(0x94, 14, struct btrfs_ioctl_vol_args)
    // struct btrfs_ioctl_vol_args { __s64 fd; char name[4088]; }  total = 4096 bytes
    //
    // nix::ioctl_write_ptr! computes the request number portably (handles
    // c_int on musl vs c_ulong on glibc).
    #[cfg(target_os = "linux")]
    nix::ioctl_write_ptr!(btrfs_ioc_subvol_create, 0x94, 14, [u8; 4096]);

    /// Creates a Btrfs subvolume using the `BTRFS_IOC_SUBVOL_CREATE` ioctl.
    ///
    /// This avoids needing the full `btrfs-progs` CLI in the EROFS rootfs.
    #[cfg(target_os = "linux")]
    fn btrfs_create_subvolume(path: &str) -> Result<(), String> {
        use std::os::unix::io::AsRawFd;

        let parent = Path::new(path)
            .parent()
            .ok_or_else(|| "no parent directory".to_string())?;
        let name = Path::new(path)
            .file_name()
            .ok_or_else(|| "no subvolume name".to_string())?
            .to_str()
            .ok_or_else(|| "invalid subvolume name".to_string())?;

        let parent_dir =
            std::fs::File::open(parent).map_err(|e| format!("open {}: {}", parent.display(), e))?;

        let mut args = [0u8; 4096];
        // First 8 bytes: fd field (unused for SUBVOL_CREATE, set to 0).
        // Bytes 8..4096: null-terminated name.
        let name_bytes = name.as_bytes();
        if name_bytes.len() >= 4088 {
            return Err("subvolume name too long".to_string());
        }
        args[8..8 + name_bytes.len()].copy_from_slice(name_bytes);

        // SAFETY: valid fd from File::open, args buffer is 4096 bytes matching
        // the kernel struct btrfs_ioctl_vol_args layout.
        unsafe { btrfs_ioc_subvol_create(parent_dir.as_raw_fd(), &args) }
            .map_err(|e| format!("BTRFS_IOC_SUBVOL_CREATE: {}", e))?;

        tracing::info!("created Btrfs subvolume {}", path);
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn btrfs_create_subvolume(_path: &str) -> Result<(), String> {
        Err("Btrfs subvolume creation is only supported on Linux".to_string())
    }

    /// Result from handling a request.
    enum RequestResult {
        /// Single response.
        Single(RpcResponse),
    }

    /// The Guest Agent.
    ///
    /// Listens on vsock and handles RPC requests from the host.
    pub struct Agent;

    impl Agent {
        /// Creates a new agent.
        pub fn new() -> Self {
            Self
        }

        /// Runs the agent, listening on vsock.
        pub async fn run(&self) -> Result<()> {
            // Mount standard VirtioFS shares if not already mounted.
            crate::mount::mount_standard_shares();

            // Eagerly initialise the sandbox service so its first-time
            // NetworkManager setup (which requires root) happens at startup
            // rather than on the first sandbox request.
            let _ = sandbox_service();

            // Start guest-side Docker API proxy (vsock -> unix socket).
            tokio::spawn(async {
                if let Err(e) = run_docker_api_proxy().await {
                    tracing::warn!("Docker API proxy exited: {}", e);
                }
            });

            let mut listener =
                bind_vsock_listener_with_retry(AGENT_PORT, "agent rpc listener").await?;

            tracing::info!("Agent listening on vsock port {}", AGENT_PORT);

            loop {
                match listener.accept().await {
                    Ok((stream, peer_addr)) => {
                        tracing::info!("Accepted connection from {:?}", peer_addr);
                        eprintln!("[AGENT] Accepted connection from {:?}", peer_addr);
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(stream).await {
                                tracing::error!("Connection error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        tracing::error!("Accept error: {}", e);
                    }
                }
            }
        }
    }

    async fn bind_vsock_listener_with_retry(port: u32, component: &str) -> Result<VsockListener> {
        const INITIAL_DELAY_MS: u64 = 120;
        const MAX_DELAY_MS: u64 = 2_000;

        let mut delay_ms = INITIAL_DELAY_MS;

        loop {
            let addr = VsockAddr::new(VMADDR_CID_ANY, port);
            match VsockListener::bind(addr) {
                Ok(listener) => {
                    tracing::info!(port, component, "vsock listener bound");
                    return Ok(listener);
                }
                Err(e) => {
                    tracing::warn!(
                        port,
                        component,
                        retry_delay_ms = delay_ms,
                        error = %e,
                        "failed to bind vsock listener, retrying"
                    );
                }
            }

            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            delay_ms = (delay_ms * 3 / 2).min(MAX_DELAY_MS);
        }
    }

    async fn run_docker_api_proxy() -> Result<()> {
        let port = docker_api_vsock_port();
        let mut listener = bind_vsock_listener_with_retry(port, "docker api proxy").await?;
        tracing::info!("Docker API proxy listening on vsock port {}", port);

        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    tracing::debug!("Docker API proxy accepted connection from {:?}", peer_addr);
                    tokio::spawn(async move {
                        if let Err(e) = proxy_docker_api_connection(stream).await {
                            tracing::debug!("Docker API proxy connection ended: {}", e);
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!("Docker API proxy accept failed: {}", e);
                }
            }
        }
    }

    async fn proxy_docker_api_connection(mut vsock_stream: VsockStream) -> Result<()> {
        let mut unix_stream = UnixStream::connect(DOCKER_API_UNIX_SOCKET)
            .await
            .context("failed to connect guest docker unix socket")?;

        let _ = tokio::io::copy_bidirectional(&mut vsock_stream, &mut unix_stream)
            .await
            .context("docker api proxy copy failed")?;
        Ok(())
    }

    impl Default for Agent {
        fn default() -> Self {
            Self::new()
        }
    }

    /// Handles a single vsock connection.
    ///
    /// Reads RPC requests, processes them, and writes responses.
    async fn handle_connection<S>(mut stream: S) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        loop {
            // Read the next request (V2 wire format with trace_id).
            let (msg_type, trace_id, payload) = match read_message(&mut stream).await {
                Ok(msg) => msg,
                Err(e) => {
                    // Check if it's an EOF (clean disconnect)
                    if e.to_string().contains("failed to read message header") {
                        tracing::debug!("Client disconnected");
                        return Ok(());
                    }
                    return Err(e);
                }
            };

            tracing::info!(
                trace_id = %trace_id,
                "Received message type {:?}, payload_len={}",
                msg_type,
                payload.len()
            );

            // Sandbox requests are handled separately — they bypass the normal
            // RPC request/response cycle because streaming operations hold the
            // connection open and write multiple frames.
            if msg_type.is_sandbox_request() {
                if let Err(e) =
                    handle_sandbox_message(&mut stream, msg_type, &trace_id, &payload).await
                {
                    tracing::warn!(trace_id = %trace_id, error = %e, "sandbox handler error");
                }
                continue;
            }

            // Parse and handle the request.
            let result = match parse_request(msg_type, &payload) {
                Ok(request) => handle_request(request).await,
                Err(e) => {
                    tracing::warn!(trace_id = %trace_id, "Failed to parse request: {}", e);
                    RequestResult::Single(RpcResponse::Error(ErrorResponse::new(
                        400,
                        format!("invalid request: {}", e),
                    )))
                }
            };

            // Handle the result, echoing back the trace_id in responses.
            match result {
                RequestResult::Single(response) => {
                    // Write single response
                    write_response(&mut stream, &response, &trace_id).await?;
                }
            }
        }
    }

    /// Dispatches a sandbox RPC request.
    ///
    /// Non-streaming requests (CRUD, snapshots) write a single response frame
    /// and return.  Streaming requests (Run, Events) write multiple frames
    /// until the stream ends.
    async fn handle_sandbox_message<S>(
        stream: &mut S,
        msg_type: MessageType,
        trace_id: &str,
        payload: &[u8],
    ) -> anyhow::Result<()>
    where
        S: tokio::io::AsyncWrite + Unpin,
    {
        let svc = match sandbox_service() {
            Some(s) => Arc::clone(s),
            None => {
                let err = ErrorResponse::new(503, "sandbox service unavailable");
                write_message(stream, MessageType::Error, trace_id, &err.encode()).await?;
                return Ok(());
            }
        };

        match msg_type {
            // -----------------------------------------------------------------
            // CRUD
            // -----------------------------------------------------------------
            MessageType::SandboxCreateRequest => match svc.create(payload).await {
                Ok(resp) => {
                    use prost::Message as _;
                    write_message(
                        stream,
                        MessageType::SandboxCreateResponse,
                        trace_id,
                        &resp.encode_to_vec(),
                    )
                    .await?;
                }
                Err(e) => {
                    send_sandbox_error(stream, trace_id, 500, &e).await?;
                }
            },
            MessageType::SandboxStopRequest => match svc.stop(payload).await {
                Ok(()) => {
                    write_message(stream, MessageType::SandboxStopResponse, trace_id, &[]).await?;
                }
                Err(e) => {
                    send_sandbox_error(stream, trace_id, 500, &e).await?;
                }
            },
            MessageType::SandboxRemoveRequest => match svc.remove(payload).await {
                Ok(()) => {
                    write_message(stream, MessageType::SandboxRemoveResponse, trace_id, &[])
                        .await?;
                }
                Err(e) => {
                    send_sandbox_error(stream, trace_id, 500, &e).await?;
                }
            },
            MessageType::SandboxInspectRequest => match svc.inspect(payload) {
                Ok(resp) => {
                    use prost::Message as _;
                    write_message(
                        stream,
                        MessageType::SandboxInspectResponse,
                        trace_id,
                        &resp.encode_to_vec(),
                    )
                    .await?;
                }
                Err(e) => {
                    send_sandbox_error(stream, trace_id, 500, &e).await?;
                }
            },
            MessageType::SandboxListRequest => match svc.list(payload) {
                Ok(resp) => {
                    use prost::Message as _;
                    write_message(
                        stream,
                        MessageType::SandboxListResponse,
                        trace_id,
                        &resp.encode_to_vec(),
                    )
                    .await?;
                }
                Err(e) => {
                    send_sandbox_error(stream, trace_id, 500, &e).await?;
                }
            },
            // -----------------------------------------------------------------
            // Streaming: Run
            // -----------------------------------------------------------------
            MessageType::SandboxRunRequest => {
                handle_sandbox_run(stream, &svc, trace_id, payload).await?;
            }
            // -----------------------------------------------------------------
            // Streaming: Events
            // -----------------------------------------------------------------
            MessageType::SandboxEventsRequest => {
                handle_sandbox_events(stream, &svc, trace_id, payload).await?;
            }
            // -----------------------------------------------------------------
            // Exec: not yet implemented
            // -----------------------------------------------------------------
            MessageType::SandboxExecRequest => {
                send_sandbox_error(stream, trace_id, 501, "SandboxExec not yet implemented")
                    .await?;
            }
            // -----------------------------------------------------------------
            // Snapshots
            // -----------------------------------------------------------------
            MessageType::SandboxCheckpointRequest => match svc.checkpoint(payload).await {
                Ok(resp) => {
                    use prost::Message as _;
                    write_message(
                        stream,
                        MessageType::SandboxCheckpointResponse,
                        trace_id,
                        &resp.encode_to_vec(),
                    )
                    .await?;
                }
                Err(e) => {
                    send_sandbox_error(stream, trace_id, 500, &e).await?;
                }
            },
            MessageType::SandboxRestoreRequest => match svc.restore(payload).await {
                Ok(resp) => {
                    use prost::Message as _;
                    write_message(
                        stream,
                        MessageType::SandboxRestoreResponse,
                        trace_id,
                        &resp.encode_to_vec(),
                    )
                    .await?;
                }
                Err(e) => {
                    send_sandbox_error(stream, trace_id, 500, &e).await?;
                }
            },
            MessageType::SandboxListSnapshotsRequest => match svc.list_snapshots(payload) {
                Ok(resp) => {
                    use prost::Message as _;
                    write_message(
                        stream,
                        MessageType::SandboxListSnapshotsResponse,
                        trace_id,
                        &resp.encode_to_vec(),
                    )
                    .await?;
                }
                Err(e) => {
                    send_sandbox_error(stream, trace_id, 500, &e).await?;
                }
            },
            MessageType::SandboxDeleteSnapshotRequest => match svc.delete_snapshot(payload) {
                Ok(()) => {
                    write_message(
                        stream,
                        MessageType::SandboxDeleteSnapshotResponse,
                        trace_id,
                        &[],
                    )
                    .await?;
                }
                Err(e) => {
                    send_sandbox_error(stream, trace_id, 500, &e).await?;
                }
            },
            _ => {
                send_sandbox_error(stream, trace_id, 400, "unrecognised sandbox message type")
                    .await?;
            }
        }

        Ok(())
    }

    /// Stream `SandboxRunOutput` frames from `SandboxService::run`.
    async fn handle_sandbox_run<S>(
        stream: &mut S,
        svc: &SandboxService,
        trace_id: &str,
        payload: &[u8],
    ) -> anyhow::Result<()>
    where
        S: tokio::io::AsyncWrite + Unpin,
    {
        let mut rx = match svc.run(payload).await {
            Ok(r) => r,
            Err(e) => {
                send_sandbox_error(stream, trace_id, 500, &e).await?;
                return Ok(());
            }
        };

        while let Some(encoded) = rx.recv().await {
            write_message(stream, MessageType::SandboxRunOutput, trace_id, &encoded).await?;
        }

        Ok(())
    }

    /// Stream `SandboxEvent` frames from `SandboxService::subscribe_events`.
    async fn handle_sandbox_events<S>(
        stream: &mut S,
        svc: &SandboxService,
        trace_id: &str,
        payload: &[u8],
    ) -> anyhow::Result<()>
    where
        S: tokio::io::AsyncWrite + Unpin,
    {
        let mut rx = match svc.subscribe_events(payload) {
            Ok(r) => r,
            Err(e) => {
                send_sandbox_error(stream, trace_id, 500, &e).await?;
                return Ok(());
            }
        };

        while let Some(encoded) = rx.recv().await {
            write_message(stream, MessageType::SandboxEvent, trace_id, &encoded).await?;
        }

        Ok(())
    }

    /// Write a single `Error` frame back to the caller.
    async fn send_sandbox_error<S>(
        stream: &mut S,
        trace_id: &str,
        code: i32,
        message: &str,
    ) -> anyhow::Result<()>
    where
        S: tokio::io::AsyncWrite + Unpin,
    {
        let err = ErrorResponse::new(code, message);
        write_message(stream, MessageType::Error, trace_id, &err.encode()).await
    }

    /// Handles a single RPC request.
    async fn handle_request(request: RpcRequest) -> RequestResult {
        match request {
            RpcRequest::Ping(req) => RequestResult::Single(handle_ping(req)),
            RpcRequest::GetSystemInfo => RequestResult::Single(handle_get_system_info().await),
            RpcRequest::EnsureRuntime(req) => {
                RequestResult::Single(handle_ensure_runtime(req).await)
            }
            RpcRequest::RuntimeStatus(req) => {
                RequestResult::Single(handle_runtime_status(req).await)
            }
        }
    }

    /// Handles a Ping request.
    fn handle_ping(req: arcbox_protocol::agent::PingRequest) -> RpcResponse {
        tracing::debug!("Ping request: {:?}", req.message);
        RpcResponse::Ping(PingResponse {
            message: if req.message.is_empty() {
                "pong".to_string()
            } else {
                format!("pong: {}", req.message)
            },
            version: AGENT_VERSION.to_string(),
        })
    }

    /// Handles a GetSystemInfo request.
    async fn handle_get_system_info() -> RpcResponse {
        let info = collect_system_info();
        RpcResponse::SystemInfo(info)
    }

    /// Idempotent, concurrency-safe EnsureRuntime handler.
    ///
    /// Delegates to the platform-independent `ensure_runtime` module, injecting
    /// the actual start and probe functions that depend on Linux system state.
    async fn handle_ensure_runtime(req: RuntimeEnsureRequest) -> RpcResponse {
        let guard = ensure_runtime::runtime_guard();

        let response = ensure_runtime::ensure_runtime(
            guard,
            req.start_if_needed,
            do_ensure_runtime_start(),
            do_ensure_runtime_probe(),
        )
        .await;

        RpcResponse::RuntimeEnsure(response)
    }

    /// Performs the actual runtime start sequence (called only by the driver).
    async fn do_ensure_runtime_start() -> RuntimeEnsureResponse {
        let mut notes = Vec::new();
        let note = try_start_bundled_runtime().await;
        if !note.is_empty() {
            notes.push(note);
        }

        // Poll until docker socket is ready (up to ~30 seconds).
        // dockerd on first boot may need significant time to initialise its
        // overlay2 storage and connect to containerd.
        let mut status = collect_runtime_status().await;
        for _ in 0..60 {
            if status.docker_ready {
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
            status = collect_runtime_status().await;
        }

        let mut message = status.detail.clone();
        if !notes.is_empty() {
            message = format!("{}; {}", notes.join("; "), status.detail);
        }

        let result_status = if status.docker_ready {
            ensure_runtime::STATUS_STARTED.to_string()
        } else {
            ensure_runtime::STATUS_FAILED.to_string()
        };

        RuntimeEnsureResponse {
            ready: status.docker_ready,
            endpoint: status.endpoint,
            message,
            status: result_status,
        }
    }

    /// Probes runtime status without attempting to start (for start_if_needed=false).
    async fn do_ensure_runtime_probe() -> RuntimeEnsureResponse {
        let status = collect_runtime_status().await;
        RuntimeEnsureResponse {
            ready: status.docker_ready,
            endpoint: status.endpoint,
            message: status.detail,
            status: if status.docker_ready {
                ensure_runtime::STATUS_REUSED.to_string()
            } else {
                ensure_runtime::STATUS_FAILED.to_string()
            },
        }
    }

    async fn handle_runtime_status(_req: RuntimeStatusRequest) -> RpcResponse {
        RpcResponse::RuntimeStatus(collect_runtime_status().await)
    }

    async fn collect_runtime_status() -> RuntimeStatusResponse {
        use arcbox_protocol::agent::ServiceStatus;

        let containerd_ready = probe_first_ready_socket(&CONTAINERD_SOCKET_CANDIDATES).await;
        let docker_ready = probe_unix_socket(DOCKER_API_UNIX_SOCKET).await;
        let runtime_dir = PathBuf::from(ARCBOX_RUNTIME_BIN_DIR);
        let missing_runtime_binaries = missing_runtime_binaries_at(&runtime_dir);

        // Build per-service status entries.
        let mut services = Vec::new();

        // containerd status
        services.push(if containerd_ready {
            ServiceStatus {
                name: "containerd".to_string(),
                status: SERVICE_READY.to_string(),
                detail: format!(
                    "socket reachable: {}",
                    CONTAINERD_SOCKET_CANDIDATES
                        .iter()
                        .find(|p| Path::new(p).exists())
                        .unwrap_or(&CONTAINERD_SOCKET_CANDIDATES[0])
                ),
            }
        } else {
            let socket_paths = CONTAINERD_SOCKET_CANDIDATES
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            ServiceStatus {
                name: "containerd".to_string(),
                status: SERVICE_NOT_READY.to_string(),
                detail: format!("no reachable socket found; checked: {}", socket_paths),
            }
        });

        // dockerd status
        let docker_detail = if docker_ready {
            format!("socket reachable: {}", DOCKER_API_UNIX_SOCKET)
        } else if Path::new(DOCKER_API_UNIX_SOCKET).exists() {
            format!(
                "socket exists but not reachable: {}",
                DOCKER_API_UNIX_SOCKET
            )
        } else {
            format!("socket missing: {}", DOCKER_API_UNIX_SOCKET)
        };

        services.push(ServiceStatus {
            name: "dockerd".to_string(),
            status: if docker_ready {
                SERVICE_READY.to_string()
            } else if Path::new(DOCKER_API_UNIX_SOCKET).exists() {
                SERVICE_ERROR.to_string()
            } else {
                SERVICE_NOT_READY.to_string()
            },
            detail: docker_detail,
        });

        // Build the summary detail string.
        let detail = if docker_ready {
            "docker socket ready".to_string()
        } else if Path::new(DOCKER_API_UNIX_SOCKET).exists() {
            format!(
                "docker socket exists but not reachable: {}",
                DOCKER_API_UNIX_SOCKET
            )
        } else if !missing_runtime_binaries.is_empty() {
            format!(
                "docker socket missing: {}; {}",
                DOCKER_API_UNIX_SOCKET,
                runtime_missing_detail_from(&missing_runtime_binaries)
            )
        } else {
            format!("docker socket missing: {}", DOCKER_API_UNIX_SOCKET)
        };

        RuntimeStatusResponse {
            containerd_ready,
            docker_ready,
            endpoint: format!("vsock:{}", docker_api_vsock_port()),
            detail,
            services,
        }
    }

    async fn probe_first_ready_socket(paths: &[&str]) -> bool {
        for path in paths {
            if probe_unix_socket(path).await {
                return true;
            }
        }
        false
    }

    async fn probe_unix_socket(path: &str) -> bool {
        if !Path::new(path).exists() {
            return false;
        }
        match tokio::time::timeout(Duration::from_millis(300), UnixStream::connect(path)).await {
            Ok(Ok(_stream)) => true,
            Ok(Err(_)) | Err(_) => false,
        }
    }

    fn runtime_start_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    const REQUIRED_RUNTIME_BINARIES: &[&str] =
        &["dockerd", "containerd", "containerd-shim-runc-v2", "runc"];

    fn detect_runtime_bin_dir() -> Option<PathBuf> {
        let dir = PathBuf::from(ARCBOX_RUNTIME_BIN_DIR);
        if missing_runtime_binaries_at(&dir).is_empty() {
            Some(dir)
        } else {
            None
        }
    }

    fn runtime_missing_detail() -> String {
        let dir = PathBuf::from(ARCBOX_RUNTIME_BIN_DIR);
        let missing = missing_runtime_binaries_at(&dir);
        runtime_missing_detail_from(&missing)
    }

    fn runtime_missing_detail_from(missing: &[&'static str]) -> String {
        if missing.is_empty() {
            format!("all runtime binaries present under {ARCBOX_RUNTIME_BIN_DIR}")
        } else {
            format!(
                "missing runtime binaries under {}: {}",
                ARCBOX_RUNTIME_BIN_DIR,
                missing.join(", ")
            )
        }
    }

    fn missing_runtime_binaries_at(dir: &Path) -> Vec<&'static str> {
        REQUIRED_RUNTIME_BINARIES
            .iter()
            .copied()
            .filter(|name| !dir.join(name).exists())
            .collect()
    }

    /// Ensures the guest environment has the prerequisites that dockerd/containerd
    /// need: cgroup2, overlayfs, devpts, /dev/shm, /tmp, /run.
    fn ensure_runtime_prerequisites() -> Vec<String> {
        let mut notes = Vec::new();

        // Use /bin/busybox <applet> directly — always present on EROFS rootfs.
        let busybox = "/bin/busybox";

        // Mount cgroup2 unified hierarchy (required by dockerd).
        if !Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
            if let Err(e) = std::fs::create_dir_all("/sys/fs/cgroup") {
                notes.push(format!("mkdir /sys/fs/cgroup failed({})", e));
            } else {
                let rc = std::process::Command::new(busybox)
                    .args(["mount", "-t", "cgroup2", "cgroup2", "/sys/fs/cgroup"])
                    .status();
                match rc {
                    Ok(s) if s.success() => notes.push("mounted cgroup2".to_string()),
                    Ok(s) => notes.push(format!("mount cgroup2 exit={}", s.code().unwrap_or(-1))),
                    Err(e) => notes.push(format!("mount cgroup2 failed({})", e)),
                }
            }
        }

        // Mount devpts if missing (needed for PTY allocation).
        if !Path::new("/dev/pts/ptmx").exists() {
            let _ = std::fs::create_dir_all("/dev/pts");
            let _ = std::process::Command::new(busybox)
                .args([
                    "mount",
                    "-t",
                    "devpts",
                    "-o",
                    "gid=5,mode=0620,noexec,nosuid",
                    "devpts",
                    "/dev/pts",
                ])
                .status();
        }

        // Mount /dev/shm if missing.
        if !Path::new("/dev/shm").exists() {
            let _ = std::fs::create_dir_all("/dev/shm");
            let _ = std::process::Command::new(busybox)
                .args([
                    "mount",
                    "-t",
                    "tmpfs",
                    "-o",
                    "nodev,nosuid,noexec",
                    "shm",
                    "/dev/shm",
                ])
                .status();
        }

        // Ensure /tmp and /run exist as writable tmpfs.
        for dir in ["/tmp", "/run"] {
            if !Path::new(dir).exists()
                || std::fs::metadata(dir).is_ok_and(|m| m.permissions().readonly())
            {
                let _ = std::fs::create_dir_all(dir);
                let _ = std::process::Command::new(busybox)
                    .args(["mount", "-t", "tmpfs", "tmpfs", dir])
                    .status();
            }
        }

        // Enable IPv4 forwarding so Docker can route traffic between docker0 and eth0.
        // VZ framework NAT masquerades all VM traffic, so no guest-side masquerade rule needed.
        if let Err(e) = std::fs::write("/proc/sys/net/ipv4/ip_forward", b"1\n") {
            notes.push(format!("ip_forward failed({})", e));
        } else {
            notes.push("enabled ip_forward".to_string());
        }

        // Load overlay module (needed for Docker's overlay2 storage driver).
        if !Path::new("/sys/module/overlay").exists() {
            let rc = std::process::Command::new("/sbin/modprobe")
                .arg("overlay")
                .status();
            match rc {
                Ok(s) if s.success() => notes.push("loaded overlay module".to_string()),
                _ => {
                    // Fallback: try insmod with kernel version path.
                    if let Ok(uname) = std::process::Command::new(busybox)
                        .arg("uname")
                        .arg("-r")
                        .output()
                    {
                        let kver = String::from_utf8_lossy(&uname.stdout).trim().to_string();
                        let ko = format!("/lib/modules/{}/kernel/fs/overlayfs/overlay.ko", kver);
                        if Path::new(&ko).exists() {
                            let _ = std::process::Command::new(busybox)
                                .args(["insmod", &ko])
                                .status();
                            notes.push(format!("insmod overlay from {}", ko));
                        } else {
                            notes.push("overlay module not found".to_string());
                        }
                    }
                }
            }
        }

        // Sync system clock via NTP before spawning containerd/dockerd.
        // The VM guest clock starts at epoch (1970-01-01) because VZ framework's
        // virtualised RTC is not automatically read by the Alpine kernel on boot.
        // Without a correct clock, TLS certificate verification fails with
        // "x509: certificate is not yet valid".
        // busybox ntpd -q performs a one-shot adjustment and exits.
        let ntp = std::process::Command::new(busybox)
            .args(["ntpd", "-q", "-n", "-p", "pool.ntp.org"])
            .status();
        match ntp {
            Ok(s) if s.success() => notes.push("ntp synced".to_string()),
            Ok(s) => notes.push(format!("ntp exit={}", s.code().unwrap_or(-1))),
            Err(e) => notes.push(format!("ntp failed({})", e)),
        }

        notes
    }

    /// Redirects daemon stdout/stderr to a log file so crashes are diagnosable.
    ///
    /// Prefers `/arcbox/` (VirtioFS mount, visible from host as `~/.arcbox/`)
    /// so that logs survive guest restarts and are accessible without exec.
    /// Falls back to `/tmp/` (guest tmpfs) if VirtioFS is not mounted.
    fn daemon_log_file(name: &str) -> Stdio {
        let arcbox_path = format!("/arcbox/{}.log", name);
        let tmp_log_path = format!("/tmp/{}.log", name);

        let log_path = if Path::new("/arcbox").exists() {
            &arcbox_path
        } else {
            &tmp_log_path
        };

        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)
        {
            Ok(f) => f.into(),
            Err(_) => {
                // Fallback to /tmp/ if /arcbox/ write fails.
                match std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&tmp_log_path)
                {
                    Ok(f) => f.into(),
                    Err(_) => Stdio::null(),
                }
            }
        }
    }

    async fn try_start_bundled_runtime() -> String {
        let _guard = runtime_start_lock().lock().await;

        if probe_unix_socket(DOCKER_API_UNIX_SOCKET).await {
            return "docker socket already ready".to_string();
        }

        let Some(runtime_bin_dir) = detect_runtime_bin_dir() else {
            return runtime_missing_detail();
        };

        tracing::info!(
            runtime_bin_dir = %runtime_bin_dir.display(),
            "starting bundled runtime"
        );

        let containerd_bin = runtime_bin_dir.join("containerd");
        let dockerd_bin = runtime_bin_dir.join("dockerd");
        let mut notes = Vec::new();

        // Ensure kernel/filesystem prerequisites before spawning daemons.
        let prereq_notes = ensure_runtime_prerequisites();
        if !prereq_notes.is_empty() {
            tracing::info!(prerequisites = %prereq_notes.join("; "), "runtime prerequisites");
        }
        notes.extend(prereq_notes);
        match ensure_data_mount() {
            Ok(note) => notes.push(note),
            Err(e) => return format!("data volume setup failed: {}", e),
        }

        for dir in ["/run/containerd", "/var/run/docker", "/etc/docker"] {
            if let Err(e) = std::fs::create_dir_all(dir) {
                notes.push(format!("mkdir {} failed({})", dir, e));
            }
        }

        // Include standard search paths so containerd/dockerd can invoke
        // modprobe, mount, etc.
        let path_env = {
            let standard = "/usr/sbin:/usr/bin:/sbin:/bin";
            match std::env::var("PATH") {
                Ok(existing) if !existing.is_empty() => {
                    format!("{}:{}:{}", runtime_bin_dir.display(), existing, standard)
                }
                _ => format!("{}:{}", runtime_bin_dir.display(), standard),
            }
        };

        if !probe_first_ready_socket(&CONTAINERD_SOCKET_CANDIDATES).await {
            // Write a minimal containerd config that disables the CRI plugin.
            // CRI (Kubernetes Container Runtime Interface) is not needed for
            // Docker-based container usage. The containerd CLI does not support
            // a --disable-plugin flag (v1.7); the only way to disable plugins is
            // via the TOML config file.
            let containerd_config = "/etc/containerd/config.toml";
            if let Err(e) = std::fs::create_dir_all("/etc/containerd") {
                notes.push(format!("mkdir /etc/containerd failed({})", e));
            }
            let config_toml = "version = 2\ndisabled_plugins = [\"io.containerd.grpc.v1.cri\"]\n";
            if let Err(e) = std::fs::write(containerd_config, config_toml) {
                notes.push(format!("write containerd config failed({})", e));
            }

            let mut cmd = Command::new(&containerd_bin);
            cmd.args([
                "--config",
                containerd_config,
                "--address",
                CONTAINERD_SOCKET,
                "--state",
                "/run/containerd",
            ])
            .env("PATH", &path_env)
            .stdin(Stdio::null())
            .stdout(daemon_log_file("containerd"))
            .stderr(daemon_log_file("containerd"));

            match cmd.spawn() {
                Ok(child) => {
                    let pid = child.id().unwrap_or_default();
                    tracing::info!(pid, "spawned bundled containerd");
                    notes.push(format!("spawned bundled containerd (pid={})", pid));
                }
                Err(e) => return format!("failed to spawn bundled containerd: {}", e),
            }
        }

        // Poll for containerd socket readiness before spawning dockerd.
        // containerd may take several seconds to initialise its gRPC socket,
        // especially on first boot when it has to set up its state directories.
        // We wait up to 8 s in 200 ms increments; failing to detect it is not
        // fatal — dockerd will retry on its own, but logging it helps debugging.
        {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
            let mut containerd_ok = false;
            while tokio::time::Instant::now() < deadline {
                if probe_first_ready_socket(&CONTAINERD_SOCKET_CANDIDATES).await {
                    containerd_ok = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            let elapsed_ms = (tokio::time::Instant::now()
                .duration_since(deadline - Duration::from_secs(8)))
            .as_millis();
            tracing::info!(
                containerd_ready = containerd_ok,
                elapsed_ms,
                "containerd socket poll complete"
            );
            if !containerd_ok {
                notes.push("containerd socket not ready after 8s".to_string());
            }
        }

        if !probe_unix_socket(DOCKER_API_UNIX_SOCKET).await {
            let mut cmd = Command::new(&dockerd_bin);
            cmd.arg(format!("--host=unix://{DOCKER_API_UNIX_SOCKET}"))
                .arg(format!("--containerd={CONTAINERD_SOCKET}"))
                .arg("--exec-root=/var/run/docker")
                .arg(format!("--data-root={DOCKER_DATA_MOUNT_POINT}"))
                .arg("--userland-proxy=false")
                .env("PATH", &path_env)
                .stdin(Stdio::null())
                .stdout(daemon_log_file("dockerd"))
                .stderr(daemon_log_file("dockerd"));

            match cmd.spawn() {
                Ok(child) => {
                    let pid = child.id().unwrap_or_default();
                    tracing::info!(pid, "spawned bundled dockerd");
                    notes.push(format!("spawned bundled dockerd (pid={})", pid));
                }
                Err(e) => return format!("failed to spawn bundled dockerd: {}", e),
            }
        }

        notes.join("; ")
    }

    /// Collects system information from the guest.
    fn collect_system_info() -> SystemInfo {
        fn parse_ip_output(stdout: &[u8]) -> Vec<String> {
            let mut ips = Vec::new();
            let output = String::from_utf8_lossy(stdout);

            for token in output.split(|c: char| c.is_whitespace() || c == ',') {
                let token = token.trim();
                if token.is_empty() {
                    continue;
                }

                let Ok(addr) = token.parse::<IpAddr>() else {
                    continue;
                };
                if addr.is_loopback() {
                    continue;
                }

                let ip = addr.to_string();
                if !ips.iter().any(|existing| existing == &ip) {
                    ips.push(ip);
                }
            }

            ips
        }

        let mut info = SystemInfo::default();

        // Kernel version
        if let Ok(uname) = nix::sys::utsname::uname() {
            info.kernel_version = uname.release().to_string_lossy().to_string();
            info.os_name = uname.sysname().to_string_lossy().to_string();
            info.os_version = uname.version().to_string_lossy().to_string();
            info.arch = uname.machine().to_string_lossy().to_string();
            info.hostname = uname.nodename().to_string_lossy().to_string();
        }

        // Memory info
        if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
            for line in meminfo.lines() {
                if line.starts_with("MemTotal:") {
                    if let Some(kb) = line.split_whitespace().nth(1) {
                        if let Ok(kb_val) = kb.parse::<u64>() {
                            info.total_memory = kb_val * 1024;
                        }
                    }
                } else if line.starts_with("MemAvailable:") {
                    if let Some(kb) = line.split_whitespace().nth(1) {
                        if let Ok(kb_val) = kb.parse::<u64>() {
                            info.available_memory = kb_val * 1024;
                        }
                    }
                }
            }
        }

        // CPU count
        info.cpu_count = std::thread::available_parallelism()
            .map(|p| p.get() as u32)
            .unwrap_or(1);

        // Load average
        if let Ok(loadavg) = std::fs::read_to_string("/proc/loadavg") {
            let parts: Vec<&str> = loadavg.split_whitespace().collect();
            if parts.len() >= 3 {
                if let Ok(load1) = parts[0].parse::<f64>() {
                    info.load_average.push(load1);
                }
                if let Ok(load5) = parts[1].parse::<f64>() {
                    info.load_average.push(load5);
                }
                if let Ok(load15) = parts[2].parse::<f64>() {
                    info.load_average.push(load15);
                }
            }
        }

        // Uptime
        if let Ok(uptime) = std::fs::read_to_string("/proc/uptime") {
            if let Some(secs) = uptime.split_whitespace().next() {
                if let Ok(secs_val) = secs.parse::<f64>() {
                    info.uptime = secs_val as u64;
                }
            }
        }

        // IP addresses (excluding loopback).
        // Coreutils `hostname` supports `-I`, BusyBox supports `-i`.
        for flag in ["-I", "-i"] {
            let Ok(output) = std::process::Command::new("hostname").arg(flag).output() else {
                continue;
            };

            if !output.status.success() {
                continue;
            }

            let ips = parse_ip_output(&output.stdout);
            if !ips.is_empty() {
                info.ip_addresses = ips;
                break;
            }
        }

        info
    }
}
// =============================================================================
// macOS Stub Implementation (for development/testing)
// =============================================================================

#[cfg(not(target_os = "linux"))]
mod stub {
    use anyhow::Result;

    use super::AGENT_PORT;

    /// The Guest Agent (stub for non-Linux platforms).
    pub struct Agent;

    impl Agent {
        /// Creates a new agent.
        pub fn new() -> Self {
            Self
        }

        /// Runs the agent (stub mode).
        ///
        /// On non-Linux platforms (e.g., macOS), vsock is not available.
        /// This stub allows development and testing on the host.
        pub async fn run(&self) -> Result<()> {
            tracing::warn!("Agent is running in stub mode (non-Linux platform)");
            tracing::info!("Agent would listen on vsock port {}", AGENT_PORT);

            // In stub mode, we just keep the agent running
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
                tracing::debug!("Agent stub heartbeat");
            }
        }
    }

    impl Default for Agent {
        fn default() -> Self {
            Self::new()
        }
    }
}

// =============================================================================
// Public API
// =============================================================================

#[cfg(target_os = "linux")]
pub use linux::Agent;

#[cfg(not(target_os = "linux"))]
pub use stub::Agent;

/// Runs the agent.
pub async fn run() -> Result<()> {
    let agent = Agent::new();
    agent.run().await
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Docker Log Format Parsing Tests
    // =========================================================================

    /// Helper to parse Docker JSON log line for testing.
    fn parse_docker_log_line(line: &str, stdout: bool, stderr: bool) -> Option<String> {
        let parsed: serde_json::Value = serde_json::from_str(line).ok()?;
        let stream = parsed.get("stream")?.as_str()?;
        let log = parsed.get("log")?.as_str()?;

        match stream {
            "stdout" if stdout => Some(log.to_string()),
            "stderr" if stderr => Some(log.to_string()),
            _ => None,
        }
    }

    #[test]
    fn test_parse_docker_log_stdout() {
        let line = r#"{"log":"hello world","stream":"stdout","time":"2024-01-08T12:00:00Z"}"#;

        let result = parse_docker_log_line(line, true, false);
        assert_eq!(result, Some("hello world".to_string()));

        // Should filter out when stdout=false
        let result = parse_docker_log_line(line, false, true);
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_docker_log_stderr() {
        let line = r#"{"log":"error message","stream":"stderr","time":"2024-01-08T12:00:00Z"}"#;

        let result = parse_docker_log_line(line, false, true);
        assert_eq!(result, Some("error message".to_string()));

        // Should filter out when stderr=false
        let result = parse_docker_log_line(line, true, false);
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_docker_log_both_streams() {
        let stdout_line = r#"{"log":"stdout msg","stream":"stdout","time":"2024-01-08T12:00:00Z"}"#;
        let stderr_line = r#"{"log":"stderr msg","stream":"stderr","time":"2024-01-08T12:00:00Z"}"#;

        // Both enabled
        assert_eq!(
            parse_docker_log_line(stdout_line, true, true),
            Some("stdout msg".to_string())
        );
        assert_eq!(
            parse_docker_log_line(stderr_line, true, true),
            Some("stderr msg".to_string())
        );
    }

    #[test]
    fn test_parse_docker_log_invalid_json() {
        let invalid = "not json";
        assert_eq!(parse_docker_log_line(invalid, true, true), None);

        let incomplete = r#"{"log":"test"}"#; // Missing stream field
        assert_eq!(parse_docker_log_line(incomplete, true, true), None);
    }

    #[test]
    fn test_parse_docker_log_special_characters() {
        // Test with escaped characters
        let line = r#"{"log":"line with \"quotes\" and \\backslash","stream":"stdout","time":"2024-01-08T12:00:00Z"}"#;

        let result = parse_docker_log_line(line, true, false);
        assert_eq!(
            result,
            Some(r#"line with "quotes" and \backslash"#.to_string())
        );
    }

    #[test]
    fn test_parse_docker_log_empty_content() {
        let line = r#"{"log":"","stream":"stdout","time":"2024-01-08T12:00:00Z"}"#;

        let result = parse_docker_log_line(line, true, false);
        assert_eq!(result, Some("".to_string()));
    }

    #[test]
    fn test_parse_docker_log_multiline_content() {
        // Docker typically escapes newlines in log content
        let line = r#"{"log":"line1\\nline2","stream":"stdout","time":"2024-01-08T12:00:00Z"}"#;

        let result = parse_docker_log_line(line, true, false);
        assert!(result.is_some());
        // The escaped newline should be preserved
        assert!(result.unwrap().contains("\\n"));
    }

    // =========================================================================
    // Agent Creation Tests
    // =========================================================================

    #[test]
    fn test_agent_creation() {
        let _agent = Agent::new();
    }

    // =========================================================================
    // EnsureRuntime State Machine Tests
    // =========================================================================

    use crate::agent::ensure_runtime::{
        self, RuntimeGuard, RuntimeState, STATUS_FAILED, STATUS_REUSED, STATUS_STARTED,
    };
    use arcbox_protocol::agent::RuntimeEnsureResponse;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Helper: creates a successful RuntimeEnsureResponse.
    fn make_ready_response() -> RuntimeEnsureResponse {
        RuntimeEnsureResponse {
            ready: true,
            endpoint: "vsock:2375".to_string(),
            message: "docker socket ready".to_string(),
            status: STATUS_STARTED.to_string(),
        }
    }

    /// Helper: creates a failed RuntimeEnsureResponse.
    fn make_failed_response() -> RuntimeEnsureResponse {
        RuntimeEnsureResponse {
            ready: false,
            endpoint: String::new(),
            message: "docker socket missing".to_string(),
            status: STATUS_FAILED.to_string(),
        }
    }

    #[tokio::test]
    async fn test_ensure_runtime_first_call_started() {
        let guard = RuntimeGuard::new();
        let response =
            ensure_runtime::ensure_runtime(&guard, true, async { make_ready_response() }, async {
                unreachable!("probe should not be called when start_if_needed=true")
            })
            .await;

        assert!(response.ready);
        assert_eq!(response.status, STATUS_STARTED);
        assert_eq!(response.endpoint, "vsock:2375");
    }

    #[tokio::test]
    async fn test_ensure_runtime_second_call_reused() {
        let guard = RuntimeGuard::new();

        // First call: starts runtime.
        let r1 =
            ensure_runtime::ensure_runtime(&guard, true, async { make_ready_response() }, async {
                unreachable!()
            })
            .await;
        assert_eq!(r1.status, STATUS_STARTED);

        // Second call: should reuse.
        let r2 = ensure_runtime::ensure_runtime(
            &guard,
            true,
            async { panic!("start_fn should not be called for reuse") },
            async { unreachable!() },
        )
        .await;
        assert!(r2.ready);
        assert_eq!(r2.status, STATUS_REUSED);
    }

    #[tokio::test]
    async fn test_ensure_runtime_20_sequential_calls_no_error() {
        let guard = RuntimeGuard::new();

        for i in 0..20 {
            let response = ensure_runtime::ensure_runtime(
                &guard,
                true,
                async { make_ready_response() },
                async { unreachable!() },
            )
            .await;
            assert!(response.ready, "call {} should succeed", i);
            if i == 0 {
                assert_eq!(response.status, STATUS_STARTED);
            } else {
                assert_eq!(response.status, STATUS_REUSED);
            }
        }
    }

    #[tokio::test]
    async fn test_ensure_runtime_probe_only_no_start() {
        let guard = RuntimeGuard::new();

        let response = ensure_runtime::ensure_runtime(
            &guard,
            false,
            async { panic!("start_fn should not be called when start_if_needed=false") },
            async {
                RuntimeEnsureResponse {
                    ready: false,
                    endpoint: String::new(),
                    message: "docker not available".to_string(),
                    status: STATUS_FAILED.to_string(),
                }
            },
        )
        .await;

        assert!(!response.ready);
        assert_eq!(response.status, STATUS_FAILED);
    }

    #[tokio::test]
    async fn test_ensure_runtime_failed_then_retry_succeeds() {
        let guard = RuntimeGuard::new();

        // First call: fails.
        let r1 =
            ensure_runtime::ensure_runtime(&guard, true, async { make_failed_response() }, async {
                unreachable!()
            })
            .await;
        assert!(!r1.ready);
        assert_eq!(r1.status, STATUS_FAILED);

        // Second call: retry, now succeeds.
        let r2 =
            ensure_runtime::ensure_runtime(&guard, true, async { make_ready_response() }, async {
                unreachable!()
            })
            .await;
        assert!(r2.ready);
        assert_eq!(r2.status, STATUS_STARTED);

        // Third call: reused.
        let r3 = ensure_runtime::ensure_runtime(
            &guard,
            true,
            async { panic!("should not start again") },
            async { unreachable!() },
        )
        .await;
        assert!(r3.ready);
        assert_eq!(r3.status, STATUS_REUSED);
    }

    #[tokio::test]
    async fn test_ensure_runtime_concurrent_5_callers_consistent() {
        let guard = Arc::new(RuntimeGuard::new());
        let start_count = Arc::new(AtomicU32::new(0));
        let barrier = Arc::new(tokio::sync::Barrier::new(5));

        let mut handles = Vec::new();
        for _ in 0..5 {
            let guard = Arc::clone(&guard);
            let start_count = Arc::clone(&start_count);
            let barrier = Arc::clone(&barrier);

            handles.push(tokio::spawn(async move {
                // Synchronize all 5 tasks to start concurrently.
                barrier.wait().await;

                ensure_runtime::ensure_runtime(
                    &guard,
                    true,
                    async {
                        start_count.fetch_add(1, Ordering::SeqCst);
                        // Simulate some startup delay.
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        make_ready_response()
                    },
                    async { unreachable!() },
                )
                .await
            }));
        }

        let mut results = Vec::new();
        for handle in handles {
            results.push(handle.await.unwrap());
        }

        // All 5 should report ready.
        for (i, r) in results.iter().enumerate() {
            assert!(r.ready, "caller {} should see ready", i);
        }

        // Exactly 1 should have status "started", rest "reused".
        let started_count = results
            .iter()
            .filter(|r| r.status == STATUS_STARTED)
            .count();
        let reused_count = results.iter().filter(|r| r.status == STATUS_REUSED).count();
        assert_eq!(started_count, 1, "exactly one caller should be the driver");
        assert_eq!(reused_count, 4, "other callers should get reused");

        // start_fn should have been invoked exactly once.
        assert_eq!(start_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_ensure_runtime_concurrent_5_callers_failure_consistent() {
        let guard = Arc::new(RuntimeGuard::new());
        let barrier = Arc::new(tokio::sync::Barrier::new(5));

        let mut handles = Vec::new();
        for _ in 0..5 {
            let guard = Arc::clone(&guard);
            let barrier = Arc::clone(&barrier);

            handles.push(tokio::spawn(async move {
                barrier.wait().await;
                ensure_runtime::ensure_runtime(
                    &guard,
                    true,
                    async {
                        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
                        make_failed_response()
                    },
                    async { unreachable!() },
                )
                .await
            }));
        }

        let mut results = Vec::new();
        for handle in handles {
            results.push(handle.await.unwrap());
        }

        // All 5 should report not ready.
        for (i, r) in results.iter().enumerate() {
            assert!(!r.ready, "caller {} should see not ready", i);
            assert_eq!(r.status, STATUS_FAILED, "caller {} should get failed", i);
        }
    }

    #[tokio::test]
    async fn test_ensure_runtime_no_lost_wakeup_when_driver_finishes_fast() {
        // Repeat to make the regression deterministic enough: this used to
        // hang intermittently when notify happened before waiter registered.
        for _ in 0..50 {
            let guard = Arc::new(RuntimeGuard::new());
            let entered_start_fn = Arc::new(tokio::sync::Notify::new());
            let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();

            let guard_driver = Arc::clone(&guard);
            let entered_start_fn_driver = Arc::clone(&entered_start_fn);
            let driver = tokio::spawn(async move {
                ensure_runtime::ensure_runtime(
                    &guard_driver,
                    true,
                    async move {
                        entered_start_fn_driver.notify_waiters();
                        let _ = release_rx.await;
                        make_ready_response()
                    },
                    async { unreachable!() },
                )
                .await
            });

            // Ensure state has transitioned to Starting before spawning waiter.
            entered_start_fn.notified().await;

            let guard_waiter = Arc::clone(&guard);
            let waiter = tokio::spawn(async move {
                ensure_runtime::ensure_runtime(
                    &guard_waiter,
                    true,
                    async { panic!("waiter should never run start_fn") },
                    async { unreachable!() },
                )
                .await
            });

            // Give waiter a chance to enter wait path, then let driver finish.
            tokio::task::yield_now().await;
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            let _ = release_tx.send(());

            let driver_resp = tokio::time::timeout(std::time::Duration::from_millis(500), driver)
                .await
                .expect("driver timed out")
                .expect("driver task failed");
            let waiter_resp = tokio::time::timeout(std::time::Duration::from_millis(500), waiter)
                .await
                .expect("waiter timed out")
                .expect("waiter task failed");

            assert!(driver_resp.ready);
            assert_eq!(driver_resp.status, STATUS_STARTED);
            assert!(waiter_resp.ready);
            assert_eq!(waiter_resp.status, STATUS_REUSED);
        }
    }

    #[tokio::test]
    async fn test_ensure_runtime_state_machine_transitions() {
        let guard = RuntimeGuard::new();

        // Initially NotStarted.
        {
            let state = guard.state.lock().await;
            assert!(matches!(&*state, RuntimeState::NotStarted));
        }

        // After successful ensure: Ready.
        let _ =
            ensure_runtime::ensure_runtime(&guard, true, async { make_ready_response() }, async {
                unreachable!()
            })
            .await;
        {
            let state = guard.state.lock().await;
            assert!(
                matches!(&*state, RuntimeState::Ready { .. }),
                "expected Ready, got {:?}",
                *state
            );
        }
    }

    #[tokio::test]
    async fn test_ensure_runtime_state_machine_failed_to_ready() {
        let guard = RuntimeGuard::new();

        // Fail first.
        let _ =
            ensure_runtime::ensure_runtime(&guard, true, async { make_failed_response() }, async {
                unreachable!()
            })
            .await;
        {
            let state = guard.state.lock().await;
            assert!(
                matches!(&*state, RuntimeState::Failed { .. }),
                "expected Failed, got {:?}",
                *state
            );
        }

        // Retry succeeds.
        let _ =
            ensure_runtime::ensure_runtime(&guard, true, async { make_ready_response() }, async {
                unreachable!()
            })
            .await;
        {
            let state = guard.state.lock().await;
            assert!(
                matches!(&*state, RuntimeState::Ready { .. }),
                "expected Ready after retry, got {:?}",
                *state
            );
        }
    }

    #[tokio::test]
    async fn test_ensure_runtime_probe_after_ready_returns_reused() {
        let guard = RuntimeGuard::new();

        // Start first.
        let _ =
            ensure_runtime::ensure_runtime(&guard, true, async { make_ready_response() }, async {
                unreachable!()
            })
            .await;

        // Probe (start_if_needed=false) should return reused immediately
        // from the cached state, without calling probe_fn.
        let r = ensure_runtime::ensure_runtime(
            &guard,
            false,
            async { panic!("start_fn should not be called") },
            async { panic!("probe_fn should not be called when state is Ready") },
        )
        .await;
        assert!(r.ready);
        assert_eq!(r.status, STATUS_REUSED);
    }
}
