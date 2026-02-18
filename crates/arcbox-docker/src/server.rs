//! Docker API server.

use crate::api::create_router;
use crate::error::{DockerError, Result};
use arcbox_core::{ContainerBackendMode, Runtime};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper_util::rt::TokioIo;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{UnixListener, UnixStream};
use tower::Service;
use tower_http::trace::TraceLayer;

/// Docker API server configuration.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Unix socket path.
    pub socket_path: PathBuf,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            socket_path: default_socket_path(),
        }
    }
}

fn default_socket_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join(".arcbox")
        .join("docker.sock")
}

/// Docker API server.
pub struct DockerApiServer {
    config: ServerConfig,
    runtime: Arc<Runtime>,
}

struct RawFdWrapper(OwnedFd);

impl AsRawFd for RawFdWrapper {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

struct RawFdStream {
    inner: AsyncFd<RawFdWrapper>,
}

impl RawFdStream {
    fn from_raw_fd(fd: RawFd) -> io::Result<Self> {
        if fd < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid file descriptor",
            ));
        }

        Self::set_nonblocking(fd)?;
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        let inner = AsyncFd::new(RawFdWrapper(owned))?;
        Ok(Self { inner })
    }

    fn set_nonblocking(fd: RawFd) -> io::Result<()> {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        let result = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

impl AsyncRead for RawFdStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let mut guard = ready!(self.inner.poll_read_ready(cx))?;
            match guard.try_io(|inner| {
                let fd = inner.get_ref().as_raw_fd();
                let slice = buf.initialize_unfilled();
                let n = unsafe { libc::read(fd, slice.as_mut_ptr().cast(), slice.len()) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(Ok(n)) => {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(e)) if e.kind() == io::ErrorKind::Interrupted => continue,
                Ok(Err(e)) => return Poll::Ready(Err(e)),
                Err(_would_block) => continue,
            }
        }
    }
}

impl AsyncWrite for RawFdStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            let mut guard = ready!(self.inner.poll_write_ready(cx))?;
            match guard.try_io(|inner| {
                let fd = inner.get_ref().as_raw_fd();
                let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(Ok(n)) => return Poll::Ready(Ok(n)),
                Ok(Err(e)) if e.kind() == io::ErrorKind::Interrupted => continue,
                Ok(Err(e)) => return Poll::Ready(Err(e)),
                Err(_would_block) => continue,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let fd = self.inner.get_ref().as_raw_fd();
        let result = unsafe { libc::shutdown(fd, libc::SHUT_WR) };
        if result == 0 {
            return Poll::Ready(Ok(()));
        }

        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOTCONN) {
            return Poll::Ready(Ok(()));
        }
        Poll::Ready(Err(err))
    }
}

impl DockerApiServer {
    /// Creates a new Docker API server.
    #[must_use]
    pub fn new(config: ServerConfig, runtime: Arc<Runtime>) -> Self {
        Self { config, runtime }
    }

    /// Returns the socket path.
    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.config.socket_path
    }

    /// Runs the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the server fails to start.
    pub async fn run(&self) -> Result<()> {
        // Remove existing socket
        let _ = std::fs::remove_file(&self.config.socket_path);

        // Create parent directory if needed
        if let Some(parent) = self.config.socket_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let listener = UnixListener::bind(&self.config.socket_path)
            .map_err(|e| crate::error::DockerError::Server(e.to_string()))?;

        tracing::info!(
            "Docker API server listening on {}",
            self.config.socket_path.display()
        );
        match self.runtime.config().container.backend {
            ContainerBackendMode::NativeControlPlane => self.run_native_http(listener).await,
            ContainerBackendMode::GuestDocker => {
                let port = self.runtime.config().container.guest_docker_vsock_port;
                self.run_guest_docker_proxy(listener, port).await
            }
        }
    }
}

impl DockerApiServer {
    async fn run_native_http(&self, listener: UnixListener) -> Result<()> {
        let app = create_router(Arc::clone(&self.runtime)).layer(TraceLayer::new_for_http());
        tracing::info!("Docker API backend: native control plane");

        loop {
            let (stream, _) = listener
                .accept()
                .await
                .map_err(|e| DockerError::Server(e.to_string()))?;

            let tower_service = app.clone();
            tokio::spawn(async move {
                let hyper_service =
                    hyper::service::service_fn(move |request: hyper::Request<Incoming>| {
                        tower_service.clone().call(request)
                    });

                if let Err(err) = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), hyper_service)
                    .with_upgrades()
                    .await
                {
                    let err_str = err.to_string().to_lowercase();
                    if !err_str.contains("shutting down")
                        && !err_str.contains("connection reset")
                        && !err_str.contains("broken pipe")
                    {
                        tracing::error!("Error serving connection: {}", err);
                    }
                }
            });
        }
    }

    async fn run_guest_docker_proxy(&self, listener: UnixListener, guest_port: u32) -> Result<()> {
        tracing::info!(
            guest_docker_vsock_port = guest_port,
            "Docker API backend: guest docker proxy"
        );

        loop {
            let (client_stream, _) = listener
                .accept()
                .await
                .map_err(|e| DockerError::Server(e.to_string()))?;
            let runtime = Arc::clone(&self.runtime);

            tokio::spawn(async move {
                if let Err(err) =
                    proxy_guest_docker_connection(runtime, guest_port, client_stream).await
                {
                    if !is_disconnect_error(&err) {
                        tracing::warn!("Guest docker proxy connection failed: {}", err);
                    }
                }
            });
        }
    }
}

async fn proxy_guest_docker_connection(
    runtime: Arc<Runtime>,
    guest_port: u32,
    mut client_stream: UnixStream,
) -> Result<()> {
    runtime
        .ensure_vm_ready()
        .await
        .map_err(|e| DockerError::Server(format!("failed to ensure vm ready: {}", e)))?;

    let machine_name = runtime.default_machine_name();
    let guest_fd = runtime
        .machine_manager()
        .connect_vsock_port(machine_name, guest_port)
        .map_err(|e| {
            DockerError::Server(format!(
                "failed to connect guest docker endpoint on vsock port {}: {}",
                guest_port, e
            ))
        })?;

    let mut guest_stream = RawFdStream::from_raw_fd(guest_fd)
        .map_err(|e| DockerError::Server(format!("failed to create guest stream: {}", e)))?;

    let _ = tokio::io::copy_bidirectional(&mut client_stream, &mut guest_stream).await?;
    Ok(())
}

fn is_disconnect_error(err: &DockerError) -> bool {
    let msg = err.to_string().to_lowercase();
    msg.contains("broken pipe")
        || msg.contains("connection reset")
        || msg.contains("connection aborted")
        || msg.contains("unexpected eof")
}
