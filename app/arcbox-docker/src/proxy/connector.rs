//! Production guest connector via vsock.

use super::GuestConnector;
use crate::error::{DockerError, Result};
use crate::routing::UtilityVmRole;
use arcbox_core::Runtime;
use arcbox_error::CommonError;
use arcbox_transport::vsock::{VsockShutdown, VsockStream};
use hyper_util::rt::TokioIo;
use std::future::Future;
use std::os::fd::{FromRawFd, OwnedFd};
use std::pin::Pin;
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tokio::sync::Semaphore;
use tracing::Instrument as _;

/// Timeout for establishing a vsock connection to guest dockerd.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum number of concurrent vsock connection attempts.
///
/// Prevents blocking thread pool exhaustion when the guest is unresponsive
/// and Docker clients retry aggressively.
const MAX_CONCURRENT_CONNECTS: usize = 8;

static CONNECT_SEMAPHORE: LazyLock<Semaphore> =
    LazyLock::new(|| Semaphore::new(MAX_CONCURRENT_CONNECTS));

/// Connects to guest dockerd via vsock through the machine manager.
pub struct VsockConnector {
    runtime: Arc<Runtime>,
}

impl VsockConnector {
    #[must_use]
    pub fn new(runtime: Arc<Runtime>) -> Self {
        Self { runtime }
    }
}

impl GuestConnector for VsockConnector {
    fn connect(&self) -> Pin<Box<dyn Future<Output = Result<TokioIo<VsockStream>>> + Send + '_>> {
        self.connect_for(UtilityVmRole::Native)
    }

    fn connect_for(
        &self,
        role: UtilityVmRole,
    ) -> Pin<Box<dyn Future<Output = Result<TokioIo<VsockStream>>> + Send + '_>> {
        let span = tracing::debug_span!(
            "docker.guest.vsock.connect",
            utility_vm = role.as_str(),
            machine = tracing::field::Empty,
            port = tracing::field::Empty,
        );
        Box::pin(
            async move {
                let _permit = CONNECT_SEMAPHORE
                    .acquire()
                    .await
                    .map_err(|_| DockerError::Server("connect semaphore closed".into()))?;

                // Resolve role → machine/port via the runtime. Today both
                // roles still alias to the default machine; once the dual VM
                // lifecycle lands the rosetta branch returns its own machine
                // name and dockerd port without any change here.
                let port = self.runtime.guest_docker_vsock_port_for_role(role);
                let machine_name = self.runtime.machine_name_for_role(role);
                let manager = self.runtime.machine_manager().clone();
                let name = machine_name.to_string();
                tracing::Span::current().record("machine", name.as_str());
                tracing::Span::current().record("port", port);
                tracing::debug!(
                    utility_vm = role.as_str(),
                    machine = %name,
                    port,
                    "connecting to guest dockerd"
                );

                let handle = tokio::task::spawn_blocking(move || {
                    let fd = manager.connect_vsock_port(&name, port)?;
                    // SAFETY: fd is a valid, newly-opened vsock file descriptor.
                    Ok::<_, arcbox_core::CoreError>(unsafe { OwnedFd::from_raw_fd(fd) })
                });
                let abort_handle = handle.abort_handle();

                let owned_fd = match tokio::time::timeout(CONNECT_TIMEOUT, handle).await {
                    Ok(join_result) => join_result
                        .map_err(|e| {
                            let reason = if e.is_cancelled() {
                                "cancelled"
                            } else {
                                "panicked"
                            };
                            DockerError::Server(format!("connect task {reason}: {e}"))
                        })?
                        .map_err(|e| {
                            DockerError::Server(format!("failed to connect to guest docker: {e}"))
                        })?,
                    Err(_elapsed) => {
                        abort_handle.abort();
                        return Err(CommonError::timeout("guest docker connect timed out").into());
                    }
                };

                let stream =
                    VsockStream::from_fd_with_shutdown(owned_fd, VsockShutdown::CloseOnDropOnly)
                        .map_err(|e| {
                            DockerError::Server(format!("failed to create guest stream: {e}"))
                        })?;
                Ok(TokioIo::new(stream))
            }
            .instrument(span),
        )
    }
}
