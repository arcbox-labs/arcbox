//! Firecracker's hybrid vsock: a Unix socket in both directions.
//!
//! Firecracker exposes a Unix domain socket (`uds_path`) that acts as a proxy
//! for host-initiated connections to guest vsock ports.  The handshake:
//!
//! 1. Connect to `uds_path`.
//! 2. Write `"CONNECT {port}\n"`.
//! 3. Read until `'\n'` — the response is `"OK {host_ephemeral_port}\n"`.
//! 4. The socket is now a bidirectional pipe to the guest's vsock port.
//!
//! In the other direction, a guest-initiated connect to host port `P` is
//! forwarded by Firecracker to a host Unix socket at `{uds_path}_{P}`; a
//! [`UdsListener`] pre-binds there before the guest starts.

use std::path::{Path, PathBuf};

use arcbox_vm_driver::{Error, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

use crate::error::FcError;

/// Single attempt: connect to the Firecracker vsock UDS and complete the
/// `CONNECT {port}` / `OK` handshake.
///
/// Firecracker closes the connection without answering when no listener is
/// active on the guest port yet (kernel still booting, agent not started);
/// that outcome is [`Error::Io`] of kind
/// [`ConnectionRefused`](std::io::ErrorKind::ConnectionRefused), the one a
/// caller retries on. Every other failure is final.
pub async fn dial_uds(uds_path: &Path, port: u32) -> Result<UnixStream> {
    let mut stream =
        UnixStream::connect(uds_path)
            .await
            .map_err(|source| FcError::VsockConnect {
                uds: uds_path.to_path_buf(),
                source,
            })?;
    let handshake = |detail: &str, source: std::io::Error| FcError::VsockHandshake {
        uds: uds_path.to_path_buf(),
        detail: detail.to_owned(),
        source: Some(source),
    };
    let malformed = |detail: &str| FcError::VsockHandshake {
        uds: uds_path.to_path_buf(),
        detail: detail.to_owned(),
        source: None,
    };

    // Firecracker vsock host-initiated handshake.
    stream
        .write_all(format!("CONNECT {port}\n").as_bytes())
        .await
        .map_err(|e| handshake("CONNECT write", e))?;

    // Read "OK {port}\n".
    let mut buf = [0u8; 64];
    let mut i = 0usize;
    loop {
        let n = stream
            .read(&mut buf[i..=i])
            .await
            .map_err(|e| handshake("response read", e))?;
        if n == 0 {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                format!("vsock port {port}: connection closed during handshake"),
            )));
        }
        if buf[i] == b'\n' {
            break;
        }
        i += 1;
        if i >= buf.len() - 1 {
            return Err(malformed("response too long").into());
        }
    }
    let resp = std::str::from_utf8(&buf[..=i]).map_err(|_| malformed("non-UTF-8 response"))?;
    if !resp.starts_with("OK") {
        return Err(malformed(&format!("unexpected response: {resp:?}")).into());
    }
    Ok(stream)
}

/// Derive the host Unix-socket path Firecracker forwards guest-initiated
/// connections to host `port` to: `{uds_path}_{port}`.
///
/// The suffix convention is Firecracker's hybrid-vsock contract ("a guest
/// connection to port 52 will get forwarded to `./v.sock_52`", FC
/// docs/vsock.md). FC resolves the path against its own filesystem view,
/// which matches the host view here: in jailer mode both are the same file
/// under the chroot root, in direct mode the same absolute path.
pub fn listener_socket_path(uds_path: &Path, port: u32) -> PathBuf {
    let mut path = uds_path.as_os_str().to_owned();
    path.push(format!("_{port}"));
    PathBuf::from(path)
}

/// Pre-bound listener for a guest dial-out to one host port.
///
/// Must be bound BEFORE Firecracker `InstanceStart` for a boot-time
/// dial-out: FC forwards the guest's connect only to an already-listening
/// socket and resets the guest otherwise, losing the event. The socket file
/// is per-boot; dropping the listener removes it.
pub struct UdsListener {
    listener: UnixListener,
    path: PathBuf,
}

impl UdsListener {
    /// Bind the listener socket for `port` on `uds_path`, replacing any
    /// stale socket file left behind by a previous boot of the same VM
    /// directory.
    pub fn bind(uds_path: &Path, port: u32) -> Result<Self> {
        let path = listener_socket_path(uds_path, port);
        if let Err(e) = std::fs::remove_file(&path)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            return Err(FcError::VsockListen {
                what: "remove stale listener socket",
                path,
                source: e,
            }
            .into());
        }
        let listener = UnixListener::bind(&path).map_err(|source| FcError::VsockListen {
            what: "bind listener socket",
            path: path.clone(),
            source,
        })?;
        Ok(Self { listener, path })
    }

    /// The bound socket path (so jailer boots can grant FC connect access).
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Wait for the next guest connection.
    pub async fn accept(&self) -> Result<UnixStream> {
        std::future::poll_fn(|cx| self.poll_accept(cx)).await
    }

    /// Poll for the next guest connection.
    pub fn poll_accept(
        &self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<UnixStream>> {
        self.listener.poll_accept(cx).map(|accepted| {
            accepted.map(|(stream, _)| stream).map_err(|source| {
                FcError::VsockListen {
                    what: "accept on listener socket",
                    path: self.path.clone(),
                    source,
                }
                .into()
            })
        })
    }
}

impl Drop for UdsListener {
    fn drop(&mut self) {
        // The socket file is meaningful only to the boot that bound it.
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listener_socket_path_appends_the_port_suffix() {
        // Pins the Firecracker hybrid-vsock naming contract: a guest
        // dialing host port 51 lands on `{uds}_51`.
        assert_eq!(
            listener_socket_path(Path::new("/vm/dir/firecracker.vsock"), 51),
            Path::new("/vm/dir/firecracker.vsock_51")
        );
    }

    #[tokio::test]
    async fn listener_accepts_the_dial_out_and_cleans_up() {
        let dir = tempfile::tempdir().unwrap();
        let uds = dir.path().join("fc.vsock");
        // A stale socket file from a previous boot must not fail the bind.
        std::fs::write(listener_socket_path(&uds, 51), b"stale").unwrap();

        let listener = UdsListener::bind(&uds, 51).unwrap();
        let dial_path = listener.path().to_owned();
        let dial = tokio::spawn(async move {
            let mut stream = UnixStream::connect(&dial_path).await.unwrap();
            stream.write_all(&[0u8]).await.unwrap();
        });
        let mut stream = listener.accept().await.unwrap();
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).await.unwrap();
        dial.await.unwrap();

        let path = listener.path().to_owned();
        drop(listener);
        assert!(!path.exists(), "drop must remove the per-boot socket file");
    }

    #[tokio::test]
    async fn dial_completes_the_connect_handshake() {
        let dir = tempfile::tempdir().unwrap();
        let uds = dir.path().join("fc.vsock");
        let proxy = UnixListener::bind(&uds).unwrap();
        let fc = tokio::spawn(async move {
            let (mut stream, _) = proxy.accept().await.unwrap();
            let mut req = vec![0u8; "CONNECT 52\n".len()];
            stream.read_exact(&mut req).await.unwrap();
            assert_eq!(req, b"CONNECT 52\n");
            stream.write_all(b"OK 1024\n").await.unwrap();
            stream
        });
        let stream = dial_uds(&uds, 52).await.unwrap();
        drop(stream);
        fc.await.unwrap();
    }

    #[tokio::test]
    async fn dial_reports_a_closed_handshake_as_connection_refused() {
        let dir = tempfile::tempdir().unwrap();
        let uds = dir.path().join("fc.vsock");
        let proxy = UnixListener::bind(&uds).unwrap();
        // Firecracker's answer when nothing listens on the guest port: it
        // reads the CONNECT and closes without a reply.
        let fc = tokio::spawn(async move {
            let (mut stream, _) = proxy.accept().await.unwrap();
            let mut req = [0u8; 16];
            let _ = stream.read(&mut req).await.unwrap();
            drop(stream);
        });
        match dial_uds(&uds, 52).await {
            Err(Error::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::ConnectionRefused),
            other => panic!("expected Io(ConnectionRefused), got {other:?}"),
        }
        fc.await.unwrap();
    }

    #[tokio::test]
    async fn dial_rejects_a_non_ok_reply_and_a_missing_socket_as_final() {
        let dir = tempfile::tempdir().unwrap();
        let uds = dir.path().join("fc.vsock");
        let proxy = UnixListener::bind(&uds).unwrap();
        let fc = tokio::spawn(async move {
            let (mut stream, _) = proxy.accept().await.unwrap();
            let mut req = [0u8; 16];
            let _ = stream.read(&mut req).await.unwrap();
            stream.write_all(b"ERR nope\n").await.unwrap();
        });
        assert!(matches!(
            dial_uds(&uds, 52).await,
            Err(Error::Driver { .. })
        ));
        fc.await.unwrap();

        assert!(matches!(
            dial_uds(&dir.path().join("absent.vsock"), 52).await,
            Err(Error::Driver { .. })
        ));
    }
}
