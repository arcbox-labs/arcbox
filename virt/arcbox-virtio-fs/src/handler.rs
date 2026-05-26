//! FUSE request handler trait — implemented downstream (e.g. by `arcbox-fs`).

use arcbox_virtio_core::error::Result;

use crate::session::FuseSession;

/// Trait for handling FUSE requests.
///
/// This trait is implemented by `arcbox-fs::FsServer` to process FUSE
/// filesystem operations. The `VirtioFs` device dispatches requests to
/// this handler.
///
/// # Example
///
/// ```ignore
/// use arcbox_virtio::fs::{FuseRequestHandler, FuseRequest, FuseResponse};
///
/// struct MyFsHandler;
///
/// impl FuseRequestHandler for MyFsHandler {
///     fn handle_request(&self, request: &[u8]) -> arcbox_virtio_core::error::Result<Vec<u8>> {
///         // Process FUSE request and return response
///         Ok(FuseResponse::new(0, vec![]).into_data())
///     }
/// }
/// ```
pub trait FuseRequestHandler: Send + Sync {
    /// Handles a FUSE request and returns the response.
    ///
    /// The request contains the raw FUSE protocol bytes from the guest.
    /// The handler should parse, process, and return the response bytes.
    fn handle_request(&self, request: &[u8]) -> Result<Vec<u8>>;

    /// Called when the FUSE session is initialized.
    ///
    /// This is invoked after the `FUSE_INIT` handshake completes successfully.
    fn on_init(&self, _session: &FuseSession) {}

    /// Called when the FUSE session is destroyed.
    fn on_destroy(&self) {}
}
