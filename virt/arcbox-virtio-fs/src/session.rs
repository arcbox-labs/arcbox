//! FUSE session state — handles the `INIT` handshake and tracks negotiated features.

use std::sync::atomic::{AtomicBool, Ordering};

use arcbox_virtio_core::error::{Result, VirtioError};

use crate::protocol::{
    DEFAULT_MAX_PAGES, DEFAULT_MAX_READAHEAD, DEFAULT_MAX_WRITE, FUSE_ASYNC_READ, FUSE_BIG_WRITES,
    FUSE_KERNEL_MINOR_VERSION, FUSE_KERNEL_VERSION, FUSE_MAP_ALIGNMENT, FUSE_WRITEBACK_CACHE,
};

/// FUSE session state.
///
/// Manages the FUSE protocol session including initialization handshake
/// and feature negotiation.
#[derive(Debug)]
pub struct FuseSession {
    /// Whether `FUSE_INIT` has been received and processed.
    initialized: AtomicBool,
    /// Negotiated protocol major version.
    major: u32,
    /// Negotiated protocol minor version.
    minor: u32,
    /// Negotiated flags.
    flags: u32,
    /// Maximum readahead size.
    max_readahead: u32,
    /// Maximum write size.
    max_write: u32,
    /// Maximum pages per request.
    max_pages: u16,
    /// Whether DAX is enabled for this session.
    dax_enabled: bool,
}

impl FuseSession {
    /// Creates a new FUSE session with default settings.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            initialized: AtomicBool::new(false),
            major: FUSE_KERNEL_VERSION,
            minor: FUSE_KERNEL_MINOR_VERSION,
            flags: FUSE_ASYNC_READ | FUSE_BIG_WRITES | FUSE_WRITEBACK_CACHE | FUSE_MAP_ALIGNMENT,
            max_readahead: DEFAULT_MAX_READAHEAD,
            max_write: DEFAULT_MAX_WRITE,
            max_pages: DEFAULT_MAX_PAGES,
            dax_enabled: false,
        }
    }

    /// Returns whether the session is initialized.
    #[must_use]
    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::Acquire)
    }

    /// Returns the negotiated major version.
    #[must_use]
    pub const fn major(&self) -> u32 {
        self.major
    }

    /// Returns the negotiated minor version.
    #[must_use]
    pub const fn minor(&self) -> u32 {
        self.minor
    }

    /// Returns the negotiated flags.
    #[must_use]
    pub const fn flags(&self) -> u32 {
        self.flags
    }

    /// Returns the maximum readahead size.
    #[must_use]
    pub const fn max_readahead(&self) -> u32 {
        self.max_readahead
    }

    /// Returns the maximum write size.
    #[must_use]
    pub const fn max_write(&self) -> u32 {
        self.max_write
    }

    /// Returns the maximum pages per request.
    #[must_use]
    pub const fn max_pages(&self) -> u16 {
        self.max_pages
    }

    /// Handles `FUSE_INIT` request and returns the response.
    ///
    /// This negotiates the protocol version and features with the guest driver.
    pub fn handle_init(&mut self, request: &[u8]) -> Result<Vec<u8>> {
        // FUSE_INIT request body starts after the 40-byte header.
        // Layout: major(4) + minor(4) + max_readahead(4) + flags(4)
        if request.len() < 56 {
            return Err(VirtioError::DeviceError {
                device: "fs".to_string(),
                message: "FUSE_INIT request too small".to_string(),
            });
        }

        let body = &request[40..];
        let guest_major = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
        let guest_minor = u32::from_le_bytes([body[4], body[5], body[6], body[7]]);
        let guest_max_readahead = u32::from_le_bytes([body[8], body[9], body[10], body[11]]);
        let guest_flags = u32::from_le_bytes([body[12], body[13], body[14], body[15]]);

        tracing::debug!(
            "FUSE_INIT: guest version {}.{}, max_readahead={}, flags={:#x}",
            guest_major,
            guest_minor,
            guest_max_readahead,
            guest_flags
        );

        if guest_major < FUSE_KERNEL_VERSION {
            return Err(VirtioError::DeviceError {
                device: "fs".to_string(),
                message: format!(
                    "FUSE version mismatch: guest {guest_major}.{guest_minor} < required {FUSE_KERNEL_VERSION}.{FUSE_KERNEL_MINOR_VERSION}"
                ),
            });
        }

        // Negotiate features
        self.major = FUSE_KERNEL_VERSION;
        self.minor = FUSE_KERNEL_MINOR_VERSION;
        self.max_readahead = guest_max_readahead.min(DEFAULT_MAX_READAHEAD);
        self.flags &= guest_flags; // Only enable mutually supported flags
        self.dax_enabled = self.flags & FUSE_MAP_ALIGNMENT != 0;
        if self.dax_enabled {
            tracing::info!("FUSE DAX negotiated");
        }

        // Build FUSE_INIT response (80 bytes total).
        // Layout: header(16) + major(4) + minor(4) + max_readahead(4) + flags(4) +
        //         max_background(2) + congestion_threshold(2) + max_write(4) +
        //         time_gran(4) + max_pages(2) + map_alignment(2) + flags2(4) + unused[7](28)
        let mut response = Vec::with_capacity(80);

        let unique = u64::from_le_bytes([
            request[8],
            request[9],
            request[10],
            request[11],
            request[12],
            request[13],
            request[14],
            request[15],
        ]);
        let len = 80u32;
        response.extend_from_slice(&len.to_le_bytes());
        response.extend_from_slice(&0i32.to_le_bytes()); // error = 0
        response.extend_from_slice(&unique.to_le_bytes());

        // FUSE_INIT response body (64 bytes).
        // Offsets below are relative to the start of the body (after the 16-byte header).
        //   0..4  major, 4..8 minor, 8..12 max_readahead, 12..16 flags
        //  16..18 max_background, 18..20 congestion_threshold
        //  20..24 max_write, 24..28 time_gran
        //  28..30 max_pages
        //  30..32 map_alignment  ← u16 page-shift; NOT padding
        //  32..36 flags2 (unused here, zeroed)
        //  36..64 unused[7]
        response.extend_from_slice(&self.major.to_le_bytes());
        response.extend_from_slice(&self.minor.to_le_bytes());
        response.extend_from_slice(&self.max_readahead.to_le_bytes());
        response.extend_from_slice(&self.flags.to_le_bytes());
        response.extend_from_slice(&16u16.to_le_bytes()); // max_background
        response.extend_from_slice(&12u16.to_le_bytes()); // congestion_threshold
        response.extend_from_slice(&self.max_write.to_le_bytes());
        response.extend_from_slice(&1u32.to_le_bytes()); // time_gran (1 ns)
        response.extend_from_slice(&self.max_pages.to_le_bytes());
        // map_alignment: page-size shift advertised to the guest (e.g. 12 = 4 KiB,
        // 14 = 16 KiB).  Must equal the host's actual page size, because every
        // FUSE_SETUPMAPPING turns into an hv_vm_map on the host, which rejects
        // sub-page-aligned requests with HV_ERROR.  On Apple Silicon the host page
        // is 16 KiB (shift=14); on Intel/x86 it is 4 KiB (shift=12).
        // Derive at runtime instead of hardcoding so the binary is correct on both.
        let map_alignment: u16 = if self.dax_enabled {
            // SAFETY: _SC_PAGESIZE is a valid sysconf key; the return value is always
            // positive on supported platforms.  We fall back to 16 KiB (shift=14,
            // the strictest value for current ArcBox targets) on any error.
            let host_page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
            let page_size: u64 = if host_page > 0 {
                host_page as u64
            } else {
                16 * 1024
            };
            u16::try_from(page_size.trailing_zeros()).unwrap_or(14)
        } else {
            0
        };
        response.extend_from_slice(&map_alignment.to_le_bytes());
        response.extend_from_slice(&[0u8; 32]); // flags2(4) + unused[7](28)

        self.initialized.store(true, Ordering::Release);

        tracing::info!(
            "FUSE session initialized: version {}.{}, flags={:#x}, max_write={}",
            self.major,
            self.minor,
            self.flags,
            self.max_write
        );

        Ok(response)
    }

    /// Resets the session state.
    pub fn reset(&mut self) {
        self.initialized.store(false, Ordering::Release);
        self.major = FUSE_KERNEL_VERSION;
        self.minor = FUSE_KERNEL_MINOR_VERSION;
        self.flags = FUSE_ASYNC_READ | FUSE_BIG_WRITES | FUSE_WRITEBACK_CACHE | FUSE_MAP_ALIGNMENT;
        self.max_readahead = DEFAULT_MAX_READAHEAD;
        self.max_write = DEFAULT_MAX_WRITE;
        self.max_pages = DEFAULT_MAX_PAGES;
        self.dax_enabled = false;
    }
}

impl Default for FuseSession {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fuse_session_new() {
        let session = FuseSession::new();
        assert!(!session.is_initialized());
        assert_eq!(session.major(), FUSE_KERNEL_VERSION);
        assert_eq!(session.minor(), FUSE_KERNEL_MINOR_VERSION);
        assert_eq!(session.max_readahead(), DEFAULT_MAX_READAHEAD);
        assert_eq!(session.max_write(), DEFAULT_MAX_WRITE);
        assert_eq!(session.max_pages(), DEFAULT_MAX_PAGES);
    }

    #[test]
    fn test_fuse_session_default() {
        let session = FuseSession::default();
        assert!(!session.is_initialized());
    }

    #[test]
    fn test_fuse_session_reset() {
        let mut session = FuseSession::new();
        session.initialized.store(true, Ordering::SeqCst);

        session.reset();

        assert!(!session.is_initialized());
        assert_eq!(session.major(), FUSE_KERNEL_VERSION);
    }

    #[test]
    fn test_fuse_session_handle_init() {
        let mut session = FuseSession::new();

        // Build a valid FUSE_INIT request: 40-byte header + 16-byte body.
        let mut request = vec![0u8; 56];

        request[0..4].copy_from_slice(&56u32.to_le_bytes()); // length
        request[4..8].copy_from_slice(&26u32.to_le_bytes()); // opcode FUSE_INIT
        request[8..16].copy_from_slice(&1u64.to_le_bytes()); // unique
        request[16..24].copy_from_slice(&0u64.to_le_bytes()); // nodeid
        request[24..28].copy_from_slice(&0u32.to_le_bytes()); // uid
        request[28..32].copy_from_slice(&0u32.to_le_bytes()); // gid
        request[32..36].copy_from_slice(&0u32.to_le_bytes()); // pid
        request[36..40].copy_from_slice(&0u32.to_le_bytes()); // padding

        // FUSE_INIT body
        request[40..44].copy_from_slice(&FUSE_KERNEL_VERSION.to_le_bytes());
        request[44..48].copy_from_slice(&FUSE_KERNEL_MINOR_VERSION.to_le_bytes());
        request[48..52].copy_from_slice(&(64 * 1024u32).to_le_bytes());
        request[52..56].copy_from_slice(&(FUSE_ASYNC_READ | FUSE_BIG_WRITES).to_le_bytes());

        let response = session.handle_init(&request).unwrap();

        assert!(session.is_initialized());
        assert_eq!(response.len(), 80);

        let resp_len = u32::from_le_bytes([response[0], response[1], response[2], response[3]]);
        let resp_error = i32::from_le_bytes([response[4], response[5], response[6], response[7]]);
        let resp_unique = u64::from_le_bytes([
            response[8],
            response[9],
            response[10],
            response[11],
            response[12],
            response[13],
            response[14],
            response[15],
        ]);

        assert_eq!(resp_len, 80);
        assert_eq!(resp_error, 0);
        assert_eq!(resp_unique, 1);

        assert_eq!(session.max_readahead(), 64 * 1024);
    }

    #[test]
    fn test_fuse_session_handle_init_too_small() {
        let mut session = FuseSession::new();
        let request = vec![0u8; 40]; // Too small (need 56)

        let result = session.handle_init(&request);
        assert!(result.is_err());
    }

    #[test]
    fn test_fuse_session_handle_init_old_version() {
        let mut session = FuseSession::new();

        let mut request = vec![0u8; 56];
        request[0..4].copy_from_slice(&56u32.to_le_bytes());
        request[4..8].copy_from_slice(&26u32.to_le_bytes());
        request[8..16].copy_from_slice(&1u64.to_le_bytes());

        // FUSE_INIT body with an old version
        request[40..44].copy_from_slice(&5u32.to_le_bytes());
        request[44..48].copy_from_slice(&0u32.to_le_bytes());
        request[48..52].copy_from_slice(&(64 * 1024u32).to_le_bytes());
        request[52..56].copy_from_slice(&0u32.to_le_bytes());

        let result = session.handle_init(&request);
        assert!(result.is_err());
    }
}
