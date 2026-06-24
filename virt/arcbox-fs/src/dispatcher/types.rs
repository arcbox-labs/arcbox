use std::mem::size_of;

use crate::fuse::{FuseInHeader, FuseOutHeader};

/// Configuration for the FUSE dispatcher.
#[derive(Debug, Clone)]
pub struct DispatcherConfig {
    /// Entry cache timeout in seconds.
    pub entry_timeout: u64,
    /// Attribute cache timeout in seconds.
    pub attr_timeout: u64,
}

impl Default for DispatcherConfig {
    fn default() -> Self {
        Self {
            entry_timeout: 10,
            attr_timeout: 10,
        }
    }
}

/// Context for a FUSE request.
#[derive(Debug, Clone, Copy)]
pub struct RequestContext {
    /// Unique request ID.
    pub unique: u64,
    /// Node ID (inode).
    pub nodeid: u64,
    /// User ID.
    pub uid: u32,
    /// Group ID.
    pub gid: u32,
    /// Process ID.
    pub pid: u32,
}

impl From<&FuseInHeader> for RequestContext {
    fn from(header: &FuseInHeader) -> Self {
        Self {
            unique: header.unique,
            nodeid: header.nodeid,
            uid: header.uid,
            gid: header.gid,
            pid: header.pid,
        }
    }
}

/// Helper for building FUSE responses.
pub struct ResponseBuilder {
    pub(super) buffer: Vec<u8>,
}

impl ResponseBuilder {
    /// Creates a new response builder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            buffer: Vec::with_capacity(4096),
        }
    }

    /// Writes an error response.
    pub fn write_error(&mut self, unique: u64, errno: i32) {
        if errno != 0 {
            tracing::debug!("FUSE: error response unique={} errno={}", unique, -errno);
        }
        self.buffer.clear();
        let header = FuseOutHeader::error(unique, errno);
        self.write_struct(&header);
    }

    /// Writes a success response with only a header.
    pub fn write_empty(&mut self, unique: u64) {
        self.buffer.clear();
        let header = FuseOutHeader::success(unique, FuseOutHeader::SIZE as u32);
        self.write_struct(&header);
    }

    /// Writes a success response with data.
    pub fn write_data<T: Copy>(&mut self, unique: u64, data: &T) {
        self.buffer.clear();
        let len = (FuseOutHeader::SIZE + size_of::<T>()) as u32;
        let header = FuseOutHeader::success(unique, len);
        self.write_struct(&header);
        self.write_struct(data);
    }

    /// Writes a success response with raw bytes.
    pub fn write_bytes(&mut self, unique: u64, data: &[u8]) {
        self.buffer.clear();
        let len = (FuseOutHeader::SIZE + data.len()) as u32;
        let header = FuseOutHeader::success(unique, len);
        self.write_struct(&header);
        self.buffer.extend_from_slice(data);
    }

    /// Returns the built response.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.buffer
    }

    /// Returns a reference to the buffer.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer
    }

    pub(super) fn write_struct<T: Copy>(&mut self, value: &T) {
        let bytes = unsafe {
            std::slice::from_raw_parts(std::ptr::from_ref::<T>(value) as *const u8, size_of::<T>())
        };
        self.buffer.extend_from_slice(bytes);
    }
}

impl Default for ResponseBuilder {
    fn default() -> Self {
        Self::new()
    }
}
