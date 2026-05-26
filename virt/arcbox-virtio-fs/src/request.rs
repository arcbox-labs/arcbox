//! FUSE request/response wire types — read by the device, parsed by handlers.

/// FUSE request from guest.
#[derive(Debug)]
pub struct FuseRequest<'a> {
    /// Raw request data.
    data: &'a [u8],
}

impl<'a> FuseRequest<'a> {
    /// Creates a new FUSE request from raw bytes.
    #[must_use]
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    /// Returns the raw request data.
    #[must_use]
    pub const fn data(&self) -> &[u8] {
        self.data
    }

    /// Returns the request length.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns true if the request is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Parses the opcode from the request header.
    ///
    /// Returns None if the request is too small.
    #[must_use]
    pub fn opcode(&self) -> Option<u32> {
        if self.data.len() < 8 {
            return None;
        }
        Some(u32::from_le_bytes([
            self.data[4],
            self.data[5],
            self.data[6],
            self.data[7],
        ]))
    }

    /// Parses the unique ID from the request header.
    #[must_use]
    pub fn unique(&self) -> Option<u64> {
        if self.data.len() < 16 {
            return None;
        }
        Some(u64::from_le_bytes([
            self.data[8],
            self.data[9],
            self.data[10],
            self.data[11],
            self.data[12],
            self.data[13],
            self.data[14],
            self.data[15],
        ]))
    }
}

/// FUSE response to guest.
#[derive(Debug)]
pub struct FuseResponse {
    /// Response data.
    data: Vec<u8>,
}

impl FuseResponse {
    /// Creates a new FUSE response.
    #[must_use]
    pub fn new(unique: u64, payload: Vec<u8>) -> Self {
        let len = (16 + payload.len()) as u32;
        let mut data = Vec::with_capacity(len as usize);

        // Response header
        data.extend_from_slice(&len.to_le_bytes());
        data.extend_from_slice(&0i32.to_le_bytes()); // error = 0
        data.extend_from_slice(&unique.to_le_bytes());

        data.extend_from_slice(&payload);

        Self { data }
    }

    /// Creates an error response.
    #[must_use]
    pub fn error(unique: u64, errno: i32) -> Self {
        let len = 16u32;
        let mut data = Vec::with_capacity(len as usize);

        data.extend_from_slice(&len.to_le_bytes());
        data.extend_from_slice(&(-errno).to_le_bytes());
        data.extend_from_slice(&unique.to_le_bytes());

        Self { data }
    }

    /// Returns the response data.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Consumes the response and returns the data.
    #[must_use]
    pub fn into_data(self) -> Vec<u8> {
        self.data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fuse_request_new() {
        let data = vec![0u8; 64];
        let request = FuseRequest::new(&data);
        assert_eq!(request.len(), 64);
        assert!(!request.is_empty());
    }

    #[test]
    fn test_fuse_request_empty() {
        let data = vec![];
        let request = FuseRequest::new(&data);
        assert!(request.is_empty());
    }

    #[test]
    fn test_fuse_request_opcode() {
        let mut data = vec![0u8; 16];
        data[4..8].copy_from_slice(&42u32.to_le_bytes());

        let request = FuseRequest::new(&data);
        assert_eq!(request.opcode(), Some(42));
    }

    #[test]
    fn test_fuse_request_opcode_too_small() {
        let data = vec![0u8; 4];
        let request = FuseRequest::new(&data);
        assert!(request.opcode().is_none());
    }

    #[test]
    fn test_fuse_request_unique() {
        let mut data = vec![0u8; 16];
        data[8..16].copy_from_slice(&12345u64.to_le_bytes());

        let request = FuseRequest::new(&data);
        assert_eq!(request.unique(), Some(12345));
    }

    #[test]
    fn test_fuse_response_new() {
        let response = FuseResponse::new(123, vec![1, 2, 3, 4]);

        let data = response.data();
        assert_eq!(data.len(), 20); // 16 header + 4 payload

        let len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let error = i32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let unique = u64::from_le_bytes([
            data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
        ]);

        assert_eq!(len, 20);
        assert_eq!(error, 0);
        assert_eq!(unique, 123);
        assert_eq!(&data[16..], &[1, 2, 3, 4]);
    }

    #[test]
    fn test_fuse_response_error() {
        let response = FuseResponse::error(456, libc::ENOENT);

        let data = response.data();
        assert_eq!(data.len(), 16);

        let len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let error = i32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let unique = u64::from_le_bytes([
            data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
        ]);

        assert_eq!(len, 16);
        assert_eq!(error, -libc::ENOENT);
        assert_eq!(unique, 456);
    }

    #[test]
    fn test_fuse_response_into_data() {
        let response = FuseResponse::new(1, vec![]);
        let data = response.into_data();
        assert_eq!(data.len(), 16);
    }
}
