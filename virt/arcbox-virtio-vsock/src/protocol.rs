//! Vsock wire protocol — `VsockOp` enum and 44-byte packet header.

use crate::addr::VsockAddr;

/// Vsock operation types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum VsockOp {
    /// Invalid operation.
    Invalid = 0,
    /// Request connection.
    Request = 1,
    /// Connection response.
    Response = 2,
    /// Reset connection.
    Rst = 3,
    /// Shutdown connection.
    Shutdown = 4,
    /// Data transfer.
    Rw = 5,
    /// Credit update.
    CreditUpdate = 6,
    /// Credit request.
    CreditRequest = 7,
}

impl VsockOp {
    /// Converts from u16.
    #[must_use]
    pub const fn from_u16(val: u16) -> Option<Self> {
        match val {
            0 => Some(Self::Invalid),
            1 => Some(Self::Request),
            2 => Some(Self::Response),
            3 => Some(Self::Rst),
            4 => Some(Self::Shutdown),
            5 => Some(Self::Rw),
            6 => Some(Self::CreditUpdate),
            7 => Some(Self::CreditRequest),
            _ => None,
        }
    }
}

/// Vsock packet header.
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct VsockHeader {
    /// Source CID.
    pub src_cid: u64,
    /// Destination CID.
    pub dst_cid: u64,
    /// Source port.
    pub src_port: u32,
    /// Destination port.
    pub dst_port: u32,
    /// Payload length.
    pub len: u32,
    /// Socket type (stream = 1).
    pub socket_type: u16,
    /// Operation.
    pub op: u16,
    /// Flags.
    pub flags: u32,
    /// Buffer allocation.
    pub buf_alloc: u32,
    /// Forward count.
    pub fwd_cnt: u32,
}

impl VsockHeader {
    /// Header size in bytes.
    ///
    /// The VirtIO vsock spec defines the header as exactly 44 bytes (packed).
    /// We cannot use `mem::size_of::<Self>()` because Rust adds trailing padding
    /// to satisfy the struct's 8-byte alignment (from u64 fields), yielding 48.
    /// The guest kernel sends and expects exactly 44 bytes per header.
    pub const SIZE: usize = 44;

    /// Creates a new header.
    #[must_use]
    pub const fn new(src: VsockAddr, dst: VsockAddr, op: VsockOp) -> Self {
        Self {
            src_cid: src.cid,
            dst_cid: dst.cid,
            src_port: src.port,
            dst_port: dst.port,
            len: 0,
            socket_type: 1, // SOCK_STREAM
            op: op as u16,
            flags: 0,
            buf_alloc: 64 * 1024,
            fwd_cnt: 0,
        }
    }

    /// Returns the operation type.
    #[must_use]
    pub const fn operation(&self) -> Option<VsockOp> {
        VsockOp::from_u16(self.op)
    }

    /// Parses a vsock header from a byte slice.
    ///
    /// Returns `None` if the slice is too short.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::SIZE {
            return None;
        }
        Some(Self {
            src_cid: u64::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]),
            dst_cid: u64::from_le_bytes([
                bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14],
                bytes[15],
            ]),
            src_port: u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]),
            dst_port: u32::from_le_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]),
            len: u32::from_le_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]),
            socket_type: u16::from_le_bytes([bytes[28], bytes[29]]),
            op: u16::from_le_bytes([bytes[30], bytes[31]]),
            flags: u32::from_le_bytes([bytes[32], bytes[33], bytes[34], bytes[35]]),
            buf_alloc: u32::from_le_bytes([bytes[36], bytes[37], bytes[38], bytes[39]]),
            fwd_cnt: u32::from_le_bytes([bytes[40], bytes[41], bytes[42], bytes[43]]),
        })
    }

    /// Serializes the header to a byte array.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        // Copy packed fields to locals to avoid unaligned reference UB.
        let src_cid = self.src_cid;
        let dst_cid = self.dst_cid;
        let src_port = self.src_port;
        let dst_port = self.dst_port;
        let len = self.len;
        let socket_type = self.socket_type;
        let op = self.op;
        let flags = self.flags;
        let buf_alloc = self.buf_alloc;
        let fwd_cnt = self.fwd_cnt;

        buf[0..8].copy_from_slice(&src_cid.to_le_bytes());
        buf[8..16].copy_from_slice(&dst_cid.to_le_bytes());
        buf[16..20].copy_from_slice(&src_port.to_le_bytes());
        buf[20..24].copy_from_slice(&dst_port.to_le_bytes());
        buf[24..28].copy_from_slice(&len.to_le_bytes());
        buf[28..30].copy_from_slice(&socket_type.to_le_bytes());
        buf[30..32].copy_from_slice(&op.to_le_bytes());
        buf[32..36].copy_from_slice(&flags.to_le_bytes());
        buf[36..40].copy_from_slice(&buf_alloc.to_le_bytes());
        buf[40..44].copy_from_slice(&fwd_cnt.to_le_bytes());
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vsock_op_from_u16() {
        assert_eq!(VsockOp::from_u16(0), Some(VsockOp::Invalid));
        assert_eq!(VsockOp::from_u16(1), Some(VsockOp::Request));
        assert_eq!(VsockOp::from_u16(5), Some(VsockOp::Rw));
        assert_eq!(VsockOp::from_u16(100), None);
    }

    #[test]
    fn test_vsock_header() {
        let src = VsockAddr::new(3, 1000);
        let dst = VsockAddr::new(2, 80);
        let header = VsockHeader::new(src, dst, VsockOp::Request);

        let src_cid = header.src_cid;
        let dst_cid = header.dst_cid;
        let src_port = header.src_port;
        let dst_port = header.dst_port;

        assert_eq!(src_cid, 3);
        assert_eq!(dst_cid, 2);
        assert_eq!(src_port, 1000);
        assert_eq!(dst_port, 80);
        assert_eq!(header.operation(), Some(VsockOp::Request));
    }

    #[test]
    fn test_vsock_header_size() {
        assert_eq!(VsockHeader::SIZE, 44);
    }

    #[test]
    fn test_vsock_header_roundtrip() {
        let src = VsockAddr::new(3, 1000);
        let dst = VsockAddr::new(2, 80);
        let original = VsockHeader::new(src, dst, VsockOp::Request);

        let bytes = original.to_bytes();
        assert_eq!(bytes.len(), VsockHeader::SIZE);

        let parsed = VsockHeader::from_bytes(&bytes).unwrap();
        let p_src_cid = parsed.src_cid;
        let p_dst_cid = parsed.dst_cid;
        let p_src_port = parsed.src_port;
        let p_dst_port = parsed.dst_port;
        let p_socket_type = parsed.socket_type;
        assert_eq!(p_src_cid, 3);
        assert_eq!(p_dst_cid, 2);
        assert_eq!(p_src_port, 1000);
        assert_eq!(p_dst_port, 80);
        assert_eq!(parsed.operation(), Some(VsockOp::Request));
        assert_eq!(p_socket_type, 1); // SOCK_STREAM
    }

    #[test]
    fn test_vsock_header_from_bytes_too_short() {
        let short = [0u8; 20];
        assert!(VsockHeader::from_bytes(&short).is_none());
    }

    #[test]
    fn test_vsock_header_to_bytes_all_fields() {
        let mut header = VsockHeader::new(
            VsockAddr::new(0xAABB, 0x1234),
            VsockAddr::new(0xCCDD, 0x5678),
            VsockOp::Rw,
        );
        header.len = 256;
        header.flags = 0x42;
        header.buf_alloc = 32768;
        header.fwd_cnt = 100;

        let bytes = header.to_bytes();
        let parsed = VsockHeader::from_bytes(&bytes).unwrap();

        let p_src_cid = parsed.src_cid;
        let p_dst_cid = parsed.dst_cid;
        let p_src_port = parsed.src_port;
        let p_dst_port = parsed.dst_port;
        let p_len = parsed.len;
        let p_op = parsed.op;
        let p_flags = parsed.flags;
        let p_buf_alloc = parsed.buf_alloc;
        let p_fwd_cnt = parsed.fwd_cnt;
        assert_eq!(p_src_cid, 0xAABB);
        assert_eq!(p_dst_cid, 0xCCDD);
        assert_eq!(p_src_port, 0x1234);
        assert_eq!(p_dst_port, 0x5678);
        assert_eq!(p_len, 256);
        assert_eq!(p_op, VsockOp::Rw as u16);
        assert_eq!(p_flags, 0x42);
        assert_eq!(p_buf_alloc, 32768);
        assert_eq!(p_fwd_cnt, 100);
    }

    #[test]
    fn test_vsock_header_size_is_44() {
        assert_eq!(VsockHeader::SIZE, 44);
        let hdr = VsockHeader::new(
            VsockAddr::host(50000),
            VsockAddr::new(3, 1024),
            VsockOp::Request,
        );
        let bytes = hdr.to_bytes();
        assert_eq!(bytes.len(), 44);

        let parsed = VsockHeader::from_bytes(&bytes).unwrap();
        assert_eq!({ parsed.src_cid }, 2);
        assert_eq!({ parsed.dst_cid }, 3);
        assert_eq!({ parsed.src_port }, 50000);
        assert_eq!({ parsed.dst_port }, 1024);
        assert_eq!({ parsed.op }, VsockOp::Request as u16);
        assert_eq!({ parsed.socket_type }, 1);
        assert_eq!({ parsed.buf_alloc }, 64 * 1024);
    }
}
