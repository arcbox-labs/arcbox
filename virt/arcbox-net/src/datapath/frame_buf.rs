//! Owned frame buffer backed by [`PacketPool`] or a heap `Vec<u8>`.
//!
//! [`FrameBuf`] is the datapath's unit of frame ownership. It replaces raw
//! `Vec<u8>` on the hot path with a pool-backed allocation that avoids the
//! system allocator entirely (O(1) atomic CAS vs ~50-100 ns malloc).
//!
//! Code that produces frames from external sources (handshake synthesizer,
//! DNS replies, ARP construction) can still use `FrameBuf::from(vec)` to
//! wrap an existing `Vec<u8>` without copying. The datapath treats both
//! variants uniformly via `Deref<Target = [u8]>`.

use std::ops::Deref;
use std::sync::Arc;

use super::pool::PacketPool;

/// A frame buffer backed by either the [`PacketPool`] or a heap `Vec`.
///
/// - `Pooled`: data lives in a pre-allocated [`PacketPool`] slot. On drop,
///   the slot is returned to the pool (lock-free). This is the fast path.
/// - `Heap`: data lives in a regular `Vec<u8>`. Used for frames that
///   originate outside the pool (handshake replies, manually constructed
///   frames).
pub enum FrameBuf {
    /// Pool-backed frame. Automatically freed on drop.
    Pooled {
        pool: Arc<PacketPool>,
        index: u32,
        len: u32,
    },
    /// Heap-backed frame (fallback for non-pool sources).
    Heap(Vec<u8>),
}

impl FrameBuf {
    /// Allocates a frame from the pool and copies `data` into it.
    ///
    /// Falls back to `Heap` if the pool is exhausted.
    pub fn from_pool(pool: &Arc<PacketPool>, data: &[u8]) -> Self {
        if let Some(mut pkt) = pool.alloc() {
            if pkt.copy_from_slice(data).is_ok() {
                let index = pkt.into_index();
                return Self::Pooled {
                    pool: Arc::clone(pool),
                    index,
                    len: data.len() as u32,
                };
            }
            // copy_from_slice failed (data > MAX_PACKET_SIZE) — fall through.
        }
        // Pool exhausted or frame too large — fall back to heap.
        Self::Heap(data.to_vec())
    }

    /// Returns the frame data length.
    #[inline]
    pub fn len(&self) -> usize {
        match self {
            Self::Pooled { len, .. } => *len as usize,
            Self::Heap(v) => v.len(),
        }
    }

    /// Returns true if the frame is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns true if this frame is pool-backed.
    #[inline]
    pub fn is_pooled(&self) -> bool {
        matches!(self, Self::Pooled { .. })
    }
}

impl Deref for FrameBuf {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &[u8] {
        match self {
            Self::Pooled { pool, index, len } => {
                // SAFETY: The buffer at `index` is allocated (we hold ownership)
                // and no other code has a mutable reference.
                let buf = unsafe { pool.get(*index) };
                &buf.as_full_slice()[..*len as usize]
            }
            Self::Heap(v) => v,
        }
    }
}

impl AsRef<[u8]> for FrameBuf {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self
    }
}

impl Drop for FrameBuf {
    fn drop(&mut self) {
        if let Self::Pooled { pool, index, .. } = self {
            // SAFETY: We own this buffer slot exclusively. Returning it to the
            // pool makes it available for reuse.
            unsafe { pool.free_by_index(*index) };
        }
        // Heap variant: Vec<u8> drops normally.
    }
}

impl From<Vec<u8>> for FrameBuf {
    #[inline]
    fn from(v: Vec<u8>) -> Self {
        Self::Heap(v)
    }
}

impl std::fmt::Debug for FrameBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pooled { index, len, .. } => f
                .debug_struct("FrameBuf::Pooled")
                .field("index", index)
                .field("len", len)
                .finish(),
            Self::Heap(v) => f
                .debug_struct("FrameBuf::Heap")
                .field("len", &v.len())
                .finish(),
        }
    }
}

// Compile-time assertion: FrameBuf must be Send (passed through channels).
// Arc<PacketPool> is Send (PacketPool is Send+Sync), Vec<u8> is Send,
// so FrameBuf derives Send automatically — no unsafe impl needed.
const _: () = {
    const fn assert_send<T: Send>() {}
    assert_send::<FrameBuf>();
};

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pool() -> Arc<PacketPool> {
        Arc::new(PacketPool::new(16).unwrap())
    }

    #[test]
    fn test_from_pool() {
        let pool = make_pool();
        let data = [0xAB; 100];
        let buf = FrameBuf::from_pool(&pool, &data);

        assert!(buf.is_pooled());
        assert_eq!(buf.len(), 100);
        assert_eq!(&buf[..], &data[..]);
        assert_eq!(pool.free_count(), 15);

        drop(buf);
        assert_eq!(pool.free_count(), 16);
    }

    #[test]
    fn test_from_vec() {
        let buf = FrameBuf::from(vec![1, 2, 3]);
        assert!(!buf.is_pooled());
        assert_eq!(buf.len(), 3);
        assert_eq!(&buf[..], &[1, 2, 3]);
    }

    #[test]
    fn test_pool_exhaustion_fallback() {
        let pool = Arc::new(PacketPool::new(1).unwrap());

        let _held = FrameBuf::from_pool(&pool, &[0; 10]);
        assert_eq!(pool.free_count(), 0);

        // Pool exhausted — should fall back to heap.
        let fallback = FrameBuf::from_pool(&pool, &[0xFF; 20]);
        assert!(!fallback.is_pooled());
        assert_eq!(fallback.len(), 20);
    }

    #[test]
    fn test_deref_as_slice() {
        let pool = make_pool();
        let buf = FrameBuf::from_pool(&pool, &[10, 20, 30]);
        let slice: &[u8] = &buf;
        assert_eq!(slice, &[10, 20, 30]);
    }

    #[test]
    fn test_as_ref() {
        let buf = FrameBuf::from(vec![4, 5, 6]);
        let r: &[u8] = buf.as_ref();
        assert_eq!(r, &[4, 5, 6]);
    }

    #[test]
    fn test_empty() {
        let buf = FrameBuf::from(Vec::new());
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn test_send() {
        fn assert_send<T: Send>() {}
        assert_send::<FrameBuf>();
    }

    #[test]
    fn test_concurrent_alloc_drop() {
        let pool = Arc::new(PacketPool::new(64).unwrap());
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let pool = Arc::clone(&pool);
                std::thread::spawn(move || {
                    for i in 0..500 {
                        let data = vec![(i % 256) as u8; 100];
                        let buf = FrameBuf::from_pool(&pool, &data);
                        assert_eq!(buf.len(), 100);
                        assert_eq!(buf[0], (i % 256) as u8);
                        // buf dropped here — returned to pool
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(pool.free_count(), 64);
    }
}
