//! High-performance datapath for network packet processing.
//!
//! This module provides zero-copy packet handling with lock-free data structures
//! optimized for high throughput and low latency.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │                     High-Performance Datapath                 │
//! │                                                               │
//! │  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐   │
//! │  │ Zero-Copy    │    │ Lock-Free    │    │ Performance  │   │
//! │  │ Packet Pool  │ ─→ │ Ring Buffer  │ ─→ │ Statistics   │   │
//! │  └──────────────┘    └──────────────┘    └──────────────┘   │
//! │         ↑                   ↑                   ↑            │
//! │         │                   │                   │            │
//! │    Pre-allocated       SPSC design        Cache-line        │
//! │    buffers             No locks           aligned           │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Performance Targets
//!
//! - Ring buffer throughput: >100M ops/sec
//! - Packet pool allocation: O(1) constant time
//! - Zero memory copies in hot path

pub mod packet;
pub mod pool;
pub mod ring;
pub mod stats;

pub use packet::{PacketMetadata, Protocol, ZeroCopyPacket};
pub use pool::{PacketBuffer, PacketPool};
pub use ring::LockFreeRing;
pub use stats::DatapathStats;

/// Cache line size for padding (64 bytes on most architectures).
pub const CACHE_LINE_SIZE: usize = 64;

/// Default batch size for packet processing.
pub const DEFAULT_BATCH_SIZE: usize = 64;

/// Default ring buffer capacity (must be power of 2).
pub const DEFAULT_RING_CAPACITY: usize = 4096;

/// Default packet pool capacity.
pub const DEFAULT_POOL_CAPACITY: usize = 8192;

/// Maximum packet size (MTU + headers).
pub const MAX_PACKET_SIZE: usize = 65535;

/// Cache line padding to prevent false sharing.
#[repr(C, align(64))]
#[derive(Debug, Default, Clone, Copy)]
pub struct CachePadded<T>(pub T);

impl<T> CachePadded<T> {
    /// Creates a new cache-padded value.
    #[inline]
    pub const fn new(value: T) -> Self {
        Self(value)
    }

    /// Returns a reference to the inner value.
    #[inline]
    pub const fn get(&self) -> &T {
        &self.0
    }

    /// Returns a mutable reference to the inner value.
    #[inline]
    pub fn get_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

/// Software prefetch for upcoming data access.
///
/// This hints to the CPU to load data into cache before it's needed,
/// reducing memory access latency in tight loops.
#[inline(always)]
pub fn prefetch_read<T>(ptr: *const T) {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        // PRFM PLDL1KEEP - prefetch for load, keep in L1 cache
        core::arch::asm!(
            "prfm pldl1keep, [{ptr}]",
            ptr = in(reg) ptr,
            options(nostack, preserves_flags)
        );
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::x86_64::_mm_prefetch(ptr.cast::<i8>(), core::arch::x86_64::_MM_HINT_T0);
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    {
        let _ = ptr;
    }
}

/// Software prefetch for write access.
#[inline(always)]
pub fn prefetch_write<T>(ptr: *mut T) {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        // PRFM PSTL1KEEP - prefetch for store, keep in L1 cache
        core::arch::asm!(
            "prfm pstl1keep, [{ptr}]",
            ptr = in(reg) ptr,
            options(nostack, preserves_flags)
        );
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::x86_64::_mm_prefetch(ptr.cast::<i8>(), core::arch::x86_64::_MM_HINT_T0);
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    {
        let _ = ptr;
    }
}

/// Checks if a value is a power of 2.
#[inline]
pub const fn is_power_of_two(n: usize) -> bool {
    n != 0 && (n & (n - 1)) == 0
}

/// Rounds up to the next power of 2.
#[inline]
pub const fn next_power_of_two(mut n: usize) -> usize {
    if n == 0 {
        return 1;
    }
    n -= 1;
    n |= n >> 1;
    n |= n >> 2;
    n |= n >> 4;
    n |= n >> 8;
    n |= n >> 16;
    n |= n >> 32;
    n + 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_padded_size() {
        assert_eq!(
            std::mem::size_of::<CachePadded<u64>>(),
            CACHE_LINE_SIZE
        );
    }

    #[test]
    fn test_power_of_two() {
        assert!(is_power_of_two(1));
        assert!(is_power_of_two(2));
        assert!(is_power_of_two(4));
        assert!(is_power_of_two(4096));
        assert!(!is_power_of_two(0));
        assert!(!is_power_of_two(3));
        assert!(!is_power_of_two(5));
    }

    #[test]
    fn test_next_power_of_two() {
        assert_eq!(next_power_of_two(0), 1);
        assert_eq!(next_power_of_two(1), 1);
        assert_eq!(next_power_of_two(2), 2);
        assert_eq!(next_power_of_two(3), 4);
        assert_eq!(next_power_of_two(5), 8);
        assert_eq!(next_power_of_two(1000), 1024);
    }
}
