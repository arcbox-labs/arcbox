//! Connection tracking for NAT.
//!
//! This module provides a high-performance connection tracking table
//! using Swiss Tables (hashbrown) for O(1) lookups.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::Instant;

use hashbrown::HashMap;

use crate::datapath::CachePadded;

/// Connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ConnState {
    /// New connection (SYN seen).
    New = 0,
    /// Connection established.
    Established = 1,
    /// FIN seen from one side.
    FinWait = 2,
    /// Connection closing.
    Closing = 3,
    /// Connection timed out.
    TimedOut = 4,
}

impl Default for ConnState {
    fn default() -> Self {
        Self::New
    }
}

/// Connection tracking key (5-tuple).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnTrackKey {
    /// Source IP address.
    pub src_ip: Ipv4Addr,
    /// Destination IP address.
    pub dst_ip: Ipv4Addr,
    /// Source port.
    pub src_port: u16,
    /// Destination port.
    pub dst_port: u16,
    /// Protocol (6 = TCP, 17 = UDP).
    pub protocol: u8,
}

impl ConnTrackKey {
    /// Creates a new connection tracking key.
    #[inline]
    #[must_use]
    pub const fn new(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        protocol: u8,
    ) -> Self {
        Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
        }
    }

    /// Creates a key for the reverse direction.
    #[inline]
    #[must_use]
    pub const fn reverse(&self) -> Self {
        Self {
            src_ip: self.dst_ip,
            dst_ip: self.src_ip,
            src_port: self.dst_port,
            dst_port: self.src_port,
            protocol: self.protocol,
        }
    }

    /// Computes a hash for fast cache lookup.
    #[inline]
    #[must_use]
    pub fn fast_hash(&self) -> u64 {
        // FNV-1a hash
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;

        for byte in self.src_ip.octets() {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(0x0100_0000_01b3);
        }
        for byte in self.dst_ip.octets() {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(0x0100_0000_01b3);
        }
        hash ^= self.src_port as u64;
        hash = hash.wrapping_mul(0x0100_0000_01b3);
        hash ^= self.dst_port as u64;
        hash = hash.wrapping_mul(0x0100_0000_01b3);
        hash ^= self.protocol as u64;
        hash = hash.wrapping_mul(0x0100_0000_01b3);

        hash
    }
}

/// Connection tracking entry.
///
/// Cache-line aligned to prevent false sharing.
#[repr(C, align(64))]
pub struct ConnTrackEntry {
    /// Original source address.
    pub orig_src: SocketAddrV4,
    /// Original destination address.
    pub orig_dst: SocketAddrV4,
    /// NAT'd source address (for outbound).
    pub nat_src: SocketAddrV4,
    /// NAT'd destination address (for inbound DNAT).
    pub nat_dst: SocketAddrV4,
    /// Connection state.
    pub state: ConnState,
    /// Protocol.
    pub protocol: u8,
    /// Flags.
    pub flags: u8,
    /// Last activity timestamp (seconds since epoch).
    pub last_seen: AtomicU32,
    /// Packet counter.
    pub packets: AtomicU64,
    /// Byte counter.
    pub bytes: AtomicU64,
    /// Creation timestamp.
    pub created_at: u32,
}

impl ConnTrackEntry {
    /// Entry flag: SNAT applied.
    pub const FLAG_SNAT: u8 = 1 << 0;
    /// Entry flag: DNAT applied.
    pub const FLAG_DNAT: u8 = 1 << 1;
    /// Entry flag: Reply seen.
    pub const FLAG_REPLY_SEEN: u8 = 1 << 2;

    /// Creates a new connection tracking entry for SNAT.
    #[must_use]
    pub fn new_snat(
        orig_src: SocketAddrV4,
        orig_dst: SocketAddrV4,
        nat_src: SocketAddrV4,
        protocol: u8,
    ) -> Self {
        let now = Instant::now().elapsed().as_secs() as u32;
        Self {
            orig_src,
            orig_dst,
            nat_src,
            nat_dst: orig_dst, // No DNAT
            state: ConnState::New,
            protocol,
            flags: Self::FLAG_SNAT,
            last_seen: AtomicU32::new(now),
            packets: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
            created_at: now,
        }
    }

    /// Updates the last seen timestamp.
    #[inline]
    pub fn touch(&self) {
        let now = Instant::now().elapsed().as_secs() as u32;
        self.last_seen.store(now, Ordering::Relaxed);
    }

    /// Records a packet.
    #[inline]
    pub fn record_packet(&self, bytes: u64) {
        self.packets.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(bytes, Ordering::Relaxed);
        self.touch();
    }

    /// Returns true if the entry has expired.
    #[inline]
    #[must_use]
    pub fn is_expired(&self, timeout_secs: u32) -> bool {
        let now = Instant::now().elapsed().as_secs() as u32;
        let last = self.last_seen.load(Ordering::Relaxed);
        now.saturating_sub(last) > timeout_secs
    }

    /// Returns true if SNAT is applied.
    #[inline]
    #[must_use]
    pub const fn has_snat(&self) -> bool {
        self.flags & Self::FLAG_SNAT != 0
    }

    /// Returns true if DNAT is applied.
    #[inline]
    #[must_use]
    pub const fn has_dnat(&self) -> bool {
        self.flags & Self::FLAG_DNAT != 0
    }

    /// Returns true if a reply has been seen.
    #[inline]
    #[must_use]
    pub fn reply_seen(&self) -> bool {
        self.flags & Self::FLAG_REPLY_SEEN != 0
    }

    /// Marks that a reply has been seen.
    #[inline]
    pub fn mark_reply_seen(&mut self) {
        self.flags |= Self::FLAG_REPLY_SEEN;
        self.state = ConnState::Established;
    }
}

impl std::fmt::Debug for ConnTrackEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnTrackEntry")
            .field("orig_src", &self.orig_src)
            .field("orig_dst", &self.orig_dst)
            .field("nat_src", &self.nat_src)
            .field("nat_dst", &self.nat_dst)
            .field("state", &self.state)
            .field("protocol", &self.protocol)
            .field("packets", &self.packets.load(Ordering::Relaxed))
            .field("bytes", &self.bytes.load(Ordering::Relaxed))
            .finish()
    }
}

/// Fast path cache entry.
///
/// Stores recently used connections for O(1) lookup by hash.
#[derive(Debug)]
pub struct FastCacheEntry {
    /// Hash of the key.
    pub key_hash: u64,
    /// The connection tracking key.
    pub key: ConnTrackKey,
    /// Pointer to the full entry.
    pub entry_ptr: *const ConnTrackEntry,
    /// Hit count.
    pub hits: u32,
}

// Safety: FastCacheEntry is only accessed with proper synchronization.
unsafe impl Send for FastCacheEntry {}
unsafe impl Sync for FastCacheEntry {}

impl FastCacheEntry {
    /// Creates a new cache entry.
    #[must_use]
    pub fn new(key: ConnTrackKey, entry_ptr: *const ConnTrackEntry) -> Self {
        Self {
            key_hash: key.fast_hash(),
            key,
            entry_ptr,
            hits: 0,
        }
    }
}

/// Port allocator for NAT.
pub struct PortAllocator {
    /// Current port.
    current: AtomicU32,
    /// Port range start.
    start: u16,
    /// Port range end.
    end: u16,
}

impl PortAllocator {
    /// Creates a new port allocator.
    #[must_use]
    pub fn new(start: u16, end: u16) -> Self {
        Self {
            current: AtomicU32::new(start as u32),
            start,
            end,
        }
    }

    /// Allocates the next available port.
    #[inline]
    pub fn allocate(&self) -> u16 {
        let range = (self.end - self.start + 1) as u32;
        let port = self.current.fetch_add(1, Ordering::Relaxed);
        self.start + ((port - self.start as u32) % range) as u16
    }
}

/// High-performance connection tracking table.
pub struct ConnTrackTable {
    /// Connection entries (outbound key -> entry).
    entries: HashMap<ConnTrackKey, Box<ConnTrackEntry>>,
    /// Reverse lookup (NAT'd key -> original key).
    reverse: HashMap<ConnTrackKey, ConnTrackKey>,
    /// Fast path cache.
    fast_cache: Vec<Option<FastCacheEntry>>,
    /// Fast cache mask.
    fast_cache_mask: usize,
    /// Port allocator.
    port_alloc: PortAllocator,
    /// External IP for SNAT.
    external_ip: Ipv4Addr,
    /// Connection timeout.
    timeout_secs: u32,
    /// Statistics.
    stats: ConnTrackStats,
}

/// Connection tracking statistics.
#[derive(Debug, Default)]
pub struct ConnTrackStats {
    /// Total lookups.
    pub lookups: CachePadded<AtomicU64>,
    /// Fast path hits.
    pub fast_hits: CachePadded<AtomicU64>,
    /// Slow path lookups.
    pub slow_lookups: CachePadded<AtomicU64>,
    /// Entries created.
    pub created: CachePadded<AtomicU64>,
    /// Entries expired.
    pub expired: CachePadded<AtomicU64>,
}

impl ConnTrackTable {
    /// Creates a new connection tracking table.
    #[must_use]
    pub fn new(
        external_ip: Ipv4Addr,
        port_start: u16,
        port_end: u16,
        fast_cache_size: usize,
        timeout_secs: u32,
    ) -> Self {
        let fast_cache_size = fast_cache_size.next_power_of_two();
        let fast_cache = (0..fast_cache_size).map(|_| None).collect();

        Self {
            entries: HashMap::new(),
            reverse: HashMap::new(),
            fast_cache,
            fast_cache_mask: fast_cache_size - 1,
            port_alloc: PortAllocator::new(port_start, port_end),
            external_ip,
            timeout_secs,
            stats: ConnTrackStats::default(),
        }
    }

    /// Looks up a connection by key.
    ///
    /// Returns the entry if found.
    pub fn lookup(&mut self, key: &ConnTrackKey) -> Option<&ConnTrackEntry> {
        self.stats.lookups.0.fetch_add(1, Ordering::Relaxed);

        // Try fast path first
        let hash = key.fast_hash();
        let cache_idx = (hash as usize) & self.fast_cache_mask;

        if let Some(ref cache_entry) = self.fast_cache[cache_idx] {
            if cache_entry.key_hash == hash && cache_entry.key == *key {
                self.stats.fast_hits.0.fetch_add(1, Ordering::Relaxed);
                // Safety: The pointer is valid as long as the entry exists.
                return Some(unsafe { &*cache_entry.entry_ptr });
            }
        }

        // Slow path: lookup in hash table
        self.stats.slow_lookups.0.fetch_add(1, Ordering::Relaxed);

        if let Some(entry) = self.entries.get(key) {
            // Update fast cache
            let entry_ptr = entry.as_ref() as *const ConnTrackEntry;
            self.fast_cache[cache_idx] = Some(FastCacheEntry::new(*key, entry_ptr));
            return Some(entry);
        }

        None
    }

    /// Looks up a connection by NAT'd address (reverse lookup).
    pub fn lookup_reverse(&mut self, nat_key: &ConnTrackKey) -> Option<&ConnTrackEntry> {
        // Clone the key to avoid borrow conflict with lookup().
        let orig_key = self.reverse.get(nat_key).cloned()?;
        self.lookup(&orig_key)
    }

    /// Creates or gets an existing connection entry.
    ///
    /// If the connection doesn't exist, creates a new SNAT entry.
    pub fn get_or_create(&mut self, key: ConnTrackKey) -> &ConnTrackEntry {
        // Check if exists
        if self.entries.contains_key(&key) {
            return self.lookup(&key).unwrap();
        }

        // Create new entry
        let nat_port = self.port_alloc.allocate();
        let nat_src = SocketAddrV4::new(self.external_ip, nat_port);

        let entry = Box::new(ConnTrackEntry::new_snat(
            SocketAddrV4::new(key.src_ip, key.src_port),
            SocketAddrV4::new(key.dst_ip, key.dst_port),
            nat_src,
            key.protocol,
        ));

        // Create reverse lookup key
        let reverse_key = ConnTrackKey::new(
            key.dst_ip,
            self.external_ip,
            key.dst_port,
            nat_port,
            key.protocol,
        );

        self.reverse.insert(reverse_key, key);
        self.entries.insert(key, entry);
        self.stats.created.0.fetch_add(1, Ordering::Relaxed);

        // Update fast cache
        let entry_ref = self.entries.get(&key).unwrap();
        let entry_ptr = entry_ref.as_ref() as *const ConnTrackEntry;
        let hash = key.fast_hash();
        let cache_idx = (hash as usize) & self.fast_cache_mask;
        self.fast_cache[cache_idx] = Some(FastCacheEntry::new(key, entry_ptr));

        entry_ref
    }

    /// Removes expired entries.
    pub fn expire_old(&mut self) -> usize {
        let timeout = self.timeout_secs;
        let expired_keys: Vec<ConnTrackKey> = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.is_expired(timeout))
            .map(|(key, _)| *key)
            .collect();

        let count = expired_keys.len();

        for key in expired_keys {
            self.remove(&key);
        }

        self.stats.expired.0.fetch_add(count as u64, Ordering::Relaxed);
        count
    }

    /// Removes a connection entry.
    pub fn remove(&mut self, key: &ConnTrackKey) {
        if let Some(entry) = self.entries.remove(key) {
            // Remove reverse lookup
            let reverse_key = ConnTrackKey::new(
                key.dst_ip,
                self.external_ip,
                key.dst_port,
                entry.nat_src.port(),
                key.protocol,
            );
            self.reverse.remove(&reverse_key);

            // Invalidate fast cache
            let hash = key.fast_hash();
            let cache_idx = (hash as usize) & self.fast_cache_mask;
            if let Some(ref cache_entry) = self.fast_cache[cache_idx] {
                if cache_entry.key == *key {
                    self.fast_cache[cache_idx] = None;
                }
            }
        }
    }

    /// Returns the number of tracked connections.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true if there are no tracked connections.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns statistics.
    #[must_use]
    pub fn stats(&self) -> &ConnTrackStats {
        &self.stats
    }

    /// Clears all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.reverse.clear();
        for entry in &mut self.fast_cache {
            *entry = None;
        }
    }
}

impl std::fmt::Debug for ConnTrackTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnTrackTable")
            .field("entries", &self.entries.len())
            .field("external_ip", &self.external_ip)
            .field("timeout_secs", &self.timeout_secs)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conntrack_key() {
        let key = ConnTrackKey::new(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(8, 8, 8, 8),
            12345,
            80,
            6,
        );

        let reverse = key.reverse();
        assert_eq!(reverse.src_ip, Ipv4Addr::new(8, 8, 8, 8));
        assert_eq!(reverse.dst_ip, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(reverse.src_port, 80);
        assert_eq!(reverse.dst_port, 12345);
    }

    #[test]
    fn test_conntrack_entry() {
        let entry = ConnTrackEntry::new_snat(
            SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 12345),
            SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 80),
            SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 54321),
            6,
        );

        assert!(entry.has_snat());
        assert!(!entry.has_dnat());
        assert_eq!(entry.state, ConnState::New);
    }

    #[test]
    fn test_conntrack_table_create() {
        let mut table = ConnTrackTable::new(
            Ipv4Addr::new(10, 0, 0, 1),
            49152,
            65535,
            256,
            300,
        );

        let key = ConnTrackKey::new(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(8, 8, 8, 8),
            12345,
            80,
            6,
        );

        let entry = table.get_or_create(key);
        assert_eq!(entry.nat_src.ip(), &Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn test_conntrack_table_lookup() {
        let mut table = ConnTrackTable::new(
            Ipv4Addr::new(10, 0, 0, 1),
            49152,
            65535,
            256,
            300,
        );

        let key = ConnTrackKey::new(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(8, 8, 8, 8),
            12345,
            80,
            6,
        );

        // Create entry
        let _ = table.get_or_create(key);

        // Lookup should succeed
        assert!(table.lookup(&key).is_some());

        // Lookup non-existent should fail
        let other_key = ConnTrackKey::new(
            Ipv4Addr::new(192, 168, 1, 200),
            Ipv4Addr::new(8, 8, 8, 8),
            12346,
            80,
            6,
        );
        assert!(table.lookup(&other_key).is_none());
    }

    #[test]
    fn test_port_allocator() {
        let alloc = PortAllocator::new(1000, 1010);

        let ports: Vec<u16> = (0..20).map(|_| alloc.allocate()).collect();

        // Should cycle through the range
        for i in 0..11 {
            assert_eq!(ports[i], 1000 + (i as u16));
        }
        // Then wrap around
        assert_eq!(ports[11], 1000);
    }
}
