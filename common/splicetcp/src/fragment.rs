//! IPv4 fragment reassembly for guest-originated frames (ABX-429).
//!
//! The guest kernel IP-fragments UDP datagrams larger than its link MTU.
//! Downstream consumers (`UdpProxy`, `InboundRelay`, the DHCP/DNS handlers)
//! parse one L4 datagram per frame, so the classifier reassembles fragments
//! back into a single frame before classification.
//!
//! Every field here is guest-controlled input: all arithmetic is checked, all
//! bounds verified before slicing, and both the entry count and per-datagram
//! size are capped so a hostile guest can only waste a bounded buffer.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use arcbox_packet::ethernet::ipv4_header_checksum;

use crate::ethernet::ETH_HEADER_LEN;

/// Maximum IP payload of a reassembled datagram: the 16-bit total-length
/// field (65535) minus the minimal IPv4 header. A fragment reaching beyond
/// this is malformed and drops the whole entry.
const MAX_REASSEMBLED_PAYLOAD: usize = 65_535 - 20;

/// Maximum datagrams under reassembly at once. A benign guest has a handful
/// in flight; the cap bounds a hostile guest to ~2 MiB of buffer.
const MAX_ENTRIES: usize = 32;

/// How long an incomplete datagram may wait for its missing fragments.
const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(3);

/// One datagram's fragments are correlated by this RFC 791 tuple.
type Key = (Ipv4Addr, Ipv4Addr, u8, u16);

struct Entry {
    /// Ethernet + IPv4 header captured from the offset-0 fragment; `None`
    /// until that fragment arrives (fragments may arrive out of order).
    header: Option<Vec<u8>>,
    /// Reassembled IP payload, grown as fragments land.
    payload: Vec<u8>,
    /// Received byte ranges of `payload`, merged and sorted.
    ranges: Vec<(usize, usize)>,
    /// Total IP payload length, known once the MF=0 fragment arrives.
    total_len: Option<usize>,
    first_seen: Instant,
}

impl Entry {
    fn is_complete(&self) -> bool {
        match (self.header.as_ref(), self.total_len) {
            (Some(_), Some(total)) => self.ranges == [(0, total)],
            _ => false,
        }
    }
}

/// Reassembles guest IPv4 fragments into complete Ethernet frames.
pub struct FragmentReassembler {
    entries: HashMap<Key, Entry>,
}

impl FragmentReassembler {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Feeds one fragment (a frame whose MF flag or fragment offset is set).
    ///
    /// Returns the reassembled Ethernet frame — fragment field cleared, total
    /// length and header checksum rewritten — once the last missing fragment
    /// arrives; `None` while the datagram is still incomplete or the fragment
    /// is malformed.
    pub fn push(&mut self, frame: &[u8], now: Instant) -> Option<Vec<u8>> {
        self.evict_expired(now);

        let ip_start = ETH_HEADER_LEN;
        // Callers guarantee a 20-byte IP header; re-verify locally.
        if frame.len() < ip_start + 20 {
            return None;
        }
        let ihl = ((frame[ip_start] & 0x0F) as usize) * 4;
        let ip_total = usize::from(u16::from_be_bytes([
            frame[ip_start + 2],
            frame[ip_start + 3],
        ]));
        if ihl < 20 || ip_total < ihl || frame.len() < ip_start + ip_total {
            tracing::debug!("fragment with inconsistent IP lengths dropped");
            return None;
        }

        let flags_frag = u16::from_be_bytes([frame[ip_start + 6], frame[ip_start + 7]]);
        let more_fragments = flags_frag & 0x2000 != 0;
        let offset = usize::from(flags_frag & 0x1FFF) * 8;
        let fragment = &frame[ip_start + ihl..ip_start + ip_total];
        // Non-final fragment payloads must be 8-byte multiples (RFC 791) or
        // the offsets of the following fragments cannot line up.
        if more_fragments && (fragment.is_empty() || fragment.len() % 8 != 0) {
            tracing::debug!("non-final fragment with unaligned payload dropped");
            return None;
        }

        let end = offset.checked_add(fragment.len())?;
        if end > MAX_REASSEMBLED_PAYLOAD {
            tracing::debug!("fragment beyond the 64 KiB datagram bound; entry dropped");
            self.entries.remove(&key_of(frame));
            return None;
        }

        let key = key_of(frame);
        if !self.entries.contains_key(&key) && self.entries.len() >= MAX_ENTRIES {
            tracing::debug!("fragment reassembly table full; new datagram dropped");
            return None;
        }
        let entry = self.entries.entry(key).or_insert_with(|| Entry {
            header: None,
            payload: Vec::new(),
            ranges: Vec::new(),
            total_len: None,
            first_seen: now,
        });

        if !more_fragments {
            match entry.total_len {
                // Two final fragments disagreeing on the total: malformed.
                Some(total) if total != end => {
                    tracing::debug!("conflicting final fragments; entry dropped");
                    self.entries.remove(&key);
                    return None;
                }
                _ => entry.total_len = Some(end),
            }
        }
        if let Some(total) = entry.total_len {
            if end > total {
                tracing::debug!("fragment beyond the final fragment; entry dropped");
                self.entries.remove(&key);
                return None;
            }
        }
        if offset == 0 && entry.header.is_none() {
            entry.header = Some(frame[..ip_start + ihl].to_vec());
        }

        if entry.payload.len() < end {
            entry.payload.resize(end, 0);
        }
        entry.payload[offset..end].copy_from_slice(fragment);
        merge_range(&mut entry.ranges, offset, end);

        if entry.is_complete() {
            let entry = self.entries.remove(&key)?;
            let ihl = entry.header.as_ref()?.len() - ETH_HEADER_LEN;
            let total = entry.total_len?;
            // The rebuilt total length must fit the 16-bit IP field. A legal
            // sender cannot exceed it, but the offsets/lengths are guest
            // bits: an option-bearing header (ihl > 20) plus a payload
            // crafted right up to MAX_REASSEMBLED_PAYLOAD would overflow.
            if ihl.checked_add(total)? > 65_535 {
                tracing::debug!("reassembled datagram exceeds the IP total-length field; dropped");
                return None;
            }
            return Some(rebuild_frame(&entry));
        }
        None
    }

    fn evict_expired(&mut self, now: Instant) {
        self.entries
            .retain(|_, e| now.duration_since(e.first_seen) < REASSEMBLY_TIMEOUT);
    }
}

fn key_of(frame: &[u8]) -> Key {
    let ip = &frame[ETH_HEADER_LEN..];
    (
        Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]),
        Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]),
        ip[9],
        u16::from_be_bytes([ip[4], ip[5]]),
    )
}

/// Inserts `[start, end)` into the sorted, disjoint range list, merging
/// adjacent and overlapping ranges (overlaps are last-write-wins in the
/// payload buffer, which is safe — a benign guest never overlaps).
fn merge_range(ranges: &mut Vec<(usize, usize)>, start: usize, end: usize) {
    let idx = ranges.partition_point(|&(s, _)| s < start);
    ranges.insert(idx, (start, end));
    let mut merged: Vec<(usize, usize)> = Vec::with_capacity(ranges.len());
    for &(s, e) in ranges.iter() {
        match merged.last_mut() {
            Some(&mut (_, ref mut le)) if s <= *le => *le = (*le).max(e),
            _ => merged.push((s, e)),
        }
    }
    *ranges = merged;
}

/// Builds the reassembled Ethernet frame from a complete entry: the captured
/// header with the fragment field cleared, the total length rewritten, and
/// the header checksum recomputed, followed by the full IP payload.
fn rebuild_frame(entry: &Entry) -> Vec<u8> {
    let header = entry.header.as_ref().expect("complete entry has a header");
    let total = entry.total_len.expect("complete entry has a total");
    let ihl = header.len() - ETH_HEADER_LEN;

    let mut out = Vec::with_capacity(header.len() + total);
    out.extend_from_slice(header);
    out.extend_from_slice(&entry.payload[..total]);

    let ip = &mut out[ETH_HEADER_LEN..];
    // The caller has verified ihl + total ≤ 65535.
    ip[2..4].copy_from_slice(&((ihl + total) as u16).to_be_bytes());
    ip[6..8].copy_from_slice(&[0, 0]);
    ip[10..12].copy_from_slice(&[0, 0]);
    let cksum = ipv4_header_checksum(&ip[..ihl]);
    ip[10..12].copy_from_slice(&cksum.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use arcbox_packet::ethernet::build_udp_ip_ethernet;

    const SRC: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 2);
    const DST: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);

    /// Fragments of a 3000-byte UDP payload at MTU 1500 (3 fragments).
    fn fragments(payload_len: usize) -> Vec<Vec<u8>> {
        let payload: Vec<u8> = (0..payload_len).map(|i| (i % 251) as u8).collect();
        let frames = build_udp_ip_ethernet(SRC, DST, 40000, 9999, &payload, [1; 6], [2; 6], 1500);
        assert!(frames.len() > 1, "test payload must fragment");
        frames
    }

    fn udp_payload(frame: &[u8]) -> &[u8] {
        let ihl = ((frame[ETH_HEADER_LEN] & 0x0F) as usize) * 4;
        &frame[ETH_HEADER_LEN + ihl + 8..]
    }

    fn assert_reassembled(frame: &[u8], payload_len: usize) {
        let ip = &frame[ETH_HEADER_LEN..];
        // Fragment field cleared.
        assert_eq!(u16::from_be_bytes([ip[6], ip[7]]), 0);
        // Total length spans the whole datagram.
        assert_eq!(
            u16::from_be_bytes([ip[2], ip[3]]) as usize,
            20 + 8 + payload_len
        );
        // Header checksum folds to zero.
        let mut sum: u32 = 0;
        for i in (0..20).step_by(2) {
            sum += u32::from(u16::from_be_bytes([ip[i], ip[i + 1]]));
        }
        while sum > 0xFFFF {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        assert_eq!(sum as u16, 0xFFFF);
        // Payload intact.
        let payload = udp_payload(frame);
        assert_eq!(payload.len(), payload_len);
        for (i, &b) in payload.iter().enumerate() {
            assert_eq!(b, (i % 251) as u8, "payload byte {i}");
        }
    }

    #[test]
    fn in_order_fragments_reassemble() {
        let mut r = FragmentReassembler::new();
        let now = Instant::now();
        let frags = fragments(3000);
        let (last, rest) = frags.split_last().unwrap();
        for f in rest {
            assert!(r.push(f, now).is_none());
        }
        let frame = r.push(last, now).expect("last fragment completes");
        assert_reassembled(&frame, 3000);
        assert!(r.entries.is_empty(), "completed entry must be removed");
    }

    #[test]
    fn out_of_order_fragments_reassemble() {
        let mut r = FragmentReassembler::new();
        let now = Instant::now();
        let mut frags = fragments(3000);
        frags.reverse();
        let (last, rest) = frags.split_last().unwrap();
        for f in rest {
            assert!(r.push(f, now).is_none());
        }
        let frame = r.push(last, now).expect("first-sent fragment completes");
        assert_reassembled(&frame, 3000);
    }

    #[test]
    fn interleaved_datagrams_keep_separate() {
        let mut r = FragmentReassembler::new();
        let now = Instant::now();
        let a = fragments(3000);
        let b = fragments(2000);
        // Interleave: a0 b0 a1 b1 a2 — b completes first (2 fragments).
        assert!(r.push(&a[0], now).is_none());
        assert!(r.push(&b[0], now).is_none());
        assert!(r.push(&a[1], now).is_none());
        let done_b = r.push(&b[1], now).expect("b completes");
        assert_reassembled(&done_b, 2000);
        let done_a = r.push(&a[2], now).expect("a completes");
        assert_reassembled(&done_a, 3000);
    }

    #[test]
    fn duplicate_fragment_is_harmless() {
        let mut r = FragmentReassembler::new();
        let now = Instant::now();
        let frags = fragments(3000);
        assert!(r.push(&frags[0], now).is_none());
        assert!(r.push(&frags[0], now).is_none());
        assert!(r.push(&frags[1], now).is_none());
        let frame = r.push(&frags[2], now).expect("completes despite duplicate");
        assert_reassembled(&frame, 3000);
    }

    #[test]
    fn incomplete_datagram_times_out() {
        let mut r = FragmentReassembler::new();
        let now = Instant::now();
        let frags = fragments(3000);
        assert!(r.push(&frags[0], now).is_none());
        assert!(r.push(&frags[1], now).is_none());
        // The final fragment arrives after the timeout: the stale entry is
        // evicted first, so the lone final fragment cannot complete.
        let late = now + REASSEMBLY_TIMEOUT + Duration::from_millis(1);
        assert!(r.push(&frags[2], late).is_none());
        assert_eq!(r.entries.len(), 1, "late fragment starts a fresh entry");
    }

    #[test]
    fn entry_cap_bounds_hostile_guests() {
        let mut r = FragmentReassembler::new();
        let now = Instant::now();
        // MAX_ENTRIES distinct datagrams (distinct IP IDs), first fragment only.
        for _ in 0..MAX_ENTRIES {
            let frags = fragments(3000);
            assert!(r.push(&frags[0], now).is_none());
        }
        assert_eq!(r.entries.len(), MAX_ENTRIES);
        // One more datagram: rejected outright, including its final fragment.
        let extra = fragments(3000);
        for f in &extra {
            assert!(r.push(f, now).is_none());
        }
        assert_eq!(r.entries.len(), MAX_ENTRIES);
    }

    #[test]
    fn fragment_beyond_final_drops_entry() {
        let mut r = FragmentReassembler::new();
        let now = Instant::now();
        let frags = fragments(3000);
        // Final fragment first (fixes the total), then a crafted fragment
        // whose offset+len reaches past it.
        assert!(r.push(&frags[2], now).is_none());
        let mut hostile = frags[1].clone();
        // Set offset to just below the total with a full-size payload.
        let total_payload = 8 + 3000;
        let offset_units = ((total_payload - 8) / 8) as u16;
        hostile[ETH_HEADER_LEN + 6..ETH_HEADER_LEN + 8]
            .copy_from_slice(&(0x2000u16 | offset_units).to_be_bytes());
        assert!(r.push(&hostile, now).is_none());
        assert!(r.entries.is_empty(), "hostile entry must be dropped");
    }

    #[test]
    fn unaligned_non_final_fragment_is_rejected() {
        let mut r = FragmentReassembler::new();
        let now = Instant::now();
        let frags = fragments(3000);
        let mut bad = frags[0].clone();
        // Shrink the IP total length by 1: payload no longer 8-byte aligned.
        let ip_total = u16::from_be_bytes([bad[ETH_HEADER_LEN + 2], bad[ETH_HEADER_LEN + 3]]);
        bad[ETH_HEADER_LEN + 2..ETH_HEADER_LEN + 4].copy_from_slice(&(ip_total - 1).to_be_bytes());
        assert!(r.push(&bad, now).is_none());
        assert!(r.entries.is_empty());
    }

    #[test]
    fn truncated_frame_is_rejected() {
        let mut r = FragmentReassembler::new();
        let now = Instant::now();
        let frags = fragments(3000);
        // Cut the frame shorter than its own IP total length claims.
        let truncated = &frags[0][..frags[0].len() - 100];
        assert!(r.push(truncated, now).is_none());
        assert!(r.entries.is_empty());
    }
}
