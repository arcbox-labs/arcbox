//! High-performance checksum calculation.
//!
//! This module provides optimized checksum calculation routines for
//! IP and TCP/UDP headers, including incremental updates for NAT.

/// Folds a 32-bit sum into a 16-bit checksum.
#[allow(clippy::inline_always)] // hot path: called in every packet's checksum update, must inline to avoid call overhead
#[inline(always)]
pub fn checksum_fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

/// Length at which SIMD `checksum_add` is used. Short headers stay scalar
/// so setup cost does not dominate.
const SIMD_THRESHOLD: usize = 64;

/// Calculates the ones' complement sum of 16-bit words.
///
/// This is the core operation for IP/TCP/UDP checksums. Buffers of
/// [`SIMD_THRESHOLD`] bytes or more use the architecture SIMD path when
/// available (NEON / SSSE3); shorter buffers stay on the scalar loop.
#[inline]
pub fn checksum_add(data: &[u8]) -> u32 {
    if data.len() >= SIMD_THRESHOLD {
        checksum_add_fast(data)
    } else {
        checksum_add_scalar(data)
    }
}

/// Scalar ones' complement sum (always available; used for short buffers
/// and as the SIMD fallback).
#[inline]
pub fn checksum_add_scalar(data: &[u8]) -> u32 {
    let mut sum: u32 = 0;
    let mut i = 0;

    while i + 1 < data.len() {
        let word = u16::from_be_bytes([data[i], data[i + 1]]);
        sum = sum.wrapping_add(word as u32);
        i += 2;
    }

    if i < data.len() {
        sum = sum.wrapping_add((data[i] as u32) << 8);
    }

    sum
}

/// Calculates Internet checksum over data.
#[inline]
pub fn checksum(data: &[u8]) -> u16 {
    checksum_fold(checksum_add(data))
}

/// Incremental checksum update (RFC 1624).
///
/// When a 16-bit value changes from `old` to `new`, this function
/// efficiently updates an existing checksum without recalculating
/// the entire packet.
///
/// Formula: ~C' = ~C + ~m + m'
/// Where C is old checksum, m is old value, m' is new value.
#[allow(clippy::inline_always)] // hot path: called per NAT field update on every translated packet
#[inline(always)]
pub fn incremental_checksum_update(old_checksum: u16, old_value: u16, new_value: u16) -> u16 {
    // ~C + ~m + m'
    let sum = (!old_checksum as u32)
        .wrapping_add(!old_value as u32)
        .wrapping_add(new_value as u32);

    // Fold and complement
    checksum_fold(sum)
}

/// Updates checksum for a 32-bit (4-byte) field change.
///
/// Useful for IP address changes in NAT.
#[inline]
pub fn incremental_checksum_update_32(old_checksum: u16, old_value: u32, new_value: u32) -> u16 {
    let old_hi = (old_value >> 16) as u16;
    let old_lo = old_value as u16;
    let new_hi = (new_value >> 16) as u16;
    let new_lo = new_value as u16;

    // Update for high word
    let checksum = incremental_checksum_update(old_checksum, old_hi, new_hi);
    // Update for low word
    incremental_checksum_update(checksum, old_lo, new_lo)
}

/// Updates checksum for IP address change.
#[inline]
pub fn update_checksum_for_ip(old_checksum: u16, old_ip: [u8; 4], new_ip: [u8; 4]) -> u16 {
    let old_val = u32::from_be_bytes(old_ip);
    let new_val = u32::from_be_bytes(new_ip);
    incremental_checksum_update_32(old_checksum, old_val, new_val)
}

/// Updates checksum for port change.
#[inline]
pub fn update_checksum_for_port(old_checksum: u16, old_port: u16, new_port: u16) -> u16 {
    incremental_checksum_update(old_checksum, old_port, new_port)
}

/// Updates checksum for both IP and port change (common in NAT).
#[inline]
pub fn update_checksum_for_nat(
    old_checksum: u16,
    old_ip: [u8; 4],
    old_port: u16,
    new_ip: [u8; 4],
    new_port: u16,
) -> u16 {
    let checksum = update_checksum_for_ip(old_checksum, old_ip, new_ip);
    update_checksum_for_port(checksum, old_port, new_port)
}

/// Calculates IPv4 header checksum.
///
/// The header checksum covers only the IP header (not payload).
/// Assumes checksum field is zeroed before calculation.
#[inline]
pub fn ipv4_header_checksum(header: &[u8]) -> u16 {
    debug_assert!(header.len() >= 20, "IPv4 header too short");
    checksum(header)
}

/// Calculates TCP checksum including pseudo-header.
///
/// TCP checksum covers: pseudo-header + TCP header + data.
#[inline]
pub fn tcp_checksum(src_ip: [u8; 4], dst_ip: [u8; 4], tcp_segment: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Pseudo-header
    sum = sum.wrapping_add(u16::from_be_bytes([src_ip[0], src_ip[1]]) as u32);
    sum = sum.wrapping_add(u16::from_be_bytes([src_ip[2], src_ip[3]]) as u32);
    sum = sum.wrapping_add(u16::from_be_bytes([dst_ip[0], dst_ip[1]]) as u32);
    sum = sum.wrapping_add(u16::from_be_bytes([dst_ip[2], dst_ip[3]]) as u32);
    sum = sum.wrapping_add(6u32); // Protocol (TCP = 6)
    sum = sum.wrapping_add(tcp_segment.len() as u32);

    // TCP segment
    sum = sum.wrapping_add(checksum_add(tcp_segment));

    checksum_fold(sum)
}

/// Calculates UDP checksum including pseudo-header.
///
/// UDP checksum covers: pseudo-header + UDP header + data.
#[inline]
pub fn udp_checksum(src_ip: [u8; 4], dst_ip: [u8; 4], udp_datagram: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Pseudo-header
    sum = sum.wrapping_add(u16::from_be_bytes([src_ip[0], src_ip[1]]) as u32);
    sum = sum.wrapping_add(u16::from_be_bytes([src_ip[2], src_ip[3]]) as u32);
    sum = sum.wrapping_add(u16::from_be_bytes([dst_ip[0], dst_ip[1]]) as u32);
    sum = sum.wrapping_add(u16::from_be_bytes([dst_ip[2], dst_ip[3]]) as u32);
    sum = sum.wrapping_add(17u32); // Protocol (UDP = 17)
    sum = sum.wrapping_add(udp_datagram.len() as u32);

    // UDP datagram
    sum = sum.wrapping_add(checksum_add(udp_datagram));

    let result = checksum_fold(sum);
    // UDP uses 0xFFFF for zero checksum
    if result == 0 { 0xFFFF } else { result }
}

/// Ones' complement sum via the fastest available path for this host.
#[inline]
fn checksum_add_fast(data: &[u8]) -> u32 {
    #[cfg(target_arch = "aarch64")]
    {
        // SAFETY: NEON is mandatory on AArch64.
        unsafe { checksum_add_neon(data) }
    }
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("ssse3") {
            // SAFETY: SSSE3 just verified.
            unsafe { checksum_add_ssse3(data) }
        } else {
            checksum_add_scalar(data)
        }
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    {
        checksum_add_scalar(data)
    }
}

/// SIMD ones' complement sum for ARM64 NEON (16 bytes/iter, BE halfwords).
///
/// # Safety
/// Requires NEON (`#[target_feature(enable = "neon")]`). Always true on AArch64.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn checksum_add_neon(data: &[u8]) -> u32 {
    use std::arch::aarch64::*;

    // SAFETY: NEON available; loads stay within `data`.
    unsafe {
        let mut sum = vdupq_n_u32(0);
        let (chunks, remainder) = data.as_chunks::<16>();

        for chunk in chunks {
            let bytes = vld1q_u8(chunk.as_ptr());
            // Network order is BE; swap adjacent bytes on LE host.
            let swapped = vrev16q_u8(bytes);
            let words = vreinterpretq_u16_u8(swapped);
            sum = vpadalq_u16(sum, words);
        }

        let mut scalar_sum = vaddvq_u32(sum);
        let mut i = 0;
        while i + 1 < remainder.len() {
            let word = u16::from_be_bytes([remainder[i], remainder[i + 1]]);
            scalar_sum = scalar_sum.wrapping_add(word as u32);
            i += 2;
        }
        if i < remainder.len() {
            scalar_sum = scalar_sum.wrapping_add((remainder[i] as u32) << 8);
        }
        scalar_sum
    }
}

/// SIMD ones' complement sum for x86_64 SSSE3.
///
/// # Safety
/// Requires SSSE3 (`pshufb`).
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "ssse3")]
unsafe fn checksum_add_ssse3(data: &[u8]) -> u32 {
    use std::arch::x86_64::*;

    // SAFETY: SSSE3 available; unaligned loads within `data`.
    unsafe {
        let mut sum_lo = _mm_setzero_si128();
        let mut sum_hi = _mm_setzero_si128();
        let swap_mask = _mm_setr_epi8(1, 0, 3, 2, 5, 4, 7, 6, 9, 8, 11, 10, 13, 12, 15, 14);

        let (chunks, remainder) = data.as_chunks::<16>();

        for chunk in chunks {
            let bytes = _mm_loadu_si128(chunk.as_ptr().cast());
            let swapped = _mm_shuffle_epi8(bytes, swap_mask);
            let zero = _mm_setzero_si128();
            let words_lo = _mm_unpacklo_epi16(swapped, zero);
            let words_hi = _mm_unpackhi_epi16(swapped, zero);
            sum_lo = _mm_add_epi32(sum_lo, words_lo);
            sum_hi = _mm_add_epi32(sum_hi, words_hi);
        }

        let sum = _mm_add_epi32(sum_lo, sum_hi);
        let hadd1 = _mm_hadd_epi32(sum, sum);
        let hadd2 = _mm_hadd_epi32(hadd1, hadd1);
        let mut scalar_sum = _mm_cvtsi128_si32(hadd2) as u32;

        let mut i = 0;
        while i + 1 < remainder.len() {
            let word = u16::from_be_bytes([remainder[i], remainder[i + 1]]);
            scalar_sum = scalar_sum.wrapping_add(word as u32);
            i += 2;
        }
        if i < remainder.len() {
            scalar_sum = scalar_sum.wrapping_add((remainder[i] as u32) << 8);
        }
        scalar_sum
    }
}

/// Full Internet checksum using the SIMD path when available.
///
/// Prefer [`checksum`] for call sites: it already selects SIMD for long
/// buffers. This entry point forces the fast path for benches and tests.
#[inline]
pub fn checksum_simd(data: &[u8]) -> u16 {
    checksum_fold(checksum_add_fast(data))
}

/// Deprecated name kept for external callers that linked the old NEON entry.
///
/// Prefer [`checksum`] or [`checksum_simd`].
#[cfg(target_arch = "aarch64")]
#[deprecated(note = "use checksum() or checksum_simd() instead")]
#[target_feature(enable = "neon")]
#[inline]
pub unsafe fn checksum_simd_neon(data: &[u8]) -> u16 {
    // SAFETY: NEON mandatory on AArch64.
    checksum_fold(unsafe { checksum_add_neon(data) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checksum_basic() {
        // Test vector from RFC 1071
        let data = [0x00, 0x01, 0xF2, 0x03, 0xF4, 0xF5, 0xF6, 0xF7];
        let sum = checksum(&data);
        // Expected: ~(0x0001 + 0xF203 + 0xF4F5 + 0xF6F7) = ~0x2DDF0 = ~0xDDF2 = 0x220D
        assert_eq!(sum, 0x220D);
    }

    #[test]
    fn test_checksum_empty() {
        assert_eq!(checksum(&[]), 0xFFFF);
    }

    #[test]
    fn test_checksum_odd_length() {
        let data = [0x01, 0x02, 0x03];
        let sum = checksum(&data);
        // 0x0102 + 0x0300 = 0x0402, ~0x0402 = 0xFBFD
        assert_eq!(sum, 0xFBFD);
    }

    #[test]
    fn test_incremental_update() {
        // Original data
        let data = [0x00, 0x01, 0x02, 0x03];
        let original_checksum = checksum(&data);

        // Change 0x0001 to 0x0005
        let updated = incremental_checksum_update(original_checksum, 0x0001, 0x0005);

        // Verify by recalculating
        let new_data = [0x00, 0x05, 0x02, 0x03];
        let recalculated = checksum(&new_data);

        assert_eq!(updated, recalculated);
    }

    #[test]
    fn test_incremental_update_ip() {
        let data: [u8; 8] = [
            192, 168, 1, 100, // Old IP: 192.168.1.100
            192, 168, 1, 1, // Dest IP: 192.168.1.1
        ];
        let original_checksum = checksum(&data);

        let new_ip = [10u8, 0, 0, 100]; // New IP: 10.0.0.100
        let updated = update_checksum_for_ip(original_checksum, [192, 168, 1, 100], new_ip);

        // Verify
        let new_data: [u8; 8] = [10, 0, 0, 100, 192, 168, 1, 1];
        let recalculated = checksum(&new_data);

        assert_eq!(updated, recalculated);
    }

    #[test]
    fn test_ipv4_checksum() {
        // Sample IPv4 header (20 bytes)
        let header: [u8; 20] = [
            0x45, 0x00, // Version, IHL, ToS
            0x00, 0x3c, // Total Length
            0x1c, 0x46, // Identification
            0x40, 0x00, // Flags, Fragment Offset
            0x40, 0x06, // TTL, Protocol (TCP)
            0x00, 0x00, // Checksum (zeroed for calculation)
            0xac, 0x10, 0x0a, 0x63, // Source IP: 172.16.10.99
            0xac, 0x10, 0x0a, 0x0c, // Dest IP: 172.16.10.12
        ];

        let checksum = ipv4_header_checksum(&header);
        // This should be a valid checksum
        assert_ne!(checksum, 0);
    }

    #[test]
    fn test_nat_checksum_update() {
        // Simulate NAT: 192.168.1.100:12345 -> 10.0.0.1:54321
        let original_checksum: u16 = 0x1234; // Dummy original

        let updated = update_checksum_for_nat(
            original_checksum,
            [192, 168, 1, 100],
            12345,
            [10, 0, 0, 1],
            54321,
        );

        // Just verify it produces a valid result
        assert_ne!(updated, original_checksum);
    }

    #[test]
    fn test_checksum_simd() {
        let data: Vec<u8> = (0..100).collect();
        let scalar = checksum_fold(checksum_add_scalar(&data));
        let simd = checksum_simd(&data);
        assert_eq!(scalar, simd);
    }

    #[test]
    fn test_checksum_add_fast_matches_scalar_long() {
        let data: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
        assert_eq!(checksum_add_scalar(&data), checksum_add_fast(&data));
        assert_eq!(
            checksum_fold(checksum_add_scalar(&data)),
            checksum(&data),
            "checksum() must match pure scalar on long buffers"
        );
    }

    #[test]
    fn test_tcp_checksum_long_payload_matches_scalar() {
        let mut segment = vec![0u8; 20 + 1500];
        segment[12] = 0x50; // data offset 5
        for (i, b) in segment[20..].iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        // Force scalar path for expected: zero checksum field then compute via scalar add.
        segment[16] = 0;
        segment[17] = 0;
        let src = [10, 0, 0, 1];
        let dst = [10, 0, 0, 2];
        let mut sum = 0u32;
        sum = sum.wrapping_add(u16::from_be_bytes([src[0], src[1]]) as u32);
        sum = sum.wrapping_add(u16::from_be_bytes([src[2], src[3]]) as u32);
        sum = sum.wrapping_add(u16::from_be_bytes([dst[0], dst[1]]) as u32);
        sum = sum.wrapping_add(u16::from_be_bytes([dst[2], dst[3]]) as u32);
        sum = sum.wrapping_add(6);
        sum = sum.wrapping_add(segment.len() as u32);
        sum = sum.wrapping_add(checksum_add_scalar(&segment));
        let expected = checksum_fold(sum);
        assert_eq!(tcp_checksum(src, dst, &segment), expected);
    }
}
