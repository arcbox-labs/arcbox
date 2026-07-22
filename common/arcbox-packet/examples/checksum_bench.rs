//! Microbench: scalar vs SIMD Internet checksum throughput.
//!
//! ```text
//! cargo run -p arcbox-packet --example checksum_bench --release
//! ```

use std::time::Instant;

use arcbox_packet::checksum::{checksum_add_scalar, checksum_fold, checksum_simd};

fn bench(label: &str, len: usize, iters: usize, f: impl Fn(&[u8]) -> u16) {
    let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
    for _ in 0..100 {
        std::hint::black_box(f(&data));
    }
    let t0 = Instant::now();
    let mut sink = 0u16;
    for _ in 0..iters {
        sink ^= f(&data);
    }
    let elapsed = t0.elapsed();
    std::hint::black_box(sink);
    let bytes = (len as u64).saturating_mul(iters as u64);
    let gbps = (bytes as f64 * 8.0) / elapsed.as_secs_f64() / 1e9;
    let ns_per_call = elapsed.as_nanos() as f64 / iters as f64;
    println!(
        "{label:<18} len={len:>5}  {iters:>8} iters  {gbps:>8.2} Gbit/s  {ns_per_call:>8.1} ns/call"
    );
}

fn main() {
    println!(
        "# Internet checksum microbench (host = {})",
        std::env::consts::ARCH
    );
    println!();

    for &len in &[64usize, 1500, 9000, 16384, 65536] {
        let iters = (50_000_000 / len).max(2_000);
        bench("scalar", len, iters, |d| {
            checksum_fold(checksum_add_scalar(d))
        });
        bench("simd", len, iters, checksum_simd);
        let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        assert_eq!(
            checksum_fold(checksum_add_scalar(&data)),
            checksum_simd(&data),
            "scalar/simd mismatch at len={len}"
        );
        println!();
    }
}
