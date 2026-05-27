use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::process::Command;
use std::time::Instant;

use crate::report::BenchmarkMetrics;

/// Sequential read benchmark using `dd`.
///
/// Creates a test file of the given size, then reads it back through
/// `dd` to `/dev/null`, parsing the reported throughput.
pub fn bench_sequential_read(target: &str, size_mb: u64) -> BenchmarkMetrics {
    let test_file = format!("{}/bench_seq_read.dat", target);

    // Create test file if it doesn't already exist.
    if !Path::new(&test_file).exists() {
        let status = Command::new("dd")
            .args([
                "if=/dev/zero",
                &format!("of={}", test_file),
                "bs=1048576",
                &format!("count={}", size_mb),
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .status();
        if let Err(e) = status {
            eprintln!("    failed to create test file: {e}");
        }
    }

    // Purge filesystem caches if possible (requires root).
    let _ = Command::new("sync").status();
    let _ = Command::new("purge").status();

    let start = Instant::now();
    let output = Command::new("dd")
        .args([
            &format!("if={}", test_file),
            "of=/dev/null",
            "bs=1048576",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .output();

    let elapsed = start.elapsed();

    let mb_per_sec = match output {
        Ok(ref out) => parse_dd_throughput(&String::from_utf8_lossy(&out.stderr)),
        Err(_) => None,
    };

    // Fallback: compute from elapsed time if dd output parsing fails.
    let mb_per_sec = mb_per_sec.unwrap_or_else(|| size_mb as f64 / elapsed.as_secs_f64());

    // Clean up.
    let _ = fs::remove_file(&test_file);

    BenchmarkMetrics {
        ops_per_sec: None,
        mb_per_sec: Some(mb_per_sec),
        duration_ms: elapsed.as_secs_f64() * 1000.0,
        duration_p50_ms: elapsed.as_secs_f64() * 1000.0,
        duration_p99_ms: elapsed.as_secs_f64() * 1000.0,
        percent_of_native: None,
    }
}

/// Sequential write benchmark using `dd`.
///
/// Writes `size_mb` megabytes from `/dev/zero` to a file on the target
/// filesystem, measuring throughput.
pub fn bench_sequential_write(target: &str, size_mb: u64) -> BenchmarkMetrics {
    let test_file = format!("{}/bench_seq_write.dat", target);

    let start = Instant::now();
    let output = Command::new("dd")
        .args([
            "if=/dev/zero",
            &format!("of={}", test_file),
            "bs=1048576",
            &format!("count={}", size_mb),
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .output();

    // Ensure data is flushed to disk.
    let _ = Command::new("sync").status();
    let elapsed = start.elapsed();

    let mb_per_sec = match output {
        Ok(ref out) => parse_dd_throughput(&String::from_utf8_lossy(&out.stderr)),
        Err(_) => None,
    };

    let mb_per_sec = mb_per_sec.unwrap_or_else(|| size_mb as f64 / elapsed.as_secs_f64());

    // Clean up.
    let _ = fs::remove_file(&test_file);

    BenchmarkMetrics {
        ops_per_sec: None,
        mb_per_sec: Some(mb_per_sec),
        duration_ms: elapsed.as_secs_f64() * 1000.0,
        duration_p50_ms: elapsed.as_secs_f64() * 1000.0,
        duration_p99_ms: elapsed.as_secs_f64() * 1000.0,
        percent_of_native: None,
    }
}

/// Random 4K read benchmark.
///
/// If `fio` is available, delegates to it for accurate IOPS measurement.
/// Otherwise falls back to a pure-Rust implementation using random seeks.
pub fn bench_random_read_4k(target: &str, num_ops: u64) -> BenchmarkMetrics {
    // Check if fio is available.
    let fio_available = Command::new("fio").arg("--version").output().is_ok();

    if fio_available {
        bench_random_read_4k_fio(target, num_ops)
    } else {
        bench_random_read_4k_rust(target, num_ops)
    }
}

/// Random 4K read using fio for accurate IOPS measurement.
fn bench_random_read_4k_fio(target: &str, num_ops: u64) -> BenchmarkMetrics {
    let test_file = format!("{}/bench_rand_read.dat", target);

    // Create a 256MB test file for random reads.
    let _ = Command::new("dd")
        .args([
            "if=/dev/urandom",
            &format!("of={}", test_file),
            "bs=1048576",
            "count=256",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    let start = Instant::now();
    let output = Command::new("fio")
        .args([
            "--name=randread",
            &format!("--filename={}", test_file),
            "--rw=randread",
            "--bs=4k",
            "--direct=1",
            "--ioengine=posixaio",
            &format!("--io_limit={}k", num_ops * 4),
            "--output-format=json",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output();

    let elapsed = start.elapsed();

    let ops_per_sec = match output {
        Ok(ref out) => parse_fio_iops(&String::from_utf8_lossy(&out.stdout)),
        Err(_) => None,
    };

    let ops_per_sec = ops_per_sec.unwrap_or_else(|| num_ops as f64 / elapsed.as_secs_f64());

    let _ = fs::remove_file(&test_file);

    BenchmarkMetrics {
        ops_per_sec: Some(ops_per_sec),
        mb_per_sec: Some(ops_per_sec * 4.0 / 1024.0),
        duration_ms: elapsed.as_secs_f64() * 1000.0,
        duration_p50_ms: elapsed.as_secs_f64() * 1000.0,
        duration_p99_ms: elapsed.as_secs_f64() * 1000.0,
        percent_of_native: None,
    }
}

/// Pure-Rust fallback for random 4K reads when fio is unavailable.
fn bench_random_read_4k_rust(target: &str, num_ops: u64) -> BenchmarkMetrics {
    let test_file = format!("{}/bench_rand_read.dat", target);
    let file_size: u64 = 256 * 1024 * 1024; // 256 MB

    // Create test file with random data.
    {
        let mut f = fs::File::create(&test_file).expect("failed to create test file");
        let buf = vec![0xABu8; 1024 * 1024];
        for _ in 0..256 {
            f.write_all(&buf).expect("failed to write test data");
        }
        f.sync_all().expect("failed to sync test file");
    }

    let mut f = fs::File::open(&test_file).expect("failed to open test file");
    let mut buf = [0u8; 4096];

    // Simple LCG for reproducible pseudo-random offsets.
    let max_offset = file_size / 4096;
    let mut rng_state: u64 = 0xDEAD_BEEF_CAFE_BABE;

    let start = Instant::now();
    for _ in 0..num_ops {
        // Linear congruential generator.
        rng_state = rng_state.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        let offset = (rng_state % max_offset) * 4096;
        f.seek(SeekFrom::Start(offset))
            .expect("failed to seek in test file");
        f.read_exact(&mut buf).expect("failed to read from test file");
    }
    let elapsed = start.elapsed();

    let ops_per_sec = num_ops as f64 / elapsed.as_secs_f64();

    let _ = fs::remove_file(&test_file);

    BenchmarkMetrics {
        ops_per_sec: Some(ops_per_sec),
        mb_per_sec: Some(ops_per_sec * 4.0 / 1024.0),
        duration_ms: elapsed.as_secs_f64() * 1000.0,
        duration_p50_ms: elapsed.as_secs_f64() * 1000.0,
        duration_p99_ms: elapsed.as_secs_f64() * 1000.0,
        percent_of_native: None,
    }
}

/// Metadata stat benchmark.
///
/// Creates a nested directory tree with `num_files` files, then times
/// how long it takes to `stat` (metadata lookup) every file.
pub fn bench_metadata_stat(target: &str, num_files: u64) -> BenchmarkMetrics {
    let bench_dir = format!("{}/bench_metadata", target);
    let _ = fs::remove_dir_all(&bench_dir);
    fs::create_dir_all(&bench_dir).expect("failed to create benchmark directory");

    // Create files spread across subdirectories (100 files per dir).
    let files_per_dir: u64 = 100;
    let mut file_paths = Vec::with_capacity(num_files as usize);

    for i in 0..num_files {
        let dir_idx = i / files_per_dir;
        let dir_path = format!("{}/d{}", bench_dir, dir_idx);
        if i % files_per_dir == 0 {
            fs::create_dir_all(&dir_path).expect("failed to create subdirectory");
        }
        let file_path = format!("{}/f{}.txt", dir_path, i);
        fs::File::create(&file_path).expect("failed to create file");
        file_paths.push(file_path);
    }

    // Measure stat time.
    let start = Instant::now();
    for path in &file_paths {
        let _ = fs::metadata(path);
    }
    let elapsed = start.elapsed();

    let ops_per_sec = num_files as f64 / elapsed.as_secs_f64();

    // Clean up.
    let _ = fs::remove_dir_all(&bench_dir);

    BenchmarkMetrics {
        ops_per_sec: Some(ops_per_sec),
        mb_per_sec: None,
        duration_ms: elapsed.as_secs_f64() * 1000.0,
        duration_p50_ms: elapsed.as_secs_f64() * 1000.0,
        duration_p99_ms: elapsed.as_secs_f64() * 1000.0,
        percent_of_native: None,
    }
}

/// File create/delete benchmark.
///
/// Creates `num_files` files and then deletes them all, measuring the
/// combined throughput in operations per second.
pub fn bench_create_delete(target: &str, num_files: u64) -> BenchmarkMetrics {
    let bench_dir = format!("{}/bench_create_delete", target);
    let _ = fs::remove_dir_all(&bench_dir);
    fs::create_dir_all(&bench_dir).expect("failed to create benchmark directory");

    let mut file_paths = Vec::with_capacity(num_files as usize);

    // Create phase.
    let start = Instant::now();
    for i in 0..num_files {
        let path = format!("{}/f{}.tmp", bench_dir, i);
        fs::File::create(&path).expect("failed to create file");
        file_paths.push(path);
    }

    // Delete phase.
    for path in &file_paths {
        fs::remove_file(path).expect("failed to remove file");
    }
    let elapsed = start.elapsed();

    // Total ops = num_files creates + num_files deletes.
    let total_ops = num_files * 2;
    let ops_per_sec = total_ops as f64 / elapsed.as_secs_f64();

    // Clean up.
    let _ = fs::remove_dir_all(&bench_dir);

    BenchmarkMetrics {
        ops_per_sec: Some(ops_per_sec),
        mb_per_sec: None,
        duration_ms: elapsed.as_secs_f64() * 1000.0,
        duration_p50_ms: elapsed.as_secs_f64() * 1000.0,
        duration_p99_ms: elapsed.as_secs_f64() * 1000.0,
        percent_of_native: None,
    }
}

/// Negative lookup (ENOENT) benchmark.
///
/// Repeatedly stats non-existent files to measure negative dentry cache
/// performance. A well-tuned VirtioFS should handle these at near-native
/// speed via the negative lookup cache.
pub fn bench_negative_lookup(target: &str, num_lookups: u64) -> BenchmarkMetrics {
    let bench_dir = format!("{}/bench_neglookup", target);
    let _ = fs::remove_dir_all(&bench_dir);
    fs::create_dir_all(&bench_dir).expect("failed to create benchmark directory");

    let start = Instant::now();
    for i in 0..num_lookups {
        // These files never exist, so every stat returns ENOENT.
        let path = format!("{}/nonexistent_{}.txt", bench_dir, i);
        let _ = fs::metadata(&path);
    }
    let elapsed = start.elapsed();

    let ops_per_sec = num_lookups as f64 / elapsed.as_secs_f64();

    // Clean up.
    let _ = fs::remove_dir_all(&bench_dir);

    BenchmarkMetrics {
        ops_per_sec: Some(ops_per_sec),
        mb_per_sec: None,
        duration_ms: elapsed.as_secs_f64() * 1000.0,
        duration_p50_ms: elapsed.as_secs_f64() * 1000.0,
        duration_p99_ms: elapsed.as_secs_f64() * 1000.0,
        percent_of_native: None,
    }
}

/// Parses throughput from `dd` stderr output.
///
/// dd typically outputs something like:
///   "1048576000 bytes transferred in 0.523 secs (2004930784 bytes/sec)"
/// or on Linux:
///   "1000+0 records out\n1048576000 bytes (1.0 GB, 1000 MiB) copied, 0.523 s, 2.0 GB/s"
fn parse_dd_throughput(stderr: &str) -> Option<f64> {
    // Try macOS format: "bytes/sec" in parentheses.
    if let Some(idx) = stderr.find("bytes/sec") {
        let before = &stderr[..idx];
        if let Some(paren_idx) = before.rfind('(') {
            let num_str = before[paren_idx + 1..].trim();
            if let Ok(bytes_per_sec) = num_str.parse::<f64>() {
                return Some(bytes_per_sec / (1024.0 * 1024.0));
            }
        }
    }

    // Try Linux format: extract "X bytes ... copied, Y s" and compute.
    if let Some(copied_idx) = stderr.find("copied,") {
        let after = &stderr[copied_idx + 7..];
        // Find the time value (e.g., " 0.523 s").
        let time_str = after.trim().split_whitespace().next()?;
        let secs: f64 = time_str.parse().ok()?;

        // Find bytes count at the start of the line.
        let line_start = stderr[..copied_idx]
            .rfind('\n')
            .map_or(0, |i| i + 1);
        let bytes_str = stderr[line_start..copied_idx]
            .split_whitespace()
            .next()?;
        let bytes: f64 = bytes_str.parse().ok()?;

        return Some(bytes / secs / (1024.0 * 1024.0));
    }

    None
}

/// Parses IOPS from fio JSON output.
fn parse_fio_iops(stdout: &str) -> Option<f64> {
    let json: serde_json::Value = serde_json::from_str(stdout).ok()?;
    let jobs = json.get("jobs")?.as_array()?;
    let job = jobs.first()?;
    let read = job.get("read")?;
    let iops = read.get("iops")?.as_f64()?;
    Some(iops)
}

/// Returns the list of all micro-benchmark names.
pub fn all_micro_benchmarks() -> Vec<&'static str> {
    vec![
        "sequential_read",
        "sequential_write",
        "random_read_4k",
        "metadata_stat",
        "create_delete",
        "negative_lookup",
    ]
}

/// Dispatches a micro-benchmark by name, returning None if the name is unknown.
pub fn run_micro_benchmark(name: &str, target: &str) -> Option<BenchmarkMetrics> {
    match name {
        "sequential_read" => Some(bench_sequential_read(target, 512)),
        "sequential_write" => Some(bench_sequential_write(target, 512)),
        "random_read_4k" => Some(bench_random_read_4k(target, 10_000)),
        "metadata_stat" => Some(bench_metadata_stat(target, 10_000)),
        "create_delete" => Some(bench_create_delete(target, 10_000)),
        "negative_lookup" => Some(bench_negative_lookup(target, 100_000)),
        _ => None,
    }
}
