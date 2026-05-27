use std::time::{Duration, Instant};

use crate::report::BenchmarkMetrics;

/// Executes benchmark functions with warmup and measured iterations,
/// collecting timing data and computing statistical metrics.
pub struct BenchmarkRunner {
    pub warmup_iterations: u32,
    pub measured_iterations: u32,
}

/// Complete result for a single benchmark run, including all individual
/// iteration durations and aggregated metrics.
#[allow(dead_code)]
pub struct BenchmarkResult {
    pub name: String,
    pub iterations: u32,
    pub durations: Vec<Duration>,
    pub metrics: BenchmarkMetrics,
    pub platform: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl BenchmarkRunner {
    pub fn new(warmup: u32, iterations: u32) -> Self {
        Self {
            warmup_iterations: warmup,
            measured_iterations: iterations,
        }
    }

    /// Runs a benchmark function with warmup and measurement phases.
    ///
    /// The warmup phase discards results to let caches and JIT settle.
    /// The measurement phase collects `measured_iterations` samples and
    /// computes aggregated metrics (median, p99, throughput).
    pub fn run<F>(&self, name: &str, platform: &str, f: F) -> BenchmarkResult
    where
        F: Fn() -> BenchmarkMetrics,
    {
        // Warmup phase: run the benchmark but discard results.
        for i in 0..self.warmup_iterations {
            eprintln!("  [warmup {}/{}] {name}", i + 1, self.warmup_iterations);
            let _ = f();
        }

        // Measurement phase: collect timing and metrics for each iteration.
        let mut durations = Vec::with_capacity(self.measured_iterations as usize);
        let mut all_metrics = Vec::with_capacity(self.measured_iterations as usize);

        for i in 0..self.measured_iterations {
            eprintln!(
                "  [iter {}/{}] {name}",
                i + 1,
                self.measured_iterations
            );
            let start = Instant::now();
            let metrics = f();
            let elapsed = start.elapsed();
            durations.push(elapsed);
            all_metrics.push(metrics);
        }

        // Aggregate metrics across iterations.
        let aggregated = Self::aggregate_metrics(&all_metrics, &durations);

        BenchmarkResult {
            name: name.to_string(),
            iterations: self.measured_iterations,
            durations,
            metrics: aggregated,
            platform: platform.to_string(),
            timestamp: chrono::Utc::now(),
        }
    }

    /// Aggregates metrics from multiple iterations by computing medians
    /// for throughput values and percentile durations from raw timings.
    fn aggregate_metrics(all: &[BenchmarkMetrics], durations: &[Duration]) -> BenchmarkMetrics {
        if all.is_empty() {
            return BenchmarkMetrics {
                ops_per_sec: None,
                mb_per_sec: None,
                duration_ms: 0.0,
                duration_p50_ms: 0.0,
                duration_p99_ms: 0.0,
                percent_of_native: None,
            };
        }

        // Sort durations for percentile computation.
        let mut sorted_ms: Vec<f64> = durations
            .iter()
            .map(|d| d.as_secs_f64() * 1000.0)
            .collect();
        sorted_ms.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let p50 = percentile(&sorted_ms, 50.0);
        let p99 = percentile(&sorted_ms, 99.0);
        let mean_ms: f64 = sorted_ms.iter().sum::<f64>() / sorted_ms.len() as f64;

        // Average ops/sec and MB/s across iterations (where available).
        let ops_per_sec = median_option(all.iter().filter_map(|m| m.ops_per_sec).collect());
        let mb_per_sec = median_option(all.iter().filter_map(|m| m.mb_per_sec).collect());
        let percent_of_native =
            median_option(all.iter().filter_map(|m| m.percent_of_native).collect());

        BenchmarkMetrics {
            ops_per_sec,
            mb_per_sec,
            duration_ms: mean_ms,
            duration_p50_ms: p50,
            duration_p99_ms: p99,
            percent_of_native,
        }
    }
}

/// Computes the p-th percentile from a sorted slice of f64 values.
fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    if sorted.len() == 1 {
        return sorted[0];
    }
    let rank = (p / 100.0) * (sorted.len() - 1) as f64;
    let lower = rank.floor() as usize;
    let upper = rank.ceil() as usize;
    let frac = rank - lower as f64;
    sorted[lower] * (1.0 - frac) + sorted[upper] * frac
}

/// Computes the median of a Vec<f64>, returning None if empty.
fn median_option(mut values: Vec<f64>) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let mid = values.len() / 2;
    if values.len() % 2 == 0 {
        Some((values[mid - 1] + values[mid]) / 2.0)
    } else {
        Some(values[mid])
    }
}
