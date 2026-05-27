use serde::{Deserialize, Serialize};

use crate::runner::BenchmarkResult;

/// Quantitative metrics captured for each benchmark run.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BenchmarkMetrics {
    /// Operations per second (for metadata / IOPS benchmarks).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ops_per_sec: Option<f64>,
    /// Throughput in megabytes per second (for sequential I/O benchmarks).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mb_per_sec: Option<f64>,
    /// Mean wall-clock duration in milliseconds.
    pub duration_ms: f64,
    /// 50th-percentile (median) duration in milliseconds.
    pub duration_p50_ms: f64,
    /// 99th-percentile duration in milliseconds.
    pub duration_p99_ms: f64,
    /// Performance relative to native macOS filesystem (percentage).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub percent_of_native: Option<f64>,
}

/// Top-level JSON report containing all benchmark results.
#[derive(Serialize, Deserialize)]
pub struct BenchmarkReport {
    /// Schema version for forward compatibility.
    pub version: String,
    /// When this report was generated.
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Platform label (e.g. "arcbox-hv", "orbstack", "native").
    pub platform: String,
    /// Individual benchmark results.
    pub results: Vec<BenchmarkResultJson>,
}

/// Serializable representation of a single benchmark result.
#[derive(Serialize, Deserialize)]
pub struct BenchmarkResultJson {
    pub name: String,
    pub metrics: BenchmarkMetrics,
}

/// Summary of a comparison between two reports.
pub struct ComparisonResult {
    pub regressions: Vec<Regression>,
    pub improvements: Vec<Improvement>,
}

/// A benchmark that got slower beyond the acceptable threshold.
pub struct Regression {
    pub benchmark: String,
    pub current: f64,
    pub baseline: f64,
    /// Positive value indicates slowdown (e.g. 10.0 means 10% slower).
    pub percent_change: f64,
}

/// A benchmark that got faster.
pub struct Improvement {
    pub benchmark: String,
    pub current: f64,
    pub baseline: f64,
    /// Negative value indicates speedup (e.g. -15.0 means 15% faster).
    pub percent_change: f64,
}

impl BenchmarkReport {
    /// Constructs a report from a set of benchmark results.
    pub fn from_results(platform: &str, results: &[BenchmarkResult]) -> Self {
        Self {
            version: "1.0.0".to_string(),
            timestamp: chrono::Utc::now(),
            platform: platform.to_string(),
            results: results
                .iter()
                .map(|r| BenchmarkResultJson {
                    name: r.name.clone(),
                    metrics: r.metrics.clone(),
                })
                .collect(),
        }
    }

    /// Serializes the report to pretty-printed JSON.
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }

    /// Deserializes a report from a JSON string.
    pub fn from_json(json: &str) -> serde_json::Result<Self> {
        serde_json::from_str(json)
    }
}

/// Compares two reports and identifies regressions and improvements.
///
/// Comparison is based on `duration_ms` — lower is better. A positive
/// `percent_change` means the current run is slower (regression).
/// Only benchmarks present in both reports are compared.
pub fn compare_reports(
    current: &BenchmarkReport,
    baseline: &BenchmarkReport,
    threshold: f64,
) -> ComparisonResult {
    let mut regressions = Vec::new();
    let mut improvements = Vec::new();

    for current_result in &current.results {
        let Some(baseline_result) = baseline
            .results
            .iter()
            .find(|b| b.name == current_result.name)
        else {
            continue;
        };

        let cur = current_result.metrics.duration_ms;
        let base = baseline_result.metrics.duration_ms;

        if base == 0.0 {
            continue;
        }

        // Positive percent_change = regression (slower).
        let percent_change = ((cur - base) / base) * 100.0;

        if percent_change > threshold {
            regressions.push(Regression {
                benchmark: current_result.name.clone(),
                current: cur,
                baseline: base,
                percent_change,
            });
        } else if percent_change < -threshold {
            improvements.push(Improvement {
                benchmark: current_result.name.clone(),
                current: cur,
                baseline: base,
                percent_change,
            });
        }
    }

    ComparisonResult {
        regressions,
        improvements,
    }
}

/// Prints a human-readable comparison to stderr.
pub fn print_comparison(comparison: &ComparisonResult) {
    if comparison.regressions.is_empty() && comparison.improvements.is_empty() {
        eprintln!("\nNo significant changes detected.");
        return;
    }

    if !comparison.regressions.is_empty() {
        eprintln!("\n--- REGRESSIONS ---");
        for r in &comparison.regressions {
            eprintln!(
                "  {}: {:.2}ms -> {:.2}ms ({:+.1}%)",
                r.benchmark, r.baseline, r.current, r.percent_change
            );
        }
    }

    if !comparison.improvements.is_empty() {
        eprintln!("\n--- IMPROVEMENTS ---");
        for i in &comparison.improvements {
            eprintln!(
                "  {}: {:.2}ms -> {:.2}ms ({:+.1}%)",
                i.benchmark, i.baseline, i.current, i.percent_change
            );
        }
    }
}
