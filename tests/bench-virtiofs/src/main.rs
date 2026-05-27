mod macro_bench;
mod micro;
mod report;
mod runner;

use std::fs;
use std::process;

use clap::Parser;

use report::{BenchmarkReport, compare_reports, print_comparison};
use runner::BenchmarkRunner;

/// Performance targets as percentage of native macOS filesystem performance.
///
/// These represent the minimum acceptable performance for each benchmark
/// category. Values below these thresholds indicate a regression that
/// needs investigation.
pub const TARGETS: &[(&str, f64)] = &[
    ("sequential_read", 90.0),
    ("sequential_write", 85.0),
    ("random_read_4k", 80.0),
    ("metadata_stat", 85.0),
    ("npm_install", 90.0),
    ("rm_rf", 90.0),
    ("negative_lookup", 99.0),
];

#[derive(Parser)]
#[command(name = "arcbox-bench-virtiofs")]
#[command(about = "VirtioFS benchmark suite for ArcBox")]
struct Cli {
    /// Run all benchmarks.
    #[arg(long)]
    all: bool,

    /// Run a specific benchmark by name.
    #[arg(long)]
    benchmark: Option<String>,

    /// Output format (text or json).
    #[arg(long, default_value = "text")]
    format: OutputFormat,

    /// Target directory (VirtioFS mount point).
    #[arg(long, default_value = "/arcbox")]
    target: String,

    /// Path to a baseline results JSON file for comparison.
    #[arg(long)]
    compare: Option<String>,

    /// Regression threshold as a percentage (default 5%).
    #[arg(long, default_value = "5")]
    threshold: f64,

    /// Exit with non-zero status if any benchmark regresses beyond threshold.
    #[arg(long)]
    fail_on_regression: bool,

    /// Number of warmup iterations (discarded).
    #[arg(long, default_value = "3")]
    warmup: u32,

    /// Number of measured iterations.
    #[arg(long, default_value = "5")]
    iterations: u32,

    /// Platform label for the report.
    #[arg(long, default_value = "arcbox-hv")]
    platform: String,

    /// List all available benchmarks and exit.
    #[arg(long)]
    list: bool,
}

#[derive(Clone, clap::ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

fn main() {
    let cli = Cli::parse();

    // List mode: print all benchmark names and exit.
    if cli.list {
        println!("Micro-benchmarks:");
        for name in micro::all_micro_benchmarks() {
            println!("  {name}");
        }
        println!("\nMacro-benchmarks:");
        for name in macro_bench::all_macro_benchmarks() {
            println!("  {name}");
        }
        println!("\nPerformance targets (% of native):");
        for (name, target) in TARGETS {
            println!("  {name}: {target}%");
        }
        return;
    }

    // Determine which benchmarks to run.
    let benchmarks_to_run = if cli.all {
        let mut all = micro::all_micro_benchmarks();
        all.extend(macro_bench::all_macro_benchmarks());
        all
    } else if let Some(ref name) = cli.benchmark {
        vec![name.as_str()]
    } else {
        eprintln!("Error: specify --all or --benchmark <name>. Use --list to see available benchmarks.");
        process::exit(1);
    };

    // Verify target directory exists.
    if !std::path::Path::new(&cli.target).is_dir() {
        eprintln!(
            "Error: target directory '{}' does not exist. \
             Use --target to specify a valid VirtioFS mount point.",
            cli.target
        );
        process::exit(1);
    }

    let runner = BenchmarkRunner::new(cli.warmup, cli.iterations);
    let mut results = Vec::new();

    eprintln!(
        "ArcBox VirtioFS Benchmark Suite v{}\n\
         Platform: {}\n\
         Target:   {}\n\
         Warmup:   {} iterations\n\
         Measured: {} iterations\n",
        env!("CARGO_PKG_VERSION"),
        cli.platform,
        cli.target,
        cli.warmup,
        cli.iterations,
    );

    for bench_name in &benchmarks_to_run {
        eprintln!("Running benchmark: {bench_name}");

        let target = cli.target.clone();
        let name = bench_name.to_string();

        // Try micro first, then macro.
        let result = if micro::all_micro_benchmarks().contains(bench_name) {
            runner.run(&name, &cli.platform, || {
                micro::run_micro_benchmark(bench_name, &target)
                    .expect("unknown micro-benchmark")
            })
        } else if macro_bench::all_macro_benchmarks().contains(bench_name) {
            runner.run(&name, &cli.platform, || {
                macro_bench::run_macro_benchmark(bench_name, &target)
                    .expect("unknown macro-benchmark")
            })
        } else {
            eprintln!("  Unknown benchmark: {bench_name}, skipping");
            continue;
        };

        // Print text summary for this benchmark.
        if matches!(cli.format, OutputFormat::Text) {
            print_result_text(&result);
        }

        results.push(result);
    }

    // Build report.
    let report = BenchmarkReport::from_results(&cli.platform, &results);

    // Output.
    match cli.format {
        OutputFormat::Json => {
            println!("{}", report.to_json().expect("failed to serialize report"));
        }
        OutputFormat::Text => {
            eprintln!("\n=== Summary ===");
            for r in &report.results {
                eprintln!(
                    "  {}: {:.2}ms{}{}",
                    r.name,
                    r.metrics.duration_ms,
                    r.metrics
                        .mb_per_sec
                        .map(|v| format!(" ({:.1} MB/s)", v))
                        .unwrap_or_default(),
                    r.metrics
                        .ops_per_sec
                        .map(|v| format!(" ({:.0} ops/s)", v))
                        .unwrap_or_default(),
                );
            }
        }
    }

    // Comparison with baseline.
    let mut has_regressions = false;
    if let Some(ref baseline_path) = cli.compare {
        let baseline_json =
            fs::read_to_string(baseline_path).expect("failed to read baseline file");
        let baseline =
            BenchmarkReport::from_json(&baseline_json).expect("failed to parse baseline report");

        let comparison = compare_reports(&report, &baseline, cli.threshold);
        print_comparison(&comparison);

        has_regressions = !comparison.regressions.is_empty();
    }

    // Check performance targets.
    if matches!(cli.format, OutputFormat::Text) {
        eprintln!("\n=== Target Compliance ===");
        for (target_name, target_pct) in TARGETS {
            if let Some(result) = report.results.iter().find(|r| r.name == *target_name) {
                if let Some(pct) = result.metrics.percent_of_native {
                    let status = if pct >= *target_pct { "PASS" } else { "FAIL" };
                    eprintln!(
                        "  {target_name}: {pct:.1}% of native (target: {target_pct}%) [{status}]"
                    );
                } else {
                    eprintln!(
                        "  {target_name}: no native baseline available (target: {target_pct}%)"
                    );
                }
            }
        }
    }

    if cli.fail_on_regression && has_regressions {
        eprintln!("\nFAILED: regressions detected beyond {:.1}% threshold", cli.threshold);
        process::exit(1);
    }
}

/// Prints a human-readable summary of a single benchmark result.
fn print_result_text(result: &runner::BenchmarkResult) {
    eprintln!("  Duration:  {:.2}ms (p50: {:.2}ms, p99: {:.2}ms)",
        result.metrics.duration_ms,
        result.metrics.duration_p50_ms,
        result.metrics.duration_p99_ms,
    );
    if let Some(mb_s) = result.metrics.mb_per_sec {
        eprintln!("  Throughput: {:.1} MB/s", mb_s);
    }
    if let Some(ops) = result.metrics.ops_per_sec {
        eprintln!("  Ops/sec:   {:.0}", ops);
    }
    eprintln!();
}
