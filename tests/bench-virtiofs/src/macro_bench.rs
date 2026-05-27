use std::fs;
use std::process::Command;
use std::time::Instant;

use crate::report::BenchmarkMetrics;

/// npm install benchmark.
///
/// Copies a minimal fixture project (package.json + package-lock.json)
/// into the target directory and runs `npm install --frozen-lockfile`,
/// measuring wall-clock time. This exercises metadata lookups, small file
/// creation, and symlink-heavy workloads.
pub fn bench_npm_install(target: &str) -> BenchmarkMetrics {
    let bench_dir = format!("{}/bench_npm", target);
    let _ = fs::remove_dir_all(&bench_dir);
    fs::create_dir_all(&bench_dir).expect("failed to create npm benchmark directory");

    // Create a minimal package.json that pulls in a few common packages
    // to generate a realistic node_modules tree.
    let package_json = r#"{
  "name": "arcbox-bench-fixture",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "express": "^4.18.0",
    "lodash": "^4.17.0",
    "chalk": "^4.1.0"
  }
}"#;
    fs::write(format!("{}/package.json", bench_dir), package_json)
        .expect("failed to write package.json");

    let start = Instant::now();
    let status = Command::new("npm")
        .args(["install", "--no-audit", "--no-fund"])
        .current_dir(&bench_dir)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .status();
    let elapsed = start.elapsed();

    if let Err(e) = &status {
        eprintln!("    npm install failed: {e}");
    }

    // Clean up.
    let _ = fs::remove_dir_all(&bench_dir);

    BenchmarkMetrics {
        ops_per_sec: None,
        mb_per_sec: None,
        duration_ms: elapsed.as_secs_f64() * 1000.0,
        duration_p50_ms: elapsed.as_secs_f64() * 1000.0,
        duration_p99_ms: elapsed.as_secs_f64() * 1000.0,
        percent_of_native: None,
    }
}

/// Git clone benchmark.
///
/// Clones a repository into the target directory, measuring wall-clock
/// time. This exercises sequential writes, metadata operations, and
/// network I/O through the filesystem layer.
pub fn bench_git_clone(target: &str, repo_url: &str) -> BenchmarkMetrics {
    let bench_dir = format!("{}/bench_git_clone", target);
    let _ = fs::remove_dir_all(&bench_dir);

    let start = Instant::now();
    let status = Command::new("git")
        .args(["clone", "--depth=1", repo_url, &bench_dir])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .status();
    let elapsed = start.elapsed();

    if let Err(e) = &status {
        eprintln!("    git clone failed: {e}");
    }

    // Clean up.
    let _ = fs::remove_dir_all(&bench_dir);

    BenchmarkMetrics {
        ops_per_sec: None,
        mb_per_sec: None,
        duration_ms: elapsed.as_secs_f64() * 1000.0,
        duration_p50_ms: elapsed.as_secs_f64() * 1000.0,
        duration_p99_ms: elapsed.as_secs_f64() * 1000.0,
        percent_of_native: None,
    }
}

/// rm -rf benchmark.
///
/// First creates a large directory tree (simulating node_modules), then
/// measures how long `rm -rf` takes to delete it. This is a common pain
/// point for shared-filesystem solutions.
pub fn bench_rm_rf(target: &str) -> BenchmarkMetrics {
    let bench_dir = format!("{}/bench_rm_rf", target);
    let _ = fs::remove_dir_all(&bench_dir);

    // Build a tree resembling a medium node_modules directory.
    // ~5000 files across ~200 directories.
    eprintln!("    creating directory tree for rm -rf benchmark...");
    for dir_idx in 0..200 {
        let dir_path = format!("{}/pkg_{}/lib", bench_dir, dir_idx);
        fs::create_dir_all(&dir_path).expect("failed to create directory tree");
        for file_idx in 0..25 {
            let file_path = format!("{}/file_{}.js", dir_path, file_idx);
            fs::write(&file_path, "// placeholder\n").expect("failed to write file");
        }
    }

    let start = Instant::now();
    let status = Command::new("rm")
        .args(["-rf", &bench_dir])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .status();
    let elapsed = start.elapsed();

    if let Err(e) = &status {
        eprintln!("    rm -rf failed: {e}");
    }

    BenchmarkMetrics {
        ops_per_sec: None,
        mb_per_sec: None,
        duration_ms: elapsed.as_secs_f64() * 1000.0,
        duration_p50_ms: elapsed.as_secs_f64() * 1000.0,
        duration_p99_ms: elapsed.as_secs_f64() * 1000.0,
        percent_of_native: None,
    }
}

/// Recursive find benchmark.
///
/// Runs `find <target> -name "*.ts" -type f` over a pre-built directory
/// tree, measuring wall-clock time and reporting the number of matching
/// files. This exercises readdir + stat in a deeply nested structure.
pub fn bench_find_recursive(target: &str) -> BenchmarkMetrics {
    let bench_dir = format!("{}/bench_find", target);
    let _ = fs::remove_dir_all(&bench_dir);

    // Build a tree with mixed file types.
    eprintln!("    creating directory tree for find benchmark...");
    for dir_idx in 0..100 {
        let dir_path = format!("{}/src/module_{}", bench_dir, dir_idx);
        fs::create_dir_all(&dir_path).expect("failed to create directory tree");
        for file_idx in 0..20 {
            // Mix of .ts, .js, .json files.
            let ext = match file_idx % 4 {
                0 => "ts",
                1 => "js",
                2 => "json",
                _ => "tsx",
            };
            let file_path = format!("{}/file_{}.{}", dir_path, file_idx, ext);
            fs::write(&file_path, "// placeholder\n").expect("failed to write file");
        }
    }

    let start = Instant::now();
    let output = Command::new("find")
        .args([&bench_dir, "-name", "*.ts", "-type", "f"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output();
    let elapsed = start.elapsed();

    let file_count = match output {
        Ok(ref out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            stdout.lines().count()
        }
        Err(e) => {
            eprintln!("    find failed: {e}");
            0
        }
    };

    eprintln!("    found {file_count} .ts files");

    // Clean up.
    let _ = fs::remove_dir_all(&bench_dir);

    BenchmarkMetrics {
        ops_per_sec: Some(file_count as f64 / elapsed.as_secs_f64()),
        mb_per_sec: None,
        duration_ms: elapsed.as_secs_f64() * 1000.0,
        duration_p50_ms: elapsed.as_secs_f64() * 1000.0,
        duration_p99_ms: elapsed.as_secs_f64() * 1000.0,
        percent_of_native: None,
    }
}

/// Returns the list of all macro-benchmark names.
pub fn all_macro_benchmarks() -> Vec<&'static str> {
    vec!["npm_install", "git_clone", "rm_rf", "find_recursive"]
}

/// Dispatches a macro-benchmark by name, returning None if the name is unknown.
pub fn run_macro_benchmark(name: &str, target: &str) -> Option<BenchmarkMetrics> {
    match name {
        "npm_install" => Some(bench_npm_install(target)),
        "git_clone" => Some(bench_git_clone(
            target,
            "https://github.com/expressjs/express.git",
        )),
        "rm_rf" => Some(bench_rm_rf(target)),
        "find_recursive" => Some(bench_find_recursive(target)),
        _ => None,
    }
}
