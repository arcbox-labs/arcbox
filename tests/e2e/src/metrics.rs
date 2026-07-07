//! Machine-readable per-run metrics.
//!
//! Every performance target is a hard number (cold boot <1.5 s, …), and
//! the easiest casualty of a correctness-fix campaign is a silent
//! performance regression. Each e2e run records its phase timings as
//! JSON: into the run's data dir, and — when `ARCBOX_E2E_METRICS_DIR`
//! is set (the `cargo xtask e2e` runner does this) — into the archive
//! directory as `<label>.metrics.json`, so passing runs leave numbers
//! behind too.

use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::Serialize;

/// One timed phase of an e2e run.
#[derive(Debug, Serialize)]
pub struct Phase {
    pub name: String,
    pub seconds: f64,
}

/// Machine-readable record of one e2e run.
#[derive(Debug, Serialize)]
pub struct RunMetrics {
    /// Test target name (e.g. `boot_assets`, `hv_vmm`).
    pub test: String,
    /// System VM backend label, when the run pinned one.
    pub backend: Option<String>,
    /// Whether the run passed. Set by the caller before writing.
    pub passed: bool,
    /// Unix time the run started.
    pub unix_time: u64,
    /// Timed phases, in execution order.
    pub phases: Vec<Phase>,
}

impl RunMetrics {
    #[must_use]
    pub fn new(test: &str, backend: Option<&str>) -> Self {
        Self {
            test: test.to_owned(),
            backend: backend.map(str::to_owned),
            passed: false,
            unix_time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or_default(),
            phases: Vec::new(),
        }
    }

    /// Runs `f`, recording its wall-clock duration under `name` (also
    /// when it fails — a slow failure is still a data point).
    pub fn time<T, E>(&mut self, name: &str, f: impl FnOnce() -> Result<T, E>) -> Result<T, E> {
        let started = Instant::now();
        let result = f();
        self.record(name, started.elapsed().as_secs_f64());
        result
    }

    /// Records an externally measured phase duration.
    pub fn record(&mut self, name: &str, seconds: f64) {
        self.phases.push(Phase {
            name: name.to_owned(),
            seconds,
        });
    }

    /// Writes `metrics.json` into `run_dir` (when given) and
    /// `$ARCBOX_E2E_METRICS_DIR/<label>.metrics.json` (when the variable
    /// is set). The label comes from `ARCBOX_E2E_RUN_LABEL`, defaulting
    /// to `<test>-<pid>`. Returns the written paths.
    pub fn write(&self, run_dir: Option<&Path>) -> Result<Vec<PathBuf>> {
        let json = serde_json::to_vec_pretty(self).context("serializing run metrics")?;
        let mut written = Vec::new();

        if let Some(dir) = run_dir {
            let path = dir.join("metrics.json");
            std::fs::write(&path, &json).with_context(|| format!("writing {}", path.display()))?;
            written.push(path);
        }

        if let Ok(dir) = std::env::var("ARCBOX_E2E_METRICS_DIR") {
            if !dir.is_empty() {
                let label = std::env::var("ARCBOX_E2E_RUN_LABEL")
                    .unwrap_or_else(|_| format!("{}-{}", self.test, std::process::id()));
                let dir = PathBuf::from(dir);
                std::fs::create_dir_all(&dir)
                    .with_context(|| format!("creating {}", dir.display()))?;
                let path = dir.join(format!("{label}.metrics.json"));
                std::fs::write(&path, &json)
                    .with_context(|| format!("writing {}", path.display()))?;
                written.push(path);
            }
        }

        Ok(written)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_records_duration_for_failures_too() {
        let mut metrics = RunMetrics::new("t", Some("hv"));
        let ok: Result<(), &str> = metrics.time("good", || Ok(()));
        let err: Result<(), &str> = metrics.time("bad", || Err("boom"));
        assert!(ok.is_ok());
        assert!(err.is_err());
        assert_eq!(metrics.phases.len(), 2);
        assert_eq!(metrics.phases[0].name, "good");
        assert_eq!(metrics.phases[1].name, "bad");
    }

    #[test]
    fn write_lands_in_run_dir() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut metrics = RunMetrics::new("t", None);
        metrics.record("phase", 1.5);
        metrics.passed = true;
        let written = metrics.write(Some(dir.path())).expect("write");
        assert!(written.iter().any(|p| p.ends_with("metrics.json")));
        let text = std::fs::read_to_string(dir.path().join("metrics.json")).expect("read");
        assert!(text.contains("\"phase\""));
        assert!(text.contains("\"passed\": true"));
    }
}
