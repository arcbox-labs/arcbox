//! Idle-cost sampler for a running process (typically `arcbox-daemon`).
//!
//! The idle targets are hard numbers (CPU <0.05%, memory <150 MB); R3
//! (tickless WFI, event-driven workers) needs a measurement to prove
//! progress. CPU% is computed from the `ps` cputime delta over the
//! sampling window — not `%cpu`, whose decaying average hides short
//! windows.

use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

use crate::IdleArgs;

pub fn run(args: IdleArgs) -> Result<()> {
    let (cpu_before, _) = sample(args.pid)?;
    let started = Instant::now();
    std::thread::sleep(Duration::from_secs(args.seconds));
    let wall = started.elapsed().as_secs_f64();
    let (cpu_after, rss_kb) = sample(args.pid)?;

    let cpu_percent = (cpu_after - cpu_before) / wall * 100.0;
    let rss_mb = rss_kb as f64 / 1024.0;
    println!(
        "[idle] pid={} window={:.0}s cpu={cpu_percent:.3}% rss={rss_mb:.1}MB",
        args.pid, wall
    );
    println!(
        "[idle] targets: cpu <0.05% [{}], rss <150MB [{}]",
        if cpu_percent < 0.05 { "OK" } else { "MISS" },
        if rss_mb < 150.0 { "OK" } else { "MISS" },
    );
    Ok(())
}

/// Returns (cumulative CPU seconds, RSS KiB) for `pid`.
fn sample(pid: u32) -> Result<(f64, u64)> {
    let output = Command::new("ps")
        .args(["-o", "cputime=,rss=", "-p", &pid.to_string()])
        .output()
        .context("running ps")?;
    if !output.status.success() {
        bail!("pid {pid} not found");
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut fields = text.split_whitespace();
    let cputime = fields.next().context("ps output missing cputime")?;
    let rss: u64 = fields
        .next()
        .context("ps output missing rss")?
        .parse()
        .context("parsing rss")?;
    Ok((parse_cputime(cputime)?, rss))
}

/// Parses `ps` cputime (`[[HH:]MM:]SS.ss` or `DD-HH:MM:SS`) to seconds.
fn parse_cputime(text: &str) -> Result<f64> {
    let (days, rest) = match text.split_once('-') {
        Some((d, rest)) => (d.parse::<f64>().context("parsing cputime days")?, rest),
        None => (0.0, text),
    };
    let mut seconds = 0.0;
    for part in rest.split(':') {
        seconds = seconds * 60.0 + part.parse::<f64>().context("parsing cputime field")?;
    }
    Ok(days.mul_add(86_400.0, seconds))
}

#[cfg(test)]
mod tests {
    use super::parse_cputime;

    #[test]
    fn parses_common_cputime_forms() {
        assert!((parse_cputime("0:01.23").unwrap() - 1.23).abs() < 1e-9);
        assert!((parse_cputime("2:03:04").unwrap() - 7384.0).abs() < 1e-9);
        assert!((parse_cputime("1-00:00:01").unwrap() - 86_401.0).abs() < 1e-9);
    }
}
