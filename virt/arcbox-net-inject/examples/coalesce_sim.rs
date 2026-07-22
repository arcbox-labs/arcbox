//! Discrete-event model of inject coalesce under sustained frame rates.
//!
//! ```text
//! cargo run -p arcbox-net-inject --example coalesce_sim --release
//! ```

#![allow(clippy::while_float)]

use arcbox_net_inject::coalesce::{
    BATCH_SIZE, CoalescePolicy, EXPAND_MIN_FPS, QUIET_MAX_BATCH, WINDOW_DEFAULT_US, WINDOW_MAX_US,
};

fn gather_once(window_us: u32, frames_per_sec: f64) -> (u16, f64, bool) {
    if frames_per_sec <= 0.0 {
        return (0, f64::from(window_us) / 1_000_000.0, false);
    }
    let frames_in_window = frames_per_sec * f64::from(window_us) / 1_000_000.0;
    if frames_in_window >= BATCH_SIZE as f64 {
        let batch = BATCH_SIZE as u16;
        let advance = f64::from(batch) / frames_per_sec;
        (batch, advance, true)
    } else {
        let batch = frames_in_window.floor() as u16;
        (batch, f64::from(window_us) / 1_000_000.0, false)
    }
}

struct Run {
    label: &'static str,
    frames_per_sec: f64,
    duration_s: f64,
    adaptive: bool,
}

struct ResultRow {
    label: String,
    policy: String,
    frames: u64,
    irqs: u64,
    frames_per_irq: f64,
    avg_window_us: f64,
    peak_window_us: u32,
    irqs_per_sec: f64,
}

fn simulate(run: &Run) -> ResultRow {
    let mut policy = CoalescePolicy::new();
    let mut frames = 0u64;
    let mut flushes = 0u64;
    let mut window_sum = 0u64;
    let mut peak = WINDOW_DEFAULT_US;
    let mut t = 0.0;

    while t < run.duration_s {
        let window_us = if run.adaptive {
            policy.window_us()
        } else {
            WINDOW_DEFAULT_US
        };
        let (batch, advance, filled_early) = gather_once(window_us, run.frames_per_sec);
        frames += u64::from(batch);
        if batch > 0 {
            flushes += 1;
            window_sum += u64::from(window_us);
            peak = peak.max(window_us);
        }
        if run.adaptive {
            policy.observe(batch, window_us, filled_early, true);
        }
        t += advance;
    }

    let irqs = flushes;
    ResultRow {
        label: run.label.to_string(),
        policy: if run.adaptive {
            "adaptive".into()
        } else {
            "fixed-200µs".into()
        },
        frames,
        irqs,
        frames_per_irq: if irqs == 0 {
            0.0
        } else {
            frames as f64 / irqs as f64
        },
        avg_window_us: if flushes == 0 {
            0.0
        } else {
            window_sum as f64 / flushes as f64
        },
        peak_window_us: peak,
        irqs_per_sec: irqs as f64 / run.duration_s,
    }
}

fn main() {
    let scenarios = [
        ("P1 GSO ~10 Gbps", 37_000.0),
        ("P1 GSO ~22 Gbps", 80_000.0),
        ("P2 multi-flow ~same bits as 10G", 74_000.0),
        ("P2 multi-flow saturated", 120_000.0),
        ("small-packet stress 500k fps", 500_000.0),
        ("idle / very light 100 fps", 100.0),
    ];

    let duration_s = 1.0;
    println!("# Coalesce mechanism model (no VM)");
    println!(
        "duration={duration_s}s BATCH={BATCH_SIZE} default={WINDOW_DEFAULT_US}µs max={WINDOW_MAX_US}µs expand_min_fps={EXPAND_MIN_FPS} quiet_max_batch={QUIET_MAX_BATCH}"
    );
    println!(
        "Note: 'irqs' here = non-empty flushes with EVENT_IDX off; production can suppress further."
    );
    println!();
    println!(
        "{:<32} {:<12} {:>10} {:>10} {:>10} {:>10} {:>10} {:>8}",
        "scenario", "policy", "frames", "irqs", "f/IRQ", "IRQ/s", "avg_win", "peak_us"
    );
    println!("{}", "-".repeat(110));

    for (label, fps) in scenarios {
        let fixed = simulate(&Run {
            label,
            frames_per_sec: fps,
            duration_s,
            adaptive: false,
        });
        let adapt = simulate(&Run {
            label,
            frames_per_sec: fps,
            duration_s,
            adaptive: true,
        });
        for row in [&fixed, &adapt] {
            println!(
                "{:<32} {:<12} {:>10} {:>10} {:>10.1} {:>10.0} {:>10.0} {:>8}",
                row.label,
                row.policy,
                row.frames,
                row.irqs,
                row.frames_per_irq,
                row.irqs_per_sec,
                row.avg_window_us,
                row.peak_window_us
            );
        }
        if fixed.irqs_per_sec > 0.0 {
            let irq_delta = (adapt.irqs_per_sec / fixed.irqs_per_sec - 1.0) * 100.0;
            let fpi_delta = if fixed.frames_per_irq > 0.0 {
                (adapt.frames_per_irq / fixed.frames_per_irq - 1.0) * 100.0
            } else {
                0.0
            };
            println!(
                "{:<32} {:<12} irq/s {:+.1}%   frames/IRQ {:+.1}%   peak {}→{}µs",
                "", "Δ adaptive", irq_delta, fpi_delta, fixed.peak_window_us, adapt.peak_window_us
            );
        }
        println!();
    }
}
