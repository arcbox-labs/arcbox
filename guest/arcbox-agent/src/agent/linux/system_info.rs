//! `GetSystemInfo` RPC handler and the underlying guest-state collector.

use std::net::IpAddr;
use std::path::Path;

use arcbox_protocol::agent::SystemInfo;

use crate::rpc::RpcResponse;

/// Whether the distro's own init is still running its boot sequence.
///
/// On a Machine the boot shim runs `machine-init`, backgrounds the agent, and
/// only then `exec`s the distro's `/sbin/init`. So by the time the agent can
/// answer at all, the distro's boot is still ahead of it — and it typically
/// reconfigures the network from scratch, flushing the interface the shim
/// already configured. The host gates machine readiness on this so `Start`
/// does not return into that window (CORE-66).
///
/// The answer is in two parts, and conflating them is the trap: *which* init
/// the image will run is decided from files that exist on disk before it ever
/// starts, and *whether it has settled* from its runtime state. Asking only
/// the runtime question reads "has not started yet" as "already done" —
/// exactly the window this exists to close, and exactly how the first version
/// of this check failed to fire at all.
///
/// - **openrc** — image detected by `/sbin/openrc`; settled per
///   [`openrc_settled`].
/// - **systemd** — image detected by the systemd binary; settled once its
///   runtime dir exists and `is-system-running` reports a settled state.
///
/// An unrecognized init reports "not pending". Blocking start forever on a
/// distro we cannot read is worse than the race this closes, and it keeps
/// this a pure addition for images that are not affected.
fn distro_init_pending() -> bool {
    if Path::new("/sbin/openrc").exists() || Path::new("/usr/libexec/rc").is_dir() {
        return !openrc_settled(
            Path::new("/run/openrc/softlevel").exists(),
            Path::new("/run/openrc/rc.starting").exists(),
        );
    }
    if Path::new("/usr/lib/systemd/systemd").exists() || Path::new("/lib/systemd/systemd").exists()
    {
        let state = std::process::Command::new("systemctl")
            .arg("is-system-running")
            .output()
            .ok()
            .map(|out| String::from_utf8_lossy(&out.stdout).into_owned());
        return !systemd_settled(Path::new("/run/systemd/system").is_dir(), state.as_deref());
    }
    false
}

/// Whether an openrc guest has finished its runlevel.
///
/// Both conditions are load-bearing and neither alone is sufficient:
/// `rc.starting` is absent *before* openrc runs as well as after it finishes,
/// and `softlevel` appears while it is still starting. Measured on alpine
/// 3.24: `softlevel` at guest uptime 0.45 s, the network flush at 0.61–0.63 s,
/// `rc.starting` cleared at 1.64 s. Requiring softlevel present AND
/// rc.starting gone is what separates "not started yet" from "done".
fn openrc_settled(softlevel: bool, rc_starting: bool) -> bool {
    softlevel && !rc_starting
}

/// Whether a systemd guest has finished starting.
///
/// The runtime directory is the "has systemd begun" half — it does not exist
/// before systemd runs, so its absence must read as pending, not settled. An
/// unanswerable `systemctl` once systemd *is* up counts as settled rather
/// than hanging the machine.
fn systemd_settled(runtime_dir: bool, state: Option<&str>) -> bool {
    runtime_dir && state.is_none_or(|state| !systemd_state_is_pending(state))
}

/// Whether a `systemctl is-system-running` answer means "still starting".
///
/// Only `initializing` and `starting` are pre-settle states. Everything else
/// — `running`, `degraded`, `maintenance`, `stopping`, or an answer we cannot
/// parse — counts as settled: a machine must not stay unusable because one
/// unrelated unit failed, or because a future systemd invented a state we do
/// not know.
fn systemd_state_is_pending(state: &str) -> bool {
    matches!(state.trim(), "initializing" | "starting")
}

/// Handles a GetSystemInfo request.
pub(super) async fn handle_get_system_info() -> RpcResponse {
    let info = collect_system_info();
    RpcResponse::SystemInfo(info)
}

/// Collects system information from the guest.
fn collect_system_info() -> SystemInfo {
    fn parse_ip_output(stdout: &[u8]) -> Vec<String> {
        let mut ips = Vec::new();
        let output = String::from_utf8_lossy(stdout);

        for token in output.split(|c: char| c.is_whitespace() || c == ',') {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }

            let Ok(addr) = token.parse::<IpAddr>() else {
                continue;
            };
            if addr.is_loopback() {
                continue;
            }

            let ip = addr.to_string();
            if !ips.iter().any(|existing| existing == &ip) {
                ips.push(ip);
            }
        }

        ips
    }

    let mut info = SystemInfo::default();

    // Kernel version
    if let Ok(uname) = nix::sys::utsname::uname() {
        info.kernel_version = uname.release().to_string_lossy().to_string();
        info.os_name = uname.sysname().to_string_lossy().to_string();
        info.os_version = uname.version().to_string_lossy().to_string();
        info.arch = uname.machine().to_string_lossy().to_string();
        info.hostname = uname.nodename().to_string_lossy().to_string();
    }

    // Memory info
    if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
        for line in meminfo.lines() {
            if line.starts_with("MemTotal:") {
                if let Some(kb) = line.split_whitespace().nth(1) {
                    if let Ok(kb_val) = kb.parse::<u64>() {
                        info.total_memory = kb_val * 1024;
                    }
                }
            } else if line.starts_with("MemAvailable:") {
                if let Some(kb) = line.split_whitespace().nth(1) {
                    if let Ok(kb_val) = kb.parse::<u64>() {
                        info.available_memory = kb_val * 1024;
                    }
                }
            }
        }
    }

    // CPU count
    info.cpu_count = std::thread::available_parallelism()
        .map(|p| p.get() as u32)
        .unwrap_or(1);

    // Load average
    if let Ok(loadavg) = std::fs::read_to_string("/proc/loadavg") {
        let parts: Vec<&str> = loadavg.split_whitespace().collect();
        if parts.len() >= 3 {
            if let Ok(load1) = parts[0].parse::<f64>() {
                info.load_average.push(load1);
            }
            if let Ok(load5) = parts[1].parse::<f64>() {
                info.load_average.push(load5);
            }
            if let Ok(load15) = parts[2].parse::<f64>() {
                info.load_average.push(load15);
            }
        }
    }

    // Uptime
    if let Ok(uptime) = std::fs::read_to_string("/proc/uptime") {
        if let Some(secs) = uptime.split_whitespace().next() {
            if let Ok(secs_val) = secs.parse::<f64>() {
                info.uptime = secs_val as u64;
            }
        }
    }

    // IP addresses (excluding loopback).
    // Coreutils `hostname` supports `-I`, BusyBox supports `-i`.
    for flag in ["-I", "-i"] {
        let Ok(output) = std::process::Command::new("hostname").arg(flag).output() else {
            continue;
        };

        if !output.status.success() {
            continue;
        }

        let ips = parse_ip_output(&output.stdout);
        if !ips.is_empty() {
            info.ip_addresses = ips;
            break;
        }
    }

    info.distro_init_pending = distro_init_pending();

    info
}

#[cfg(test)]
mod tests {
    use super::{openrc_settled, systemd_settled, systemd_state_is_pending};

    /// The regression that made the first version of this check inert: the
    /// agent starts before the distro init, so `rc.starting` is absent at
    /// that moment too. Reading that as settled lets readiness through in
    /// exactly the window CORE-66 is about.
    #[test]
    fn openrc_that_has_not_started_yet_is_not_settled() {
        assert!(!openrc_settled(false, false));
    }

    #[test]
    fn openrc_mid_runlevel_is_not_settled() {
        // softlevel is written at 0.45 s while the runlevel is still going.
        assert!(!openrc_settled(true, true));
    }

    #[test]
    fn openrc_is_settled_only_once_the_runlevel_finishes() {
        assert!(openrc_settled(true, false));
    }

    /// Same ambiguity on the systemd side: no runtime directory means
    /// systemd has not started, which is pending, not settled.
    #[test]
    fn systemd_that_has_not_started_yet_is_not_settled() {
        assert!(!systemd_settled(false, None));
        assert!(!systemd_settled(false, Some("running")));
    }

    #[test]
    fn systemd_is_settled_once_started_and_out_of_the_starting_states() {
        assert!(!systemd_settled(true, Some("initializing")));
        assert!(systemd_settled(true, Some("running")));
        assert!(systemd_settled(true, Some("degraded")));
    }

    /// An unanswerable systemctl once systemd is up must not hang the
    /// machine until the readiness timeout.
    #[test]
    fn an_unanswerable_systemctl_counts_as_settled() {
        assert!(systemd_settled(true, None));
    }

    /// The two pre-settle states systemd reports while it is still bringing
    /// the system up — the window CORE-66 is about.
    #[test]
    fn systemd_pre_settle_states_are_pending() {
        assert!(systemd_state_is_pending("initializing\n"));
        assert!(systemd_state_is_pending("starting\n"));
    }

    /// `degraded` must count as settled: one failed unrelated unit is a
    /// normal state for a distro image and must not hold a machine unusable
    /// until the readiness timeout.
    #[test]
    fn systemd_settled_states_are_not_pending() {
        for state in ["running\n", "degraded\n", "maintenance\n", "stopping\n"] {
            assert!(!systemd_state_is_pending(state), "{state:?}");
        }
    }

    /// An answer we cannot parse (empty because systemctl failed, or a state
    /// a future systemd invented) must not block start forever.
    #[test]
    fn an_unrecognized_answer_is_not_pending() {
        assert!(!systemd_state_is_pending(""));
        assert!(!systemd_state_is_pending("offline\n"));
        assert!(!systemd_state_is_pending("something-new\n"));
    }
}
