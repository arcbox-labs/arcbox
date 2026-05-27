//! `GetSystemInfo` RPC handler and the underlying guest-state collector.

use std::net::IpAddr;

use arcbox_protocol::agent::SystemInfo;

use crate::rpc::RpcResponse;

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

    info
}
