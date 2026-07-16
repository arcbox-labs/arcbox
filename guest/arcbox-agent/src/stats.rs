//! Machine-level resource stat parsers for the `WatchStats` stream.
//!
//! Pure text parsing over `/proc` file contents, kept platform-neutral so
//! the logic is unit-testable on any host. The Linux handler
//! (`agent::linux::stats`) owns the actual file reads and frame writing.
//!
//! All extracted counters are cumulative-since-boot; consumers derive
//! rates from deltas between samples (see `MachineStats` in agent.proto).

/// Sector size `/proc/diskstats` counts in, independent of the device's
/// real block size (fixed by the kernel ABI).
const DISKSTATS_SECTOR_BYTES: u64 = 512;

/// Aggregate CPU ticks from `/proc/stat`'s first line: `(busy, total)`.
///
/// Busy is everything except idle and iowait. Fields beyond `idle` may be
/// absent on old kernels; missing fields count as zero.
#[must_use]
pub fn parse_cpu_ticks(stat: &str) -> Option<(u64, u64)> {
    let line = stat.lines().find(|l| l.starts_with("cpu "))?;
    let fields: Vec<u64> = line
        .split_ascii_whitespace()
        .skip(1)
        .map_while(|f| f.parse().ok())
        .collect();
    if fields.len() < 4 {
        return None;
    }
    let total: u64 = fields.iter().sum();
    let idle = fields[3] + fields.get(4).copied().unwrap_or(0);
    Some((total.saturating_sub(idle), total))
}

/// 1-minute load average from `/proc/loadavg`.
#[must_use]
pub fn parse_loadavg1(loadavg: &str) -> Option<f64> {
    loadavg.split_ascii_whitespace().next()?.parse().ok()
}

/// Guest monotonic milliseconds from `/proc/uptime`.
#[must_use]
pub fn parse_uptime_ms(uptime: &str) -> Option<u64> {
    let secs: f64 = uptime.split_ascii_whitespace().next()?.parse().ok()?;
    if !secs.is_finite() || secs < 0.0 {
        return None;
    }
    Some((secs * 1000.0) as u64)
}

/// `(MemTotal, MemAvailable)` in bytes from `/proc/meminfo`.
#[must_use]
pub fn parse_meminfo(meminfo: &str) -> Option<(u64, u64)> {
    Some((
        meminfo_field_bytes(meminfo, "MemTotal:")?,
        meminfo_field_bytes(meminfo, "MemAvailable:")?,
    ))
}

fn meminfo_field_bytes(meminfo: &str, key: &str) -> Option<u64> {
    let line = meminfo.lines().find(|l| l.starts_with(key))?;
    let kb: u64 = line.split_ascii_whitespace().nth(1)?.parse().ok()?;
    kb.checked_mul(1024)
}

/// The `full avg10` percentage from `/proc/pressure/memory`.
///
/// `None` on kernels without `CONFIG_PSI` (missing file is the caller's
/// case; this handles a present-but-unparsable file the same way).
#[must_use]
pub fn parse_psi_full_avg10(pressure: &str) -> Option<f64> {
    let line = pressure.lines().find(|l| l.starts_with("full "))?;
    let avg10 = line
        .split_ascii_whitespace()
        .find_map(|f| f.strip_prefix("avg10="))?;
    avg10.parse().ok()
}

/// Cumulative `(read, written)` bytes across whole physical disks.
///
/// Partitions are excluded so traffic is not counted twice; virtual
/// devices (loop, dm-*, zram, ram, md) are excluded so stacked block
/// layers do not multiply it either.
#[must_use]
pub fn parse_diskstats(diskstats: &str) -> (u64, u64) {
    let mut read = 0u64;
    let mut written = 0u64;
    for line in diskstats.lines() {
        let fields: Vec<&str> = line.split_ascii_whitespace().collect();
        // major minor name reads _ sectors_read _ writes _ sectors_written …
        let (Some(name), Some(sectors_read), Some(sectors_written)) =
            (fields.get(2), fields.get(5), fields.get(9))
        else {
            continue;
        };
        if !is_whole_disk(name) {
            continue;
        }
        let r: u64 = sectors_read.parse().unwrap_or(0);
        let w: u64 = sectors_written.parse().unwrap_or(0);
        read = read.saturating_add(r.saturating_mul(DISKSTATS_SECTOR_BYTES));
        written = written.saturating_add(w.saturating_mul(DISKSTATS_SECTOR_BYTES));
    }
    (read, written)
}

/// Whether a `/proc/diskstats` device name is a whole physical disk (as
/// opposed to a partition or a virtual/stacked device).
fn is_whole_disk(name: &str) -> bool {
    for prefix in ["vd", "sd", "xvd"] {
        if let Some(rest) = name.strip_prefix(prefix) {
            // Whole disks are letters only ("vda"); partitions end in
            // digits ("vda1").
            return !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_lowercase());
        }
    }
    // NVMe namespaces ("nvme0n1") vs partitions ("nvme0n1p2"); the same
    // 'p'-suffix convention holds for mmcblk.
    for prefix in ["nvme", "mmcblk"] {
        if let Some(rest) = name.strip_prefix(prefix) {
            return !rest.is_empty() && !rest.contains('p');
        }
    }
    false
}

/// Cumulative `(rx, tx)` bytes across physical/uplink interfaces from
/// `/proc/net/dev`.
///
/// Only real NICs are counted (see [`is_physical_nic`]). The System VM's
/// root netns also carries container bridges and veths (`docker0`,
/// `br-<hash>`, `veth<hash>`, `cni0`, …); summing those would count the
/// same bytes once per internal hop (veth → bridge → uplink), inflating
/// the machine's reported throughput — the same double-count the disk
/// parser avoids with [`is_whole_disk`]. In a container's own netns this
/// leaves just its `eth0`, so per-container reads are unaffected.
#[must_use]
pub fn parse_net_dev(net_dev: &str) -> (u64, u64) {
    let mut rx = 0u64;
    let mut tx = 0u64;
    for line in net_dev.lines() {
        let Some((name, rest)) = line.split_once(':') else {
            continue; // header lines
        };
        if !is_physical_nic(name.trim()) {
            continue;
        }
        let fields: Vec<&str> = rest.split_ascii_whitespace().collect();
        // rx: bytes packets errs drop fifo frame compressed multicast, then tx.
        let (Some(rx_bytes), Some(tx_bytes)) = (fields.first(), fields.get(8)) else {
            continue;
        };
        rx = rx.saturating_add(rx_bytes.parse().unwrap_or(0));
        tx = tx.saturating_add(tx_bytes.parse().unwrap_or(0));
    }
    (rx, tx)
}

/// Whether an interface name is a physical/uplink NIC, as opposed to a
/// container bridge or veth. An allowlist of the kernel's predictable NIC
/// prefixes (`eth`, `en*`) is robust because virtual-interface naming
/// varies widely (`docker0`, `br-<hash>`, `veth<hash>`, `cni0`,
/// `flannel.1`, `vxlan*`, `virbr*`, `tap*`, …) and none of them share
/// these prefixes — `veth` starts with `v`, not `e`.
fn is_physical_nic(name: &str) -> bool {
    name.starts_with("eth") || name.starts_with("en")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_ticks_split_busy_from_idle_and_iowait() {
        let stat = "cpu  100 20 50 800 30 5 5 0 0 0\ncpu0 10 2 5 80 3 1 1 0 0 0\n";
        let (busy, total) = parse_cpu_ticks(stat).unwrap();
        assert_eq!(total, 1010);
        assert_eq!(busy, 1010 - 800 - 30);
    }

    #[test]
    fn cpu_ticks_tolerate_short_old_kernel_lines() {
        // Pre-2.6 shape: user nice system idle only.
        let (busy, total) = parse_cpu_ticks("cpu  10 0 20 70\n").unwrap();
        assert_eq!((busy, total), (30, 100));
        assert!(parse_cpu_ticks("cpu  1 2 3\n").is_none());
        assert!(parse_cpu_ticks("intr 12345\n").is_none());
    }

    #[test]
    fn loadavg_and_uptime_parse_first_field() {
        assert_eq!(parse_loadavg1("0.42 0.36 0.34 2/1290 12345\n"), Some(0.42));
        assert_eq!(parse_uptime_ms("352.62 6082.49\n"), Some(352_620));
        assert_eq!(parse_uptime_ms("-1 0"), None);
    }

    #[test]
    fn meminfo_scales_kb_to_bytes() {
        let meminfo =
            "MemTotal:       16296128 kB\nMemFree:         1234 kB\nMemAvailable:   15000000 kB\n";
        let (total, available) = parse_meminfo(meminfo).unwrap();
        assert_eq!(total, 16_296_128 * 1024);
        assert_eq!(available, 15_000_000 * 1024);
        assert!(parse_meminfo("MemTotal: 1 kB\n").is_none());
    }

    #[test]
    fn psi_reads_full_avg10() {
        let pressure = "some avg10=0.12 avg60=0.05 avg300=0.01 total=417963\n\
                        full avg10=7.68 avg60=1.23 avg300=0.30 total=291211\n";
        assert_eq!(parse_psi_full_avg10(pressure), Some(7.68));
        assert_eq!(parse_psi_full_avg10("some avg10=0.00 total=0\n"), None);
    }

    #[test]
    fn diskstats_sum_whole_disks_only() {
        let diskstats = "\
 254       0 vda 100 0 2000 50 200 0 4000 100 0 0 0\n\
 254       1 vda1 90 0 1800 45 190 0 3800 95 0 0 0\n\
 254      16 vdb 10 0 100 5 20 0 200 10 0 0 0\n\
   7       0 loop0 5 0 50 1 0 0 0 0 0 0 0\n\
 253       0 dm-0 5 0 50 1 5 0 50 1 0 0 0\n";
        let (read, written) = parse_diskstats(diskstats);
        assert_eq!(read, (2000 + 100) * 512);
        assert_eq!(written, (4000 + 200) * 512);
    }

    #[test]
    fn whole_disk_classification() {
        for disk in ["vda", "sdb", "xvdc", "nvme0n1", "mmcblk0"] {
            assert!(is_whole_disk(disk), "{disk}");
        }
        for other in [
            "vda1",
            "sdb2",
            "nvme0n1p1",
            "mmcblk0p2",
            "loop0",
            "ram0",
            "dm-0",
            "zram0",
            "md0",
            "sr0",
            "vd",
        ] {
            assert!(!is_whole_disk(other), "{other}");
        }
    }

    #[test]
    fn net_dev_counts_uplinks_and_skips_bridges_veths() {
        // The System VM's root netns: real uplinks (eth0/eth1) plus the
        // container bridges/veths whose bytes would otherwise be counted
        // again on the uplink.
        let net_dev = "\
Inter-|   Receive                                                |  Transmit\n\
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n\
       lo: 9999999    100    0    0    0     0          0         0  9999999    100    0    0    0     0       0          0\n\
     eth0: 1000     10    0    0    0     0          0         0  2000     20    0    0    0     0       0          0\n\
     eth1:  500      5    0    0    0     0          0         0   700      7    0    0    0     0       0          0\n\
  docker0: 8000     80    0    0    0     0          0         0  8000     80    0    0    0     0       0          0\n\
veth1a2b3c: 8000     80    0    0    0     0          0         0  8000     80    0    0    0     0       0          0\n\
 br-abc123: 8000     80    0    0    0     0          0         0  8000     80    0    0    0     0       0          0\n";
        // Only eth0 + eth1 count; the bridges/veths are excluded.
        assert_eq!(parse_net_dev(net_dev), (1500, 2700));
    }

    #[test]
    fn physical_nic_allowlist() {
        for nic in ["eth0", "eth1", "en0", "ens1", "enp0s5"] {
            assert!(is_physical_nic(nic), "{nic}");
        }
        for virt in [
            "lo",
            "docker0",
            "br-abc123",
            "veth1a2b",
            "cni0",
            "flannel.1",
            "vxlan.calico",
            "virbr0",
            "tap0",
            "tun0",
        ] {
            assert!(!is_physical_nic(virt), "{virt}");
        }
    }
}
