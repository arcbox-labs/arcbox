//! System initialization for PID 1 agent.
//!
//! When the agent runs as PID 1 (EROFS boot path), the busybox trampoline has
//! already mounted /proc, /sys, /dev (devtmpfs), and /arcbox (VirtioFS).
//!
//! This module sets up everything else: writable tmpfs layers over the read-only
//! EROFS rootfs, populates /etc, mounts pseudo-filesystems, and configures networking.
//!
//! All operations are idempotent and best-effort — failures are logged but do not
//! abort, since PID 1 must not exit.

#[cfg(target_os = "linux")]
mod platform {
    use std::fs;
    use std::os::unix::fs as unix_fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    use nix::mount::{MsFlags, mount};
    use nix::sys::resource::{Resource, setrlimit};

    /// Runs one-time system initialization after trampoline hands off to agent.
    ///
    /// Trampoline already mounted: /proc, /sys, /dev, /arcbox (VirtioFS).
    /// EROFS rootfs is purely structural. All writable state goes on tmpfs.
    pub fn init_system() {
        // Raise file descriptor limits before spawning any children so that
        // containerd, dockerd, and all containers inherit a high ceiling.
        // Docker Desktop and OrbStack both set 1048576 in their guest VMs.
        raise_fd_limits();

        // Mount host /private for macOS symlink targets (/tmp, /var/folders).
        // Must come before tmpfs mounts so /private is available as a VirtioFS
        // target. Guest /tmp and /var remain isolated tmpfs.
        mount_virtiofs_optional(
            arcbox_constants::virtiofs::TAG_PRIVATE,
            arcbox_constants::virtiofs::MOUNT_PRIVATE,
        );

        // Writable layers on top of read-only EROFS.
        mount_tmpfs("/tmp");
        mount_tmpfs("/run");
        mount_tmpfs("/var");
        mount_tmpfs("/etc");

        // Populate /etc with files containerd/dockerd expect.
        write_etc_resolv_conf();
        write_etc_hosts();
        write_etc_passwd();
        write_etc_group();
        write_docker_daemon_config();

        // TLS CA certificates: EROFS has /cacerts/ca-certificates.crt.
        // Symlink into tmpfs /etc so programs find it at the standard path.
        mkdir_p("/etc/ssl/certs");
        symlink_if_source_exists(
            "/cacerts/ca-certificates.crt",
            "/etc/ssl/certs/ca-certificates.crt",
        );

        // Writable subdirectories under /var.
        mkdir_p("/var/lib/docker");
        mkdir_p("/var/run/docker");
        mkdir_p("/run/containerd");

        // Pseudo-filesystems.
        mount_cgroup2();
        mount_devpts();
        mount_shm();

        // Network.
        setup_networking();

        // Optional host /Users share (non-fatal if not configured).
        mount_virtiofs_optional(
            arcbox_constants::virtiofs::TAG_USERS,
            arcbox_constants::virtiofs::MOUNT_USERS,
        );

        // Optional DAX fixture share for the hv_e2e harness. Mounted under
        // `/run/arcbox-dax` because `/` is read-only EROFS — mkdir_p on a
        // top-level path fails with EROFS. `/run` is tmpfs, created above.
        // `dax=always` makes FUSE_SETUPMAPPING fire on every read,
        // exercising the stage-2 mmap fast path end-to-end.
        // Production VMs never attach this tag; the mount is a debug-level
        // no-op when the share is absent.
        mount_virtiofs_optional_dax("arcbox-dax", "/run/arcbox-dax");

        // Rosetta x86_64 translation (Apple Silicon only).
        // The host attaches a VirtioFS share containing the Rosetta binary.
        // We mount it and register via binfmt_misc so x86_64 ELF binaries
        // are transparently translated at near-native speed.
        setup_rosetta();

        tracing::info!("PID 1 system initialization complete");
    }

    /// Raises process file descriptor limits so that containerd, dockerd, and
    /// all containers inherit a sufficiently high ceiling.
    ///
    /// Without this, PID 1 inherits the kernel default (soft=1024, hard=4096)
    /// and containers that need `ulimit -n` > 4096 fail with EINVAL.
    fn raise_fd_limits() {
        // Ensure the kernel ceiling (fs.nr_open) is at least the target.
        // The default is already 1048576, but guard against custom kernels.
        ensure_sysctl_at_least("/proc/sys/fs/nr_open", super::NOFILE_LIMIT);

        // Only raise — never lower a previously higher inherited limit.
        let target = super::NOFILE_LIMIT;
        match nix::sys::resource::getrlimit(Resource::RLIMIT_NOFILE) {
            Ok((soft, hard)) if soft >= target && hard >= target => {}
            _ => {
                if let Err(e) = setrlimit(Resource::RLIMIT_NOFILE, target, target) {
                    tracing::warn!(error = %e, "failed to raise RLIMIT_NOFILE");
                }
            }
        }
    }

    /// Writes `value` to a sysctl path only if the current value is lower.
    fn ensure_sysctl_at_least(path: &str, target: u64) {
        let current = fs::read_to_string(path)
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(0);
        if current < target {
            if let Err(e) = fs::write(path, format!("{target}\n")) {
                tracing::warn!(path, error = %e, "failed to raise sysctl");
            }
        }
    }

    fn mount_tmpfs(target: &str) {
        if crate::mount::is_mounted(target) {
            return;
        }
        // Ensure mount point exists — EROFS may not have /etc or /var.
        mkdir_p(target);
        if let Err(e) = mount(
            Some("tmpfs"),
            target,
            Some("tmpfs"),
            MsFlags::MS_NODEV | MsFlags::MS_NOSUID,
            None::<&str>,
        ) {
            tracing::warn!(target, error = %e, "failed to mount tmpfs");
        }
    }

    fn mount_cgroup2() {
        if Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
            return;
        }
        mkdir_p("/sys/fs/cgroup");
        if let Err(e) = mount(
            Some("cgroup2"),
            "/sys/fs/cgroup",
            Some("cgroup2"),
            MsFlags::empty(),
            None::<&str>,
        ) {
            tracing::warn!(error = %e, "failed to mount cgroup2");
        }
    }

    fn mount_devpts() {
        if Path::new("/dev/pts/ptmx").exists() {
            return;
        }
        mkdir_p("/dev/pts");
        if let Err(e) = mount(
            Some("devpts"),
            "/dev/pts",
            Some("devpts"),
            MsFlags::MS_NOEXEC | MsFlags::MS_NOSUID,
            Some("gid=5,mode=0620"),
        ) {
            tracing::warn!(error = %e, "failed to mount devpts");
        }
    }

    fn mount_shm() {
        if crate::mount::is_mounted("/dev/shm") {
            return;
        }
        mkdir_p("/dev/shm");
        if let Err(e) = mount(
            Some("shm"),
            "/dev/shm",
            Some("tmpfs"),
            MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
            None::<&str>,
        ) {
            tracing::warn!(error = %e, "failed to mount /dev/shm");
        }
    }

    fn mount_virtiofs_optional(tag: &str, mountpoint: &str) {
        if crate::mount::is_mounted(mountpoint) {
            return;
        }
        mkdir_p(mountpoint);
        if let Err(e) = mount(
            Some(tag),
            mountpoint,
            Some("virtiofs"),
            MsFlags::empty(),
            None::<&str>,
        ) {
            // debug, not warn — this share is optional.
            tracing::debug!(tag, mountpoint, error = %e, "virtiofs share not available");
        }
    }

    /// Like `mount_virtiofs_optional` but passes `dax=always`.
    ///
    /// Required for shares whose consumer depends on the FUSE DAX fast path
    /// firing (e.g. the hv_e2e harness, which asserts `FUSE_SETUPMAPPING`
    /// counters increment). Still non-fatal when the share is absent, so
    /// production VMs that don't attach the tag pay only a debug log.
    ///
    /// `cache=` is NOT passed here: the Linux 6.12 virtiofs parameter spec
    /// only accepts `source` and `dax`, so `cache=always` triggers
    /// `virtiofs: Unknown parameter 'cache'` and the mount fails outright.
    /// Caching behaviour is inherited from FUSE defaults.
    fn mount_virtiofs_optional_dax(tag: &str, mountpoint: &str) {
        if crate::mount::is_mounted(mountpoint) {
            return;
        }
        mkdir_p(mountpoint);
        if let Err(e) = mount(
            Some(tag),
            mountpoint,
            Some("virtiofs"),
            MsFlags::empty(),
            Some("dax=always"),
        ) {
            tracing::debug!(tag, mountpoint, error = %e, "virtiofs DAX share not available");
        }
    }

    /// Mounts the Rosetta VirtioFS share and registers binfmt_misc for x86_64.
    ///
    /// This is a best-effort operation — if the host did not attach a Rosetta
    /// share (Intel Mac, Rosetta not installed, or config disabled), the
    /// VirtioFS mount fails silently and we skip registration.
    fn setup_rosetta() {
        const ROSETTA_MOUNT: &str = "/media/rosetta";
        const ROSETTA_TAG: &str = "rosetta";
        const ROSETTA_BINARY: &str = "/media/rosetta/rosetta";

        // Mount the Rosetta VirtioFS share (skip if already mounted).
        if !crate::mount::is_mounted(ROSETTA_MOUNT) {
            mkdir_p(ROSETTA_MOUNT);
            if let Err(e) = mount(
                Some(ROSETTA_TAG),
                ROSETTA_MOUNT,
                Some("virtiofs"),
                MsFlags::MS_RDONLY,
                None::<&str>,
            ) {
                tracing::debug!(error = %e, "Rosetta VirtioFS share not available — x86_64 translation disabled");
                return;
            }
        }

        // Verify the Rosetta binary exists in the share.
        if !Path::new(ROSETTA_BINARY).exists() {
            tracing::warn!("Rosetta share mounted but binary not found at {ROSETTA_BINARY}");
            return;
        }

        // Mount binfmt_misc if not already mounted.
        if !Path::new("/proc/sys/fs/binfmt_misc/status").exists() {
            mkdir_p("/proc/sys/fs/binfmt_misc");
            if let Err(e) = mount(
                Some("binfmt_misc"),
                "/proc/sys/fs/binfmt_misc",
                Some("binfmt_misc"),
                MsFlags::empty(),
                None::<&str>,
            ) {
                tracing::warn!(error = %e, "failed to mount binfmt_misc — Rosetta registration skipped");
                return;
            }
        }

        // Skip if already registered (idempotent re-entry).
        if Path::new("/proc/sys/fs/binfmt_misc/rosetta").exists() {
            tracing::debug!("Rosetta binfmt_misc handler already registered");
            return;
        }

        // Register Rosetta as the x86_64 ELF interpreter.
        //
        // Magic: 20-byte x86_64 ELF header (EI_CLASS=64, e_machine=EM_X86_64).
        // Mask: allows both ET_EXEC (0x02) and ET_DYN (0x03) via 0xfe on byte 16.
        // Flags: C = credentials from binary, F = fix-binary (keep fd open across
        //        mount namespaces so containers can use Rosetta without mounting it).
        let registration = format!(
            ":rosetta:M::\\x7fELF\\x02\\x01\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x02\\x00\\x3e\\x00:\\xff\\xff\\xff\\xff\\xff\\xfe\\xfe\\x00\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xfe\\xff\\xff\\xff:{ROSETTA_BINARY}:CF"
        );

        match fs::write("/proc/sys/fs/binfmt_misc/register", registration.as_bytes()) {
            Ok(()) => {
                tracing::info!("Rosetta x86_64 translation registered via binfmt_misc");
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to register Rosetta binfmt_misc handler");
            }
        }
    }

    fn setup_networking() {
        // Enable IPv4 forwarding for Docker bridge networking.
        if let Err(e) = std::fs::write("/proc/sys/net/ipv4/ip_forward", b"1\n") {
            tracing::warn!(error = %e, "failed to enable ip_forward");
        }
        // Bring up loopback interface.
        match std::process::Command::new("/bin/busybox")
            .args(["ip", "link", "set", "lo", "up"])
            .status()
        {
            Ok(s) if s.success() => {}
            Ok(s) => tracing::warn!(
                exit_code = s.code().unwrap_or(-1),
                "loopback 'ip link set lo up' exited non-zero"
            ),
            Err(e) => tracing::warn!(error = %e, "failed to bring up loopback"),
        }

        // Configure the primary interface via DHCP so the guest can reach
        // gateway services (DNS/NAT at 10.0.2.1).
        configure_primary_interface_dhcp();

        // Configure the bridge NIC (eth1) via DHCP for inbound L3 routing.
        // This NIC is connected to Apple's vmnet bridge (bridge100) and
        // provides a real L2 path for host → container traffic.
        // We only take an IP — no default route (outbound stays on eth0).
        configure_bridge_nic();

        // Allow forwarding between the primary interface and sandbox TAP
        // interfaces. Docker/containerd sets the default FORWARD policy to
        // DROP, so blanket ACCEPT rules are required for sandbox traffic.
        setup_sandbox_forwarding();
    }

    fn configure_primary_interface_dhcp() {
        let Some(interface) = detect_primary_interface() else {
            tracing::warn!("no non-loopback network interface found for DHCP");
            return;
        };

        match std::process::Command::new("/bin/busybox")
            .args(["ip", "link", "set", interface.as_str(), "up"])
            .status()
        {
            Ok(s) if s.success() => {}
            Ok(s) => {
                tracing::warn!(
                    interface,
                    exit_code = s.code().unwrap_or(-1),
                    "failed to bring interface up before DHCP"
                );
            }
            Err(e) => {
                tracing::warn!(interface, error = %e, "failed to execute 'ip link set up'");
            }
        }

        // BusyBox udhcpc requires a script to apply lease settings.
        let udhcpc_script = "/run/udhcpc.script";
        let script = r#"#!/bin/sh
set -e
case "$1" in
  deconfig)
    /bin/busybox ifconfig "$interface" 0.0.0.0 || true
    ;;
  renew|bound)
    /bin/busybox ifconfig "$interface" "$ip" netmask "${subnet:-255.255.255.0}" broadcast "${broadcast:-+}" up
    if [ -n "${router:-}" ]; then
      while /bin/busybox route del default gw 0.0.0.0 dev "$interface" 2>/dev/null; do :; done
      for r in $router; do
        /bin/busybox route add default gw "$r" dev "$interface" && break
      done
    fi
    ;;
esac
exit 0
"#;

        if let Err(e) = fs::write(udhcpc_script, script) {
            tracing::warn!(error = %e, "failed to write udhcpc script");
            return;
        }
        if let Err(e) = fs::set_permissions(udhcpc_script, fs::Permissions::from_mode(0o755)) {
            tracing::warn!(error = %e, "failed to chmod udhcpc script");
            return;
        }

        match std::process::Command::new("/bin/busybox")
            .args([
                "udhcpc",
                "-i",
                interface.as_str(),
                "-n",
                "-q",
                "-t",
                "3",
                "-T",
                "2",
                "-s",
                udhcpc_script,
            ])
            .status()
        {
            Ok(s) if s.success() => {
                tracing::info!(interface, "DHCP lease acquired");
            }
            Ok(s) => {
                tracing::warn!(
                    interface,
                    exit_code = s.code().unwrap_or(-1),
                    "DHCP request failed"
                );
            }
            Err(e) => {
                tracing::warn!(interface, error = %e, "failed to run udhcpc");
            }
        }
    }

    /// Configures the bridge NIC (second interface) via DHCP.
    ///
    /// Uses a custom udhcpc script that only sets the IP address — no default
    /// route, no DNS. This ensures outbound traffic still goes through eth0
    /// (socketpair datapath), while the bridge NIC is reachable from the host
    /// for inbound container traffic.
    fn configure_bridge_nic() {
        // Find the bridge NIC: it's the non-loopback interface that is NOT
        // the primary interface. The primary interface was already configured
        // by configure_primary_interface_dhcp() and has an IP in 10.0.2.0/24.
        let primary = detect_primary_interface();
        let entries = match fs::read_dir("/sys/class/net") {
            Ok(e) => e,
            Err(_) => return,
        };
        let mut bridge_iface: Option<String> = None;
        for entry in entries.flatten() {
            let Ok(name) = entry.file_name().into_string() else {
                continue;
            };
            // Skip loopback, virtual, and the primary interface.
            if name == "lo"
                || name.starts_with("dummy")
                || name.starts_with("veth")
                || name.starts_with("br-")
                || name.starts_with("docker")
                || name.starts_with("vmtap")
                || name.starts_with("sit")
                || primary.as_deref() == Some(&name)
            {
                continue;
            }
            bridge_iface = Some(name);
            break;
        }

        let Some(bridge_iface) = bridge_iface.as_deref() else {
            tracing::debug!("no bridge NIC found");
            return;
        };

        // Bring up the interface.
        let _ = std::process::Command::new("/bin/busybox")
            .args(["ip", "link", "set", bridge_iface, "up"])
            .status();

        // DHCP script that only sets the IP, no default route.
        let script = r#"#!/bin/sh
case "$1" in
  deconfig)
    /bin/busybox ifconfig "$interface" 0.0.0.0 || true
    ;;
  renew|bound)
    /bin/busybox ifconfig "$interface" "$ip" netmask "${subnet:-255.255.255.0}" up
    # Intentionally no default route — outbound stays on eth0.
    ;;
esac
exit 0
"#;
        let script_path = "/run/udhcpc-bridge.script";
        if let Err(e) = fs::write(script_path, script) {
            tracing::warn!(error = %e, "failed to write bridge DHCP script");
            return;
        }
        let _ = fs::set_permissions(script_path, fs::Permissions::from_mode(0o755));

        match std::process::Command::new("/bin/busybox")
            .args([
                "udhcpc",
                "-i",
                bridge_iface,
                "-n",
                "-q",
                "-t",
                "3",
                "-T",
                "2",
                "-s",
                script_path,
            ])
            .status()
        {
            Ok(s) if s.success() => {
                tracing::info!(interface = bridge_iface, "bridge NIC DHCP lease acquired");
            }
            Ok(s) => {
                tracing::warn!(
                    interface = bridge_iface,
                    exit_code = s.code().unwrap_or(-1),
                    "bridge NIC DHCP failed"
                );
            }
            Err(e) => {
                tracing::warn!(interface = bridge_iface, error = %e, "bridge NIC udhcpc failed");
            }
        }

        // Enable proxy ARP on the bridge NIC so the guest answers ARP
        // requests for container IPs (172.17.x.x) on behalf of docker0.
        // This lets the host use `-interface bridge100` routing without
        // needing to know the guest's bridge IP as a gateway.
        if let Err(e) = fs::write(
            format!("/proc/sys/net/ipv4/conf/{bridge_iface}/proxy_arp"),
            b"1\n",
        ) {
            tracing::warn!(interface = bridge_iface, error = %e, "failed to enable proxy_arp");
        } else {
            tracing::info!(interface = bridge_iface, "proxy ARP enabled");
        }

        // Add iptables FORWARD rules for the bridge NIC so container
        // traffic can flow through.
        run_iptables(
            &["-I", "FORWARD", "-i", bridge_iface, "-j", "ACCEPT"],
            "FORWARD accept from bridge NIC",
        );
        run_iptables(
            &[
                "-I",
                "FORWARD",
                "-o",
                bridge_iface,
                "-m",
                "conntrack",
                "--ctstate",
                "RELATED,ESTABLISHED",
                "-j",
                "ACCEPT",
            ],
            "FORWARD accept established to bridge NIC",
        );
    }

    /// Install iptables FORWARD rules for sandbox networking.
    ///
    /// Each sandbox has a point-to-point TAP — no bridge or MASQUERADE needed.
    /// The host-side TcpBridge / SocketProxy terminates connections and
    /// creates new host sockets, so the original sandbox src IP is irrelevant
    /// for reply routing.
    ///
    /// The subnet is read from the VMM config (default `172.20.0.0/16`).
    /// Uses `-I` (insert at chain top) so rules take effect even when
    /// Docker sets the default FORWARD policy to DROP.
    fn setup_sandbox_forwarding() {
        let config = crate::config::load();
        let subnet = &config.network.cidr;

        run_iptables(
            &["-I", "FORWARD", "-d", subnet, "-j", "ACCEPT"],
            "FORWARD accept to sandbox subnet",
        );
        run_iptables(
            &["-I", "FORWARD", "-s", subnet, "-j", "ACCEPT"],
            "FORWARD accept from sandbox subnet",
        );

        tracing::info!(subnet, "sandbox forwarding rules installed");
    }

    /// Run an iptables command, logging on failure.
    fn run_iptables(args: &[&str], desc: &str) {
        match std::process::Command::new("/sbin/iptables")
            .args(args)
            .status()
        {
            Ok(s) if s.success() => {}
            Ok(s) => tracing::warn!(
                desc,
                exit_code = s.code().unwrap_or(-1),
                "iptables rule failed"
            ),
            Err(e) => tracing::warn!(desc, error = %e, "failed to run iptables"),
        }
    }

    fn detect_primary_interface() -> Option<String> {
        let entries = fs::read_dir("/sys/class/net").ok()?;
        let mut candidates = Vec::new();
        for entry in entries.flatten() {
            let Ok(name) = entry.file_name().into_string() else {
                continue;
            };
            // Skip loopback and virtual interfaces that are not real NICs.
            if name == "lo"
                || name.starts_with("dummy")
                || name.starts_with("veth")
                || name.starts_with("br-")
                || name.starts_with("docker")
            {
                continue;
            }
            candidates.push(name);
        }
        candidates.sort();
        candidates.into_iter().next()
    }

    fn write_etc_resolv_conf() {
        // Point to the local guest DNS server (dns_server.rs) which handles:
        // - Container/sandbox name resolution from its registries
        // - *.arcbox.local → authoritative NXDOMAIN if not registered
        // - Everything else → forward to gateway (10.0.2.1)
        let content = "nameserver 127.0.0.1\n";
        if let Err(e) = std::fs::write("/etc/resolv.conf", content) {
            tracing::warn!(error = %e, "failed to write /etc/resolv.conf");
        }
    }

    /// Writes Docker daemon configuration (DNS + default ulimits).
    ///
    /// Containers get their DNS from the Docker daemon config, NOT from the
    /// guest's /etc/resolv.conf. We point them to 10.0.2.1 (the gateway)
    /// so container DNS queries go through the host-side forwarder which can
    /// resolve *.arcbox.local names registered from the host.
    ///
    /// Default ulimits ensure containers get a high NOFILE limit even if
    /// Docker's own heuristics pick a lower value.
    fn write_docker_daemon_config() {
        mkdir_p("/etc/docker");
        let content = super::docker_daemon_json();
        if let Err(e) = std::fs::write("/etc/docker/daemon.json", &content) {
            tracing::warn!(error = %e, "failed to write /etc/docker/daemon.json");
        }
    }

    fn write_etc_hosts() {
        let hostname = hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| "arcbox".to_string());
        let content = format!("127.0.0.1\tlocalhost\n::1\t\tlocalhost\n127.0.1.1\t{hostname}\n");
        if let Err(e) = std::fs::write("/etc/hosts", content) {
            tracing::warn!(error = %e, "failed to write /etc/hosts");
        }
    }

    fn write_etc_passwd() {
        let content =
            "root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/:/sbin/nologin\n";
        if let Err(e) = std::fs::write("/etc/passwd", content) {
            tracing::warn!(error = %e, "failed to write /etc/passwd");
        }
    }

    fn write_etc_group() {
        let content = "root:x:0:\ntty:x:5:\nnobody:x:65534:\n";
        if let Err(e) = std::fs::write("/etc/group", content) {
            tracing::warn!(error = %e, "failed to write /etc/group");
        }
    }

    fn mkdir_p(path: &str) {
        if let Err(e) = std::fs::create_dir_all(path) {
            tracing::warn!(path, error = %e, "failed to create directory");
        }
    }

    fn symlink_if_source_exists(source: &str, link: &str) {
        if !Path::new(source).exists() {
            tracing::debug!(source, "symlink source does not exist, skipping");
            return;
        }
        match unix_fs::symlink(source, link) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // Idempotent: symlink already in place.
            }
            Err(e) => {
                tracing::warn!(source, link, error = %e, "failed to create symlink");
            }
        }
    }
}

/// Target NOFILE limit for the guest VM, matching Docker Desktop / OrbStack.
/// Used by both `raise_fd_limits()` and `docker_daemon_json()`.
#[cfg(any(target_os = "linux", test))]
const NOFILE_LIMIT: u64 = 1_048_576;

/// Returns the Docker daemon.json content as a string.
///
/// Extracted as a pure function so the output contract (DNS + default
/// ulimits + containerd image store) is testable independently of the
/// filesystem and platform.
#[cfg(any(target_os = "linux", test))]
fn docker_daemon_json() -> String {
    serde_json::json!({
        "dns": ["10.0.2.1"],
        "default-ulimits": {
            "nofile": { "Name": "nofile", "Soft": NOFILE_LIMIT, "Hard": NOFILE_LIMIT }
        },
        "features": {
            "containerd-snapshotter": true
        }
    })
    .to_string()
}

#[cfg(target_os = "linux")]
pub use platform::init_system;

#[cfg(not(target_os = "linux"))]
pub fn init_system() {
    tracing::warn!("init_system is only functional on Linux");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daemon_json_contains_nofile_ulimit() {
        let json = docker_daemon_json();
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        let nofile = &v["default-ulimits"]["nofile"];
        assert_eq!(nofile["Soft"], 1048576);
        assert_eq!(nofile["Hard"], 1048576);
        assert_eq!(nofile["Name"], "nofile");
    }

    #[test]
    fn daemon_json_contains_dns() {
        let json = docker_daemon_json();
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(v["dns"][0], "10.0.2.1");
    }

    #[test]
    fn daemon_json_enables_containerd_snapshotter() {
        let json = docker_daemon_json();
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(v["features"]["containerd-snapshotter"], true);
    }
}
