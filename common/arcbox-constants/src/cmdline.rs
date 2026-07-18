/// Kernel cmdline key for guest Docker API vsock port propagation.
pub const GUEST_DOCKER_VSOCK_PORT_KEY: &str = "arcbox.guest_docker_vsock_port=";

/// Kernel cmdline key for guest Docker data block-device path.
pub const DOCKER_DATA_DEVICE_KEY: &str = "arcbox.docker_data_device=";

/// Kernel cmdline key carrying the host path of the interactive debug-console
/// Unix socket (custom-HV backend).
///
/// When present, the host wires the virtio-console to a bidirectional socket at
/// this path and the guest rcS spawns a root shell on the console — giving a
/// serial shell reachable via `socat - UNIX-CONNECT:<path>` even when early boot
/// hangs before networking.
pub const DEBUG_CONSOLE_KEY: &str = "arcbox.debug_console=";

/// Guest path of the machine boot shim executed as PID 1 via `init=`.
///
/// Packaged into the boot-assets EROFS; the shim stages the distro rootfs
/// (overlay over squashfs), spawns the agent, and `switch_root`s into the
/// distro's own init.
pub const MACHINE_INIT_PATH: &str = "/sbin/arcbox-machine-init";

/// Kernel cmdline key carrying the distro rootfs block device (`/dev/vdb`)
/// the machine boot shim mounts as the overlay lower layer.
pub const MACHINE_ROOTFS_KEY: &str = "arcbox.machine_rootfs=";

/// Kernel cmdline key carrying the distro rootfs filesystem type
/// (`squashfs`), from the machine image manifest.
pub const MACHINE_ROOTFS_TYPE_KEY: &str = "arcbox.machine_rootfs_type=";

/// Kernel cmdline key carrying the per-machine data block device
/// (`/dev/vdc`) the shim first-boot-formats as btrfs and uses as the overlay
/// upper layer.
pub const MACHINE_DATA_KEY: &str = "arcbox.machine_data=";

/// Explicit `earlycon` directive pinning the kernel's early console to the
/// custom-HV PL011 UART emulator at `0x0B00_0000` (see
/// `arcbox_vmm::vmm::darwin_hv::pl011::PL011_BASE`).
///
/// A bare `earlycon` relies on the device-tree `stdout-path`, which in practice
/// produces no output on the HV backend — leaving every boot failure
/// undiagnosable. Pinning the address routes early kernel messages through the
/// emulator, which forwards them to the host `guest_serial` log.
///
/// The address is verified against `PL011_BASE` by a drift-guard test in
/// `arcbox-vmm` (`darwin_hv::pl011`), the crate that owns the emulator.
pub const HV_EARLYCON_DIRECTIVE: &str = "earlycon=pl011,0x0b000000";

/// Kernel cmdline key carrying the machine's user mounts as
/// `tag=guest_path[:ro]` entries joined by commas (e.g.
/// `m0=/work,m1=/data:ro`). Each tag names a per-machine VirtioFS share the
/// shim mounts into the new root after staging the overlay. Guest paths are
/// validated host-side to contain neither `,` nor `=`.
pub const MACHINE_MOUNTS_KEY: &str = "arcbox.machine_mounts=";
