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
