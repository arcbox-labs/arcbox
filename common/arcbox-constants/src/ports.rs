/// Default vsock port for ArcBox guest agent RPC.
pub const AGENT_PORT: u32 = 1024;

/// Guest Docker API vsock proxy port.
pub const DOCKER_API_VSOCK_PORT: u32 = 2375;

/// Guest Kubernetes API vsock proxy port.
pub const KUBERNETES_API_VSOCK_PORT: u32 = 16443;

/// Host localhost port for the ArcBox Kubernetes API proxy.
pub const KUBERNETES_API_HOST_PORT: u16 = 16443;

/// Guest localhost port for the Kubernetes API server.
pub const KUBERNETES_API_GUEST_PORT: u16 = 6443;

/// Guest vsock port relaying to the in-guest kernel nfsd (NFS protocol).
///
/// The host daemon bridges a localhost TCP proxy to this port; the guest relay
/// forwards it to `127.0.0.1:2049`. NFSv4 serves everything on this one port,
/// so no separate MOUNT-protocol relay is needed.
pub const NFS_NFSD_RELAY_PORT: u32 = 2049;
