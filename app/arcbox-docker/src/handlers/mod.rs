//! Request handlers for Docker API endpoints.
//!
//! Only endpoints that need ArcBox-specific behavior live here. Ordinary
//! Docker API requests fall through to the smart proxy fallback, which keeps
//! transparent pass-through behavior out of per-endpoint handlers.

mod admission;
mod build;
mod container;
mod identity;
mod network;
mod proxying;

pub(crate) use admission::require_amd64_runtime;
pub(crate) use identity::extract_container_id;
pub(crate) use proxying::{
    ensure_system_vm_ready, hold_activity_for_response, proxy_to_system_vm,
    proxy_upload_to_system_vm,
};

pub(crate) use build::build_image;
pub(crate) use container::{
    create_container, kill_container, remove_container, rename_container, restart_container,
    start_container, stop_container,
};
pub(crate) use network::{network_connect, network_disconnect};

pub use container::extract_container_dns_info;
pub use container::extract_container_name;
