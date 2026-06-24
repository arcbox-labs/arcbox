//! Request handlers for Docker API endpoints.
//!
//! Only endpoints that need ArcBox-specific behavior live here. Ordinary
//! Docker API requests fall through to the smart proxy fallback, which keeps
//! transparent pass-through behavior out of per-endpoint handlers.

mod admission;
mod build;
mod container;
mod exec;
mod identity;
mod proxying;
mod role_resolution;

pub(crate) use admission::require_amd64_runtime;
pub(crate) use identity::{extract_container_id, extract_exec_id};
pub(crate) use proxying::{ensure_role_ready, proxy_to_role, proxy_upload_to_role};
pub(crate) use role_resolution::resolve_role_from_uri;

pub(crate) use build::build_image;
pub(crate) use container::{
    create_container, kill_container, remove_container, rename_container, restart_container,
    start_container, stop_container,
};
pub(crate) use exec::exec_create;

pub use container::extract_container_dns_info;
