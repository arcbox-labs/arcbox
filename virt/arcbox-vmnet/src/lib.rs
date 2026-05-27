//! Safe Rust bindings for Apple's vmnet.framework.
//!
//! This crate exposes:
//! - Low-level FFI declarations for `vmnet`, Core Foundation, GCD dispatch,
//!   XPC, and the Objective-C block ABI required by `vmnet_start_interface`.
//! - A high-level [`Vmnet`] interface for creating shared (NAT), host-only,
//!   and bridged virtual network interfaces.
//! - A [`VmnetRelay`] that bridges vmnet's blocking read/write API to a
//!   `socketpair` consumed by `VZFileHandleNetworkDeviceAttachment`.
//!
//! # Operating modes
//!
//! - **Shared (NAT)** — VMs share the host's network connection via NAT,
//!   with vmnet providing DHCP and DNS.
//! - **Host-only** — Isolated network between VMs and host, optionally
//!   with per-interface isolation via UUID.
//! - **Bridged** — VMs appear as separate L2 devices on a physical network.
//!
//! # Requirements
//!
//! - macOS 11.0 or later.
//! - The `com.apple.vm.networking` entitlement, or root, is required to
//!   start a vmnet interface.
//!
//! # Feature flags
//!
//! - `vmnet` — Enable the proper Objective-C completion-handler ABI for
//!   `vmnet_start_interface`. Without it, the interface starts with a
//!   NULL handler and falls back to default packet-size / generated MAC.

#![cfg(target_os = "macos")]

pub mod error;
pub mod ffi;
mod interface;
mod relay;

pub use error::{Result, VmnetError};
pub use interface::{Vmnet, VmnetConfig, VmnetInterfaceInfo, VmnetMode};
pub use relay::VmnetRelay;
