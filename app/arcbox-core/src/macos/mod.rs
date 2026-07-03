//! macOS guest support: base images, copy-on-write clones, and (later) the macOS
//! machine lifecycle. Apple Silicon only.

#[cfg(feature = "macos-ipsw-install")]
mod download;
mod image;
#[cfg(feature = "macos-ipsw-install")]
mod install;
mod lease;
mod machine;
mod pull;
mod remote;
mod vm;

pub use image::{MacImage, MacImageManager, MacImageMeta, MacInstanceDisks};
#[cfg(feature = "macos-ipsw-install")]
pub use install::{PullPhase, PullSource};
pub use machine::{MacMachineConfig, MacMachineInfo, MacMachineManager};
pub use pull::{PullStage, RemoteSource, ResolvedImage};
pub use remote::{ImageReference, RemoteLocation};
pub use vm::MacVm;
