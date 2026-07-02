//! macOS guest support: base images, copy-on-write clones, and (later) the macOS
//! machine lifecycle. Apple Silicon only.

mod download;
mod image;
mod install;
mod machine;
mod pull;
mod remote;
mod vm;

pub use image::{MacImage, MacImageManager, MacImageMeta, MacInstanceDisks};
pub use install::{PullPhase, PullSource};
pub use machine::{MacMachineConfig, MacMachineInfo, MacMachineManager};
pub use pull::{PullStage, RemoteSource};
pub use remote::{ImageReference, RemoteLocation};
pub use vm::MacVm;
