//! macOS guest support: base images, copy-on-write clones, and (later) the macOS
//! machine lifecycle. Apple Silicon only.

mod download;
mod image;
mod install;
mod machine;
mod vm;

pub use image::{MacImage, MacImageManager, MacImageMeta, MacInstanceDisks};
pub use install::{PullPhase, PullSource};
pub use machine::{MacMachineConfig, MacMachineInfo, MacMachineManager};
pub use vm::MacVm;
