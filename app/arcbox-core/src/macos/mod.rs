//! macOS guest support: base images, copy-on-write clones, and (later) the macOS
//! machine lifecycle. Apple Silicon only.

mod image;
mod install;

pub use image::{MacImage, MacImageManager, MacImageMeta, MacInstanceDisks};
