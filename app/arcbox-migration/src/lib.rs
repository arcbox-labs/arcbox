//! Docker runtime migration support for ArcBox.
//!
//! This crate provides shared migration logic for importing Docker objects
//! from Docker Desktop or OrbStack into ArcBox through the Docker CLI.

pub mod docker_types;
pub mod error;
pub mod executor;
pub mod helper_image;
pub mod model;
pub mod planner;
pub mod progress;
pub mod runner;
pub mod source;

pub use error::{MigrationError, Result};
pub use executor::{MigrationExecutor, MigrationExecutorOptions};
pub use model::{
    ContainerMount, ContainerNetworkAttachment, ContainerPlan, ContainerSpec, ImagePlan,
    MigrationPlan, NetworkPlan, PortPublish, ReplacementSummary, RestartPolicySpec,
    RunningVolumeBlocker, SourceConfig, SourceInfo, SourceKind, VolumePlan,
};
pub use planner::MigrationPlanner;
pub use progress::{MigrationProgress, MigrationStage};
pub use runner::{DockerCliRunner, ImageTransfer};
pub use source::{DockerDesktopSource, MigrationSource, OrbStackSource, resolve_source};
