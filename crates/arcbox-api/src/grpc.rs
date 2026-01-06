//! gRPC service implementations.

use arcbox_core::Runtime;
use std::sync::Arc;

/// Container service implementation.
pub struct ContainerService {
    runtime: Arc<Runtime>,
}

impl ContainerService {
    /// Creates a new container service.
    #[must_use]
    pub fn new(runtime: Arc<Runtime>) -> Self {
        Self { runtime }
    }
}

/// Machine service implementation.
pub struct MachineService {
    runtime: Arc<Runtime>,
}

impl MachineService {
    /// Creates a new machine service.
    #[must_use]
    pub fn new(runtime: Arc<Runtime>) -> Self {
        Self { runtime }
    }
}

/// Image service implementation.
pub struct ImageService {
    runtime: Arc<Runtime>,
}

impl ImageService {
    /// Creates a new image service.
    #[must_use]
    pub fn new(runtime: Arc<Runtime>) -> Self {
        Self { runtime }
    }
}

// TODO: Implement gRPC service traits when proto files are added
