//! Durable sandbox records: the phase vocabulary and the store behind it.
//!
//! [`phase`] is pure — the phases a record can hold, the legal moves between
//! them, and the validation every record must satisfy. [`store`] is the
//! file-backed persistence of those records. The split exists so the phase
//! graph can be read (and tested) without a filesystem.

mod phase;
mod store;

pub use phase::PersistPhase;
pub(super) use phase::{
    ProvisionIntent, SandboxProvisionOutcome, SandboxRecord, SandboxTransition,
};
pub(super) use store::SandboxRecordStore;
