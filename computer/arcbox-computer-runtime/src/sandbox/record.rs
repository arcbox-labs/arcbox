//! Durable sandbox records: the phase vocabulary and the store behind it.
//!
//! [`phase`] is pure — the phases a record can hold, the legal moves between
//! them, and the validation every record must satisfy. [`store`] is the
//! file-backed persistence of those records. The split exists so the phase
//! graph can be read (and tested) without a filesystem.
//!
//! Several items below are spelled `pub` rather than `pub(crate)` only
//! because clippy's `redundant_pub_crate` reads the spelling, not the reach:
//! this module is `pub(crate)` inside `sandbox`, so they end at the crate
//! boundary. What reaches beyond `crate::sandbox` is the durable-write
//! vocabulary `crate::lifecycle`'s actor executes.

mod phase;
mod store;

pub use phase::PersistPhase;
pub use phase::ProvisionIntent;
pub use phase::SandboxRecord;
/// Crate-visible, like [`PersistPhase`]: `crate::lifecycle`'s actor is what
/// executes the durable writes the machine asks for.
pub use phase::{SandboxProvisionOutcome, SandboxTransition};
pub use store::SandboxRecordStore;
