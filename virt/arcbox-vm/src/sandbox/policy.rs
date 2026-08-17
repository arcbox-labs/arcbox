//! Pure policy: the decisions the runtime makes without touching a
//! filesystem, a VMM, or the network.
//!
//! Each module is one decision with its own tests, so it can be exercised
//! on any host — no KVM, no root. The impure halves that act on those
//! decisions stay next to the resources they own.

pub(super) mod deadlines;
pub(super) mod pool;
pub(super) mod recovery;
pub(super) mod warm;
