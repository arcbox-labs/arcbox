//! Pure policy: the decisions the runtime makes without touching a
//! filesystem, a VMM, or the network.
//!
//! Each module is one decision with its own tests, so it can be exercised
//! on any host — no KVM, no root. The impure halves that act on those
//! decisions stay next to the resources they own.

pub(super) mod deadlines;
pub(super) mod pool;
/// `pub` only in the lint's spelling: the `policy` module above is
/// `pub(crate)`, so this reaches exactly `crate::lifecycle`, whose state
/// machine seeds itself from [`recovery::plan`]'s verdicts and asserts
/// against that function rather than a copy of it.
pub mod recovery;
pub(super) mod settle;
pub(super) mod warm;
