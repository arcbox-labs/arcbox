//! The transition table, read off today's flows.
//!
//! `harness` is the scratch buffer and the exhaustive walk; the tests beside
//! it either check what must hold in every state, or pin one flow at a time.

mod flows;
mod harness;
mod invariants;
mod projections;
