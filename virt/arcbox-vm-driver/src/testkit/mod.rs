//! Fakes and the contract test-kit (feature `testkit`).
//!
//! - [`FakeDriver`] — an in-memory [`VmDriver`](crate::VmDriver) with a
//!   real state machine, events, every capability, and scripted failures.
//!   Runtime unit tests drive their real actors and state machines against
//!   it on any host, no KVM required.
//!
//! - [`FakeNetwork`] — an in-memory [`GuestNetwork`](crate::net::GuestNetwork)
//!   handing out `10.200.0.0/16` leases with a quarantine ledger and the
//!   [`NetworkReconcile`](crate::net::NetworkReconcile) token protocol.
//!
//! The contract test-kit lands in the sibling module.

use std::sync::{Mutex, MutexGuard, PoisonError};

pub mod fake_driver;
pub mod fake_network;
mod fake_vm;

pub use fake_driver::{FakeDriver, FakeDriverBuilder};
pub use fake_network::FakeNetwork;
pub use fake_vm::FakeVm;

/// Locks `mutex`, tolerating poison: a fake that panicked while holding a
/// lock has already failed the test, and the state behind it is still the
/// most useful thing to show.
pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
