//! A [`NodeEnvironment`] over the fakes, for tests that must not need a VMM.

use std::sync::Arc;

use arcbox_vm_driver::testkit::{FakeDriver, FakeNetwork};

use crate::config::RuntimeConfig;
use crate::environment::NodeEnvironment;
use crate::error::Result;
use crate::snapshot_cow::{CowManager, CowOptions};
use crate::testkit::agent::FakeAgentFactory;

/// The three ports faked, over a real [`CowManager`] rooted at the config's
/// data directory.
///
/// The copy-on-write manager is real because it is not a port and has no
/// fake: with no usable `dmsetup` it comes up with dm-snapshot CoW
/// disabled, which is what an unprivileged test host would get anyway. A
/// test that needs one of the three fakes to behave differently — a driver
/// missing a capability, a network holding a startup cleanup — overrides
/// that field:
///
/// ```ignore
/// NodeEnvironment {
///     driver: Arc::new(my_driver),
///     ..fake_environment(&config)?
/// }
/// ```
pub fn fake_environment(config: &RuntimeConfig) -> Result<NodeEnvironment> {
    let mut cow_options = CowOptions::new(&config.firecracker.data_dir);
    if let Some(candidates) = &config.firecracker.dmsetup_candidates {
        cow_options.dmsetup_candidates = candidates.iter().map(std::path::PathBuf::from).collect();
    }
    Ok(NodeEnvironment {
        driver: Arc::new(FakeDriver::new()),
        network: Arc::new(FakeNetwork::new()),
        agent: Arc::new(FakeAgentFactory::new()),
        cow_manager: Arc::new(CowManager::new(cow_options)?),
    })
}
