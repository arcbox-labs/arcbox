//! The fake driver passes its own contract — with everything claimed, and
//! with nothing claimed (every skip path in the checks).

use arcbox_vm_driver::DriverCapabilities;
use arcbox_vm_driver::driver_contract;
use arcbox_vm_driver::testkit::{FakeDriver, FakeHarness};

driver_contract!(full, FakeHarness::new());

driver_contract!(
    minimal,
    FakeHarness::with_driver(
        FakeDriver::builder()
            .capabilities(DriverCapabilities::default())
            .build()
    )
);
